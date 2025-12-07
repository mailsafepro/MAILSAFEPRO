"""
API Keys Management Module

Handles secure API key generation, rotation, revocation, and management with Redis backend.
Provides comprehensive audit logging and atomic operations for data consistency.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Path, Security
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone
import secrets
import hashlib
import json
import re

from uuid import uuid4

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from app.config import settings
from app.utils import (
    update_all_user_api_keys,
    repair_user_data as repair_user_data_util,
    read_usage_for_api_key,
    read_usage_for_userid,
)
from app.models import (
    APIKeyCreateRequest,
    APIKeyListResponse,
    APIKeyMeta,
    TokenData,
)
from app.auth import (
    create_hashed_key,
    get_redis,
    validate_api_key,
    validate_api_key_string,
    get_current_client,
    validate_api_key_or_token,
    enforce_rate_limit,
    PLAN_SCOPES,
)
from app.logger import logger


router = APIRouter(prefix="/api-keys", tags=["API Keys"])

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_KEYS_PER_USER = 10
GRACE_PERIOD_DAYS = 7
SYNC_RATE_LIMIT_SECONDS = 300  # 5 minutes

HEX64_PATTERN = re.compile(r"^[a-f0-9]{64}$")


# =============================================================================
# HELPERS
# =============================================================================

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decode(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, bytes):
        return val.decode("utf-8")
    return str(val)


def _decode_dict(d: Dict[Any, Any]) -> Dict[str, str]:
    return {(_decode(k) or ""): (_decode(v) or "") for k, v in d.items()}


def _ensure_key_hash_format(key_hash: str) -> None:
    if not key_hash or not HEX64_PATTERN.fullmatch(key_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid key hash format",
        )


def _safe_json_loads(s: str) -> Optional[dict]:
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def _sanitize_metadata(d: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(d, dict):
        return {}
    # Remove sensitive identifiers by default
    redacted = {k: v for k, v in d.items() if k not in {"user_id", "internal_id", "rotated_from", "replaced_by"}}
    return redacted


# =============================================================================
# SECURITY UTILITIES
# =============================================================================

class APIKeySecurity:
    """Security utilities for API key management"""

    @staticmethod
    def hash_id(val: str) -> str:
        """Generate consistent hash for user ID"""
        if not isinstance(val, str) or not val:
            raise ValueError("Invalid id to hash")
        return hashlib.sha256(val.encode("utf-8")).hexdigest()

    @staticmethod
    def validate_key_hash(key_hash: str) -> bool:
        """Validate API key hash format"""
        return bool(HEX64_PATTERN.fullmatch(key_hash))


# =============================================================================
# LUA SCRIPTS (ATOMIC OPS)
# =============================================================================

class AtomicOperations:
    """Lua scripts for atomic Redis operations"""

    CREATE_KEY_SCRIPT = """
    local user_key = KEYS[1]
    local key_storage = KEYS[2]
    local api_keys_set = KEYS[3]
    local key_hash = ARGV[1]
    local key_data_json = ARGV[2]
    local user_id = ARGV[3]
    local user_email = ARGV[4]
    local plan = ARGV[5]
    local timestamp = ARGV[6]
    local max_keys = tonumber(ARGV[7])

    -- Verify key limit
    local current_key_count = redis.call('SCARD', api_keys_set)
    if current_key_count >= max_keys then
      return redis.error_reply("max_keys_exceeded")
    end

    -- Create user if not exists (idempotent)
    local user_exists = redis.call('EXISTS', user_key)
    if user_exists == 0 then
      redis.call('HSET', user_key,
        'id', user_id,
        'email', user_email,
        'plan', plan,
        'created_at', timestamp,
        'updated_at', timestamp
      )
    end

    -- Create API key
    redis.call('SET', key_storage, key_data_json)
    redis.call('SADD', api_keys_set, key_hash)

    return {current_key_count + 1}
    """

    REVOKE_KEY_SCRIPT = """
    local key_storage = KEYS[1]
    local api_keys_set = KEYS[2]
    local primary_key = KEYS[3]
    local key_hash = ARGV[1]
    local timestamp = ARGV[2]

    -- Verify key belongs to user
    local is_member = redis.call('SISMEMBER', api_keys_set, key_hash)
    if is_member == 0 then
      return redis.error_reply("not_found")
    end

    -- Get current data
    local key_data = redis.call('GET', key_storage)
    if not key_data then
      return redis.error_reply("not_found")
    end

    -- Parse and update
    local key_info = cjson.decode(key_data) or {}
    key_info.status = "revoked"
    key_info.revoked = true
    key_info.revoked_at = timestamp
    key_info.updated_at = timestamp

    -- Save changes
    redis.call('SET', key_storage, cjson.encode(key_info))

    -- Remove from set (no longer active)
    redis.call('SREM', api_keys_set, key_hash)

    -- Check if primary key
    local primary = redis.call('GET', primary_key)
    local is_primary = false
    if primary == key_hash then
      redis.call('DEL', primary_key)
      is_primary = true
    end

    return {is_primary}
    """

    ROTATE_KEY_SCRIPT = """
    local old_key = KEYS[1]
    local new_key = KEYS[2]
    local api_keys_set = KEYS[3]
    local old_hash = ARGV[1]
    local new_hash = ARGV[2]
    local new_data = ARGV[3]
    local deprecated_data = ARGV[4]
    local grace_period = tonumber(ARGV[5])

    -- Mark old key as deprecated with TTL
    redis.call('SET', old_key, deprecated_data)
    redis.call('EXPIRE', old_key, grace_period)

    -- Create new key
    redis.call('SET', new_key, new_data)

    -- Update set
    redis.call('SREM', api_keys_set, old_hash)
    redis.call('SADD', api_keys_set, new_hash)

    return 1
    """


# =============================================================================
# ADMIN: REPAIR DATA
# =============================================================================

@router.post("/repair-data", response_model=Dict[str, str])
async def repair_user_data_endpoint(
    current_client: TokenData = Security(get_current_client, scopes=["admin"]),
    redis: Redis = Depends(get_redis),
):
    """
    Emergency data repair endpoint - ADMINISTRATORS ONLY
    WARNING: Critical operation; relies on admin scope verification at runtime.
    """
    # Verify admin privileges
    if not hasattr(current_client, "scopes") or "admin" not in (current_client.scopes or []):
        logger.warning(
            "Unauthorized repair_data access attempt",
            extra={"user_id": getattr(current_client, "sub", "unknown")},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required",
        )

    # Audit log
    logger.warning(
        "ADMIN ACTION: repair_data invoked",
        extra={
            "admin_id": current_client.sub[:8],
            "admin_email": getattr(current_client, "email", "unknown"),
            "timestamp": _utcnow_iso(),
            "action": "user_data_repair",
        },
    )
    try:
        user_id = current_client.sub
        user_email = getattr(current_client, "email", "")
        user_plan = getattr(current_client, "plan", "FREE")
        success = await repair_user_data_util(user_id, user_email, user_plan, redis)
        if success:
            return {
                "status": "success",
                "message": "User data repaired successfully",
                "repaired_at": _utcnow_iso(),
            }
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Data repair operation failed",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Critical error in data repair: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Data repair operation failed",
        )


# =============================================================================
# SYNC (RATE-LIMITED)
# =============================================================================

@router.post("/force-sync", response_model=Dict[str, Any])
async def force_sync(
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """
    Force synchronization of user data with rate limiting.
    Synchronizes API keys with current plan and clears relevant caches.
    Limited to one sync per 5 minutes per user.
    """
    user_id = current_client.sub
    sync_key = f"user:{user_id}:last_sync"

    last_sync = await redis.get(sync_key)
    if last_sync:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Rate limit exceeded",
                "message": "Sync can only be performed once every 5 minutes",
                "retry_after": SYNC_RATE_LIMIT_SECONDS,
            },
        )

    await redis.setex(sync_key, SYNC_RATE_LIMIT_SECONDS, _utcnow_iso())

    try:
        user_key = f"user:{user_id}"
        user_plan = await redis.hget(user_key, "plan")
        plan = (_decode(user_plan) or "FREE").upper()

        updated_count = await update_all_user_api_keys(user_id, plan, redis)

        # Clear non-critical caches
        pipe = redis.pipeline()
        pipe.delete(f"user:{user_id}:subscription")
        pipe.delete(f"user:{user_id}:rate_limit")
        await pipe.execute()

        logger.info(
            "User data synchronization completed",
            extra={
                "user_id": user_id[:8],
                "plan": plan,
                "keys_updated": updated_count,
                "timestamp": _utcnow_iso(),
            },
        )

        return {
            "status": "success",
            "message": "Data synchronized successfully",
            "plan": plan,
            "keys_updated": updated_count,
            "synced_at": _utcnow_iso(),
        }
    except Exception as e:
        logger.error("Sync operation failed: %s", str(e))
        await redis.delete(sync_key)  # Reset rate limit on failure
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Synchronization failed",
        )


# =============================================================================
# CREATE
# =============================================================================

@router.post("", response_model=Dict[str, Any])
async def create_api_key(
    req: APIKeyCreateRequest,
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """
    Create a new API key with atomic transaction.
    Generates cryptographically secure API keys with proper scoping
    based on user's current plan. Enforces maximum key limits.
    """
    user_id = current_client.sub
    
    try:
        # Rate limit
        await enforce_rate_limit(redis, bucket=f"ak:create:{user_id}", limit=5, window=60)
        
        # Generate secure key material
        plain_key = secrets.token_urlsafe(32)
        key_hash = create_hashed_key(plain_key)
        client_set_hash = APIKeySecurity.hash_id(user_id)
        
        # Get current user plan
        user_key = f"user:{user_id}"
        user_data = await redis.hgetall(user_key)
        plan_raw = None
        user_email = ""
        
        if user_data:
            data_decoded = _decode_dict(user_data)
            plan_raw = data_decoded.get("plan")
            user_email = data_decoded.get("email", "")
        
        # ✅ Fallback: usar email de TokenData si existe
        if not user_email:
            user_email = getattr(current_client, "email", "")
        
        plan = (plan_raw or "FREE").upper()
        scopes = PLAN_SCOPES.get(plan, [])
        
        if not isinstance(scopes, list):
            scopes = PLAN_SCOPES.get("FREE", [])
        
        timestamp = _utcnow_iso()
        key_name = (req.name or f"API Key {timestamp[:10]}").strip()
        
        key_data = {
            "status": "active",
            "created_at": timestamp,
            "updated_at": timestamp,
            "plan": plan,
            "scopes": scopes,
            "user_id": user_id,
            "name": key_name,
            "revoked": False,
            "revoked_at": None,
            "last_used": None,
        }
        
        # ✅ Log antes de la operación Redis
        logger.debug(
            "Creating API key | User: %s | Plan: %s | Name: %s",
            user_id[:8],
            plan,
            key_name
        )
        
        # Atomic create with Lua script
        try:
            await redis.eval(
                AtomicOperations.CREATE_KEY_SCRIPT,
                3,
                user_key,
                f"key:{key_hash}",
                f"api_keys:{client_set_hash}",
                key_hash,
                json.dumps(key_data),
                user_id,
                user_email,  # ← Ahora siempre tiene valor
                plan,
                timestamp,
                str(MAX_KEYS_PER_USER),
            )
        
        except ResponseError as re:
            error_msg = str(re)
            if "max_keys_exceeded" in error_msg:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "Key limit exceeded",
                        "message": f"Maximum of {MAX_KEYS_PER_USER} API keys allowed per user",
                        "max_keys": MAX_KEYS_PER_USER,
                    },
                )
            logger.error("Redis error in key creation: %s", error_msg, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during key creation",
            )
        
        logger.info(
            "API key created successfully",
            extra={
                "user_id": user_id[:8],
                "key_name": key_name,
                "plan": plan,
                "key_prefix": key_hash[:8],
                "timestamp": timestamp,
            },
        )
        
        return {
            "api_key": plain_key,
            "plan": plan,
            "created_at": timestamp,
            "name": key_name,
            "scopes": scopes,
            "warning": "Store this key securely - it will not be shown again",
            "key_id": key_hash,
        }
    
    except HTTPException:
        raise
    
    except Exception as e:
        # ✅ Log completo con traceback
        logger.exception(
            "Unexpected error in key creation | User: %s | Error: %s",
            user_id[:8] if user_id else "unknown",
            str(e)[:200]
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key creation failed",
        )


# =============================================================================
# LIST
# =============================================================================

class APIKeyManagement:
    """Utility methods for API key data processing"""

    @staticmethod
    def parse_timestamp(timestamp_str: Optional[str]) -> Optional[datetime]:
        if not timestamp_str:
            return None
        try:
            # Accept both naive and UTC iso strings
            return datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def determine_revocation_status(key_info: Dict[str, Any]) -> bool:
        if not isinstance(key_info, dict):
            return True
        revoked_field = key_info.get("revoked")
        if isinstance(revoked_field, bool):
            if revoked_field:
                return True
        elif isinstance(revoked_field, str):
            if revoked_field.lower() in ("1", "true", "revoked"):
                return True
        elif isinstance(revoked_field, int):
            if revoked_field == 1:
                return True
        status_field = key_info.get("status", "")
        if isinstance(status_field, str) and status_field.lower() in ("revoked", "deprecated"):
            return True
        return False


@router.get("", response_model=APIKeyListResponse)
async def list_api_keys(
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """
    List all API keys for current user with consistent IDs.
    Returns comprehensive key metadata including status, scopes, and usage information.
    Handles corrupted key data gracefully.
    """
    try:
        user_id = current_client.sub
        client_hash = APIKeySecurity.hash_id(user_id)
        api_key_hashes = await redis.smembers(f"api_keys:{client_hash}")
        
        # ✅ FIX: Siempre retornar total_count y active_count
        if not api_key_hashes:
            return {
                "keys": [],
                "total_count": 0,
                "active_count": 0,
            }
        
        api_key_hash_list = sorted([_decode(h) or "" for h in api_key_hashes if _decode(h)])
        
        pipeline = redis.pipeline()
        for key_hash in api_key_hash_list:
            pipeline.get(f"key:{key_hash}")
        
        key_data_list = await pipeline.execute()
        keys_list: List[APIKeyMeta] = []
        
        for key_hash, key_data in zip(api_key_hash_list, key_data_list):
            if not key_data:
                logger.warning("Missing key data for hash: %s", key_hash[:8])
                continue
            
            key_data_str = _decode(key_data) or ""
            key_info = _safe_json_loads(key_data_str)
            
            if not key_info or not isinstance(key_info, dict):
                logger.error("Corrupted or invalid key data format for %s", key_hash[:8])
                continue
            
            created_at = APIKeyManagement.parse_timestamp(key_info.get("created_at"))
            revoked = APIKeyManagement.determine_revocation_status(key_info)
            revoked_at = APIKeyManagement.parse_timestamp(key_info.get("revoked_at") if revoked else None)
            plan = (key_info.get("plan") or "FREE").upper()
            scopes = key_info.get("scopes", PLAN_SCOPES.get(plan, []))
            
            if not isinstance(scopes, list):
                scopes = PLAN_SCOPES.get(plan, [])
            
            key_meta = APIKeyMeta(
                id=key_hash,
                key_hash=key_hash,
                plan=plan,
                created_at=created_at,
                revoked=revoked,
                revoked_at=revoked_at,
                scopes=scopes,
                name=key_info.get("name", "Unnamed Key"),
                last_used=APIKeyManagement.parse_timestamp(key_info.get("last_used")),
            )
            
            keys_list.append(key_meta)
        
        # Sort by creation date (newest first)
        keys_list.sort(
            key=lambda x: (x.created_at or datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True
        )
        
        # ✅ Calcula total_count y active_count correctamente
        total_count = len(keys_list)
        active_count = len([k for k in keys_list if not k.revoked])
        
        return {
            "keys": keys_list,
            "total_count": total_count,
            "active_count": active_count,
        }
    
    except Exception as e:
        logger.exception("Critical error listing API keys: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve API keys",
        )


# =============================================================================
# REVOKE
# =============================================================================

@router.delete("/{key_hash}/revoke", status_code=status.HTTP_200_OK)
async def revoke_api_key(
    key_hash: str = Path(..., pattern=r"^[a-f0-9]{64}$"),
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """
    Revoke an API key with atomic transaction.
    Immediately invalidates the key and removes it from active sets.
    Provides audit trail for security compliance.
    """
    _ensure_key_hash_format(key_hash)

    user_id = current_client.sub
    await enforce_rate_limit(redis, bucket=f"ak:revoke:{user_id}", limit=10, window=60)
    timestamp = _utcnow_iso()
    client_set_hash = APIKeySecurity.hash_id(user_id)
    is_member = await redis.sismember(f"api_keys:{client_set_hash}", key_hash)
    if not is_member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found or access denied")
    logger.warning("API key action", extra={"user": user_id[:8], "key": key_hash[:8], "action": "revoke"})


    try:
        await redis.eval(
            AtomicOperations.REVOKE_KEY_SCRIPT,
            3,
            f"key:{key_hash}",
            f"api_keys:{client_set_hash}",
            f"user:{user_id}:api_key",
            key_hash,
            timestamp,
        )
    except ResponseError as re:
        error_msg = str(re)
        if "not_found" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found or access denied",
            )
        logger.error("Redis error in key revocation: %s", error_msg)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key revocation failed",
        )

    logger.warning(
        "API key revoked",
        extra={
            "user_id": user_id[:8],
            "key_prefix": key_hash[:8],
            "timestamp": timestamp,
            "action": "key_revocation",
        },
    )
    return {
        "status": "success",
        "message": "API key revoked successfully",
        "revoked_at": timestamp,
        "key_id": key_hash,
    }


# =============================================================================
# SYNC PLAN → KEYS
# =============================================================================

@router.post("/sync-plan-keys", response_model=Dict[str, Any])
async def sync_plan_keys(
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """
    Synchronize current plan with all user API keys.
    Ensures all existing keys have the correct scopes and permissions
    based on the user's current subscription plan.
    """
    try:
        user_id = current_client.sub
        user_key = f"user:{user_id}"
        user_plan = await redis.hget(user_key, "plan")
        plan = (_decode(user_plan) or "FREE").upper()

        updated_count = await update_all_user_api_keys(user_id, plan, redis)

        logger.info(
            "Plan synchronization completed",
            extra={"user_id": user_id[:8], "plan": plan, "keys_updated": updated_count},
        )
        return {
            "status": "success",
            "message": f"Updated {updated_count} API keys to {plan} plan",
            "plan": plan,
            "keys_updated": updated_count,
            "synced_at": _utcnow_iso(),
        }
    except Exception as e:
        logger.exception("Plan synchronization failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Plan synchronization failed",
        )


# =============================================================================
# GET METADATA (SAFE)
# =============================================================================

@router.get("/{key_hash}/value", response_model=Dict[str, Any])
async def get_api_key_value(
    key_hash: str = Path(..., pattern=r"^[a-f0-9]{64}$"),
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """
    Retrieve API key metadata (security-safe).
    Returns key information without exposing the actual key value.
    Used for key management and verification purposes.
    """
    _ensure_key_hash_format(key_hash)

    user_id = current_client.sub
    client_set_hash = APIKeySecurity.hash_id(user_id)

    is_member = await redis.sismember(f"api_keys:{client_set_hash}", key_hash)
    if not is_member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found or access denied",
        )

    key_data = await redis.get(f"key:{key_hash}")
    if not key_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key data not found",
        )

    key_data_str = _decode(key_data) or ""
    key_info = _safe_json_loads(key_data_str)
    if key_info is None:
        return {
            "metadata": {"raw_status": key_data_str},
            "security_notice": "Actual key value is only shown during creation",
        }

    sanitized_info = _sanitize_metadata(key_info)
    return {
        "metadata": sanitized_info,
        "security_notice": "Actual key value is only shown during creation",
        "key_status": key_info.get("status", "unknown"),
    }


# =============================================================================
# ROTATE (WITH GRACE)
# =============================================================================

@router.post("/{key_hash}/rotate", response_model=Dict[str, Any])
async def rotate_api_key(
    key_hash: str = Path(..., pattern=r"^[a-f0-9]{64}$"),
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """
    Rotate API key with grace period.
    Generates a new key while keeping the old one active for 7 days
    to allow for smooth transition in client applications.
    """
    _ensure_key_hash_format(key_hash)
    user_id = current_client.sub
    await enforce_rate_limit(redis, bucket=f"ak:rotate:{user_id}", limit=10, window=60)
    client_set_hash = APIKeySecurity.hash_id(user_id)
    
    is_member = await redis.sismember(f"api_keys:{client_set_hash}", key_hash)
    if not is_member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    
    old_key_data = await redis.get(f"key:{key_hash}")
    if not old_key_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key data not found",
        )
    
    old_key_data_str = _decode(old_key_data) or ""
    old_key_info = _safe_json_loads(old_key_data_str)
    if not old_key_info:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Corrupted key data",
        )
    
    # ✅ NUEVO: Validación explícita de estado (defensa en profundidad)
    key_status = (old_key_info.get("status") or "").lower()
    is_revoked = APIKeyManagement.determine_revocation_status(old_key_info)
    
    if is_revoked or key_status in ("revoked", "deprecated"):
        logger.warning(
            "Attempt to rotate revoked/deprecated key",
            extra={
                "user_id": user_id[:8],
                "key_hash": key_hash[:8],
                "status": key_status,
            }
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot rotate revoked or deprecated API key",
        )
    
    # ✅ Continuar con la rotación solo si la key está activa
    new_plain_key = secrets.token_urlsafe(32)
    new_key_hash = create_hashed_key(new_plain_key)
    timestamp = _utcnow_iso()
    plan = (old_key_info.get("plan") or "FREE").upper()
    scopes = old_key_info.get("scopes", PLAN_SCOPES.get(plan, []))
    if not isinstance(scopes, list):
        scopes = PLAN_SCOPES.get(plan, [])
    grace_period_end = datetime.now(timezone.utc) + timedelta(days=GRACE_PERIOD_DAYS)

    new_key_data = {
        "status": "active",
        "created_at": timestamp,
        "updated_at": timestamp,
        "plan": plan,
        "scopes": scopes,
        "user_id": user_id,
        "name": f"Rotated: {old_key_info.get('name', 'Unknown Key')}",
        "revoked": False,
        "revoked_at": None,
        "rotated_from": key_hash,
        "last_used": None,
    }

    old_key_info.update(
        {
            "status": "deprecated",
            "deprecated_at": timestamp,
            "updated_at": timestamp,
            "grace_period_ends": grace_period_end.isoformat(),
            "replaced_by": new_key_hash,
        }
    )
    grace_period_seconds = GRACE_PERIOD_DAYS * 24 * 3600

    try:
        await redis.eval(
            AtomicOperations.ROTATE_KEY_SCRIPT,
            3,
            f"key:{key_hash}",
            f"key:{new_key_hash}",
            f"api_keys:{client_set_hash}",
            key_hash,
            new_key_hash,
            json.dumps(new_key_data),
            json.dumps(old_key_info),
            str(grace_period_seconds),
        )
    except ResponseError as re:
        logger.error("Redis error during key rotation: %s", str(re))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key rotation failed",
        )

    logger.info(
        "API key rotated successfully",
        extra={
            "user_id": user_id[:8],
            "old_key_prefix": key_hash[:8],
            "new_key_prefix": new_key_hash[:8],
            "grace_period_days": GRACE_PERIOD_DAYS,
        },
    )

    return {
        "api_key": new_plain_key,
        "plan": plan,
        "created_at": timestamp,
        "name": new_key_data["name"],
        "message": f"Old key will remain active for {GRACE_PERIOD_DAYS} days",
        "grace_period_ends": old_key_info["grace_period_ends"],
        "new_key_id": new_key_hash,
    }


# =============================================================================
# USAGE
# =============================================================================

@router.get("/usage", response_model=Dict[str, Any])
async def get_usage(
    current_client: TokenData = Depends(validate_api_key_or_token),
    redis: Redis = Depends(get_redis),
):
    """
    Get current API usage statistics.
    Returns usage count, limits, and remaining requests for today.
    Works with both API keys and JWT tokens.
    """
    try:
        raw_sub = current_client.sub
        user_id: Optional[str] = None
        api_key_hash: Optional[str] = None
        client_type = getattr(current_client, "type", "")

        if client_type == "api_key":
            user_exists = (await redis.exists(f"user:{raw_sub}")) == 1
            if user_exists:
                user_id = raw_sub
            else:
                if APIKeySecurity.validate_key_hash(str(raw_sub)):
                    api_key_hash = str(raw_sub)
                else:
                    try:
                        api_key_hash = create_hashed_key(str(raw_sub))
                    except Exception:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid API key format",
                        )
            if api_key_hash and not user_id:
                key_data = await redis.get(f"key:{api_key_hash}")
                if key_data:
                    key_info = _safe_json_loads(_decode(key_data) or "")
                    if key_info:
                        user_id = key_info.get("user_id")
        else:
            user_id = str(raw_sub)

        if client_type == "api_key" and api_key_hash:
            usage_count = await read_usage_for_api_key(api_key_hash, redis)
        else:
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unable to resolve user identity",
                )
            usage_count = await read_usage_for_userid(user_id, redis)

        # Plan limits
        plan = "FREE"
        if user_id:
            user_key = f"user:{user_id}"
            plan_raw = await redis.hget(user_key, "plan")
            plan = (_decode(plan_raw) or "FREE").upper()

        limit_map = {
            "FREE": 100,
            "PREMIUM": 10000,
            "ENTERPRISE": 100000,
        }
        daily_limit = limit_map.get(plan, 100)
        remaining = max(daily_limit - int(usage_count or 0), 0)
        usage_percentage = (int(usage_count or 0) / daily_limit) * 100 if daily_limit > 0 else 0.0

        return {
            "usage_today": int(usage_count or 0),
            "limit": daily_limit,
            "remaining": remaining,
            "usage_percentage": round(usage_percentage, 1),
            "plan": plan,
            "reset_time": "00:00 UTC",
            "as_of": _utcnow_iso(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Usage retrieval error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve usage information",
        )

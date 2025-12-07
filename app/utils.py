# utils.py — versión corregida y endurecida (v2)

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from app.auth import PLAN_SCOPES, create_hashed_key
from app.cache import AsyncTTLCache
from app.config import settings, get_settings
from app.logger import logger
from app.validation import VerificationResult


# ------------------------------
# Constantes y utilidades comunes
# ------------------------------

VALID_PLANS = {"FREE", "PREMIUM", "ENTERPRISE"}
USAGE_TTL_SECONDS = 48 * 3600
LOCK_DEFAULT_TTL = 30
LOCK_RETRY_WAIT = 0.1
LOCK_RETRY_ATTEMPTS = 6

plan_cache = AsyncTTLCache(ttl=60, maxsize=1000)

# Scripts Lua
INCR_EXPIRE_SCRIPT = """
local key = KEYS[1]
local amount = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local v = redis.call('INCRBY', key, amount)
redis.call('EXPIRE', key, ttl)
return v
"""

# Libera el lock sólo si el valor coincide con el token del propietario
UNLOCK_IF_VALUE_MATCHES_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
else
  return 0
end
"""

# Incrementa y fija TTL sólo en el primer incremento
USAGE_INCREMENT_SCRIPT = """
local key = KEYS[1]
local increment = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local new_val = redis.call('INCRBY', key, increment)
if new_val == increment then
  redis.call('EXPIRE', key, ttl)
end
return tostring(new_val)
"""


# ------------------------------
# Helpers de saneo y conversión
# ------------------------------

def sanitize_redis_key(value: Optional[str], max_len: int = 128) -> str:
    if not value:
        return ""
    s = re.sub(r"[^A-Za-z0-9_\-]", "", str(value))
    return s[:max_len]


def sanitize_metadata_value(value: Optional[str], max_len: int = 100) -> str:
    if not value:
        return ""
    s = re.sub(r"[^A-Za-z0-9_\-]", "", str(value))
    return s[:max_len]


def b2s(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("latin-1", errors="ignore")
    return str(value)


def s2int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, (bytes, bytearray)):
            value = b2s(value)
        return int(float(value))
    except Exception:
        return default


def today_str_utc() -> str:
    return datetime.now(timezone.utc).date().isoformat()


async def maybe_log_cache_pressure() -> None:
    try:
        size = getattr(plan_cache, "current_size", None)
        if size is not None and size > 0.9 * getattr(plan_cache, "maxsize", 1000):
            logger.warning("Plan cache near capacity: %s/%s", size, getattr(plan_cache, "maxsize", "unknown"))
    except Exception:
        pass


# ------------------------------
# Operaciones atómicas en Redis
# ------------------------------

async def incr_with_ttl(redis: Redis, key: str, amount: int = 1, ttl: int = USAGE_TTL_SECONDS) -> int:
    try:
        result = await redis.eval(INCR_EXPIRE_SCRIPT, 1, key, str(amount), str(ttl))
        return s2int(result, default=0)
    except Exception as e:
        logger.exception(f"Error executing atomic INCR script on {key}: {e}")
        try:
            await redis.incrby(key, amount)
            await redis.expire(key, ttl)
            return s2int(await redis.get(key), default=0)
        except Exception as e2:
            logger.exception(f"Fallback INCR failed for {key}: {e2}")
            raise


async def acquire_lock(redis: Redis, lock_key: str, ttl: int = LOCK_DEFAULT_TTL,
                       wait: float = LOCK_RETRY_WAIT, attempts: int = LOCK_RETRY_ATTEMPTS) -> Optional[str]:
    """
    Lock seguro con token: retorna el token si se adquiere, None si no.
    """
    import uuid
    token = str(uuid.uuid4())
    for _ in range(attempts):
        try:
            ok = await redis.set(lock_key, token, nx=True, ex=ttl)
            if ok:
                return token
        except Exception as e:
            logger.debug(f"Error acquiring lock {lock_key}: {e}")
        await asyncio.sleep(wait)
    return None


async def release_lock(redis: Redis, lock_key: str, token: Optional[str]) -> None:
    if not token:
        return
    try:
        await redis.eval(UNLOCK_IF_VALUE_MATCHES_SCRIPT, 1, lock_key, token)
    except Exception as e:
        logger.debug(f"Error releasing lock {lock_key}: {e}")


# ------------------------------
# Métricas de uso
# ------------------------------

async def read_usage_for_api_key(api_key: str, redis: Redis) -> int:
    if not api_key:
        return 0
    today = today_str_utc()
    raw_key_legacy = f"usage:{api_key}:{today}"
    hashed = create_hashed_key(api_key)
    raw_key_hashed = f"usage:{hashed}:{today}"

    vals: List[int] = []
    try:
        v = await redis.get(raw_key_legacy)
        if v is not None:
            vals.append(s2int(v, default=0))
    except Exception:
        logger.debug("No integer in legacy raw usage key %s", raw_key_legacy)
    try:
        v = await redis.get(raw_key_hashed)
        if v is not None:
            vals.append(s2int(v, default=0))
    except Exception:
        logger.debug("No integer in hashed usage key %s", raw_key_hashed)

    return max(vals) if vals else 0


async def read_usage_for_userid(user_id: str, redis: Redis) -> int:
    safe_user = sanitize_redis_key(user_id)
    key = f"usage:user:{safe_user}:{today_str_utc()}"
    try:
        v = await redis.get(key)
        return 0 if v is None else s2int(v, default=0)
    except Exception as e:
        logger.debug(f"Error reading usage for key {key}: {e}")
        return 0


async def increment_usage(redis, user_id: str, amount: int = 1) -> None:
    """Incrementa el contador de uso diario."""
    # Functions sanitize_redis_key and today_str_utc are defined above in this file
    safe_user = sanitize_redis_key(user_id)  # ✅ Direct call, no import needed
    today = today_str_utc()  # ✅ Direct call, no import needed
    key = f"usage:user:{safe_user}:{today}"  # ✅ MISMA CLAVE que read_usage_for_userid
    
    try:
        # Atomic increment
        new_value = await redis.incrby(key, amount)
        await redis.expire(key, 86400)
        
        logger.info(f"Usage incremented for {user_id}: -> {new_value}")
        
    except Exception as e:
        logger.error(f"Error incrementing usage for {user_id}: {e}")
        return
    

def calculate_dynamic_limit(current_usage: int, plan: str) -> int:
    plan = (plan or "").lower()
    base_limits = {"free": 1, "premium": 100, "enterprise": 1000}
    if plan not in base_limits:
        return 100
    base = base_limits[plan]
    threshold = int(base * 0.8)
    if current_usage > threshold:
        return int(max(base, current_usage * 1.2))
    return base


# ------------------------------
# Plan / scope lookup
# ------------------------------

async def get_user_plan_by_id(user_id: str, redis: Redis) -> str:
    try:
        user_key = f"user:{sanitize_redis_key(user_id)}"
        user_data = await redis.hgetall(user_key)
        if user_data:
            plan_val = user_data.get(b"plan") or user_data.get("plan")
            plan = (b2s(plan_val) or "FREE").upper()
            return plan if plan in VALID_PLANS else "FREE"
        return "FREE"
    except Exception as e:
        logger.error(f"Error getting user plan by ID: {str(e)}")
        return "FREE"
    
def _get_plan_config_safe(plan: str) -> Dict[str, Any]:
    pf = getattr(get_settings(), "plan_features", None) or {}
    plan_upper = (plan or "").upper()
    return pf.get(plan_upper) or pf.get("FREE", {}) or {}

async def get_plan_by_key(hashed_key: str, redis: Redis) -> str:
    if settings.environment == "testing":
        return "FREE"

    redis_key = f"key:{sanitize_redis_key(hashed_key)}"
    try:
        key_data = await redis.get(redis_key)
        if not key_data:
            return "FREE"
        key_data_str = b2s(key_data) or ""
        if not key_data_str.strip():
            return "FREE"
        try:
            key_info = json.loads(key_data_str)
            if isinstance(key_info, dict):
                plan_value = key_info.get("plan")
                if plan_value:
                    plan_str = str(plan_value).upper().strip()
                    return plan_str if plan_str in VALID_PLANS else "FREE"
            elif isinstance(key_info, str):
                plan_candidate = key_info.upper().strip()
                if plan_candidate in VALID_PLANS:
                    return plan_candidate
        except (json.JSONDecodeError, TypeError, AttributeError):
            plan_candidate = key_data_str.upper().strip()
            if plan_candidate in VALID_PLANS:
                return plan_candidate
        return "FREE"
    except Exception as e:
        logger.error(f"Error al obtener plan del usuario: {str(e)}")
        return "FREE"


async def get_user_plan_safe(request: Request, redis: Redis) -> str:
    try:
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return "FREE"

        cache_key = f"plan_cache:{create_hashed_key(api_key)}"
        cached = await plan_cache.get(cache_key)
        if cached is not None:
            plan_cached = (b2s(cached) or "").upper().strip()
            if plan_cached in VALID_PLANS:
                await maybe_log_cache_pressure()
                return plan_cached

        plan_str = await get_plan_by_key(create_hashed_key(api_key), redis)
        plan_str = (plan_str or "FREE").upper().strip()
        if plan_str not in VALID_PLANS:
            plan_str = "FREE"

        await plan_cache.set(cache_key, plan_str)
        await maybe_log_cache_pressure()
        return plan_str
    except Exception as e:
        logger.error(f"Error al obtener plan del usuario: {e}")
        return "FREE"


# ------------------------------
# Wrappers para validaciones externas
# ------------------------------

def check_smtp_mailbox(email: str) -> Tuple[bool, str]:
    from app.validation import check_smtp_mailbox as _check
    return _check(email)


def check_domain(email: str) -> VerificationResult:
    from app.validation import check_domain as _check
    return _check(email)


# ------------------------------
# Cabeceras de seguridad
# ------------------------------

def add_security_headers_to_response(response: JSONResponse) -> None:
    """
    CSP sin inline scripting; evitar X-XSS-Protection deprecado.
    """
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' https://cdn.redoc.ly; "  # Allow ReDoc CDN
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " # Allow fonts
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        ),
        "Permissions-Policy": (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=(), "
            "display-capture=(), screen-wake-lock=(), web-share=()"
        ),
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Permitted-Cross-Domain-Policies": "none",
    }
    response.headers.update(headers)


# ------------------------------
# Múltiples API keys / migración
# ------------------------------

async def update_all_user_api_keys(user_id: str, new_plan: str, redis: Redis) -> None:
    safe_user = sanitize_redis_key(user_id)
    lock_key = f"lock:update_keys:{safe_user}"
    token = await acquire_lock(redis, lock_key, ttl=30, wait=0.1, attempts=LOCK_RETRY_ATTEMPTS)
    if not token:
        logger.warning(f"Could not acquire lock to update keys for user {safe_user}")
        raise HTTPException(status_code=503, detail="Update in progress, try again later")

    try:
        new_plan_norm = (new_plan or "FREE").upper()
        scopes = PLAN_SCOPES.get(new_plan_norm, [])

        client_hash = create_hashed_key(user_id)
        api_key_hashes = await redis.smembers(f"api_keys:{client_hash}") or set()

        for api_key_hash in api_key_hashes:
            key_hash_str = b2s(api_key_hash) or ""
            if not key_hash_str:
                continue

            key_key = f"key:{sanitize_redis_key(key_hash_str)}"
            key_data = await redis.get(key_key)
            key_info: Dict[str, Any]
            if key_data:
                try:
                    key_info = json.loads(b2s(key_data) or "{}")
                    if not isinstance(key_info, dict):
                        key_info = {}
                except Exception:
                    key_info = {}
            else:
                key_info = {}

            key_info["plan"] = new_plan_norm
            key_info["scopes"] = scopes

            try:
                await redis.set(key_key, json.dumps(key_info))
            except Exception as e:
                logger.error(f"Error saving updated API key {key_hash_str}: {e}")
    finally:
        await release_lock(redis, lock_key, token)


async def migrate_user_to_multi_key_system(user_id: str, redis: Redis) -> bool:
    try:
        client_hash = create_hashed_key(user_id)
        existing_keys = await redis.smembers(f"api_keys:{client_hash}") or set()
        if existing_keys:
            return True

        current_key_hash = await redis.get(f"user:{sanitize_redis_key(user_id)}:api_key")
        if not current_key_hash:
            return False

        current_key_hash_str = b2s(current_key_hash) or ""
        if not current_key_hash_str:
            return False

        await redis.sadd(f"api_keys:{client_hash}", current_key_hash_str)

        key_key = f"key:{sanitize_redis_key(current_key_hash_str)}"
        key_data = await redis.get(key_key)
        if key_data:
            try:
                key_info = json.loads(b2s(key_data) or "{}")
                if not isinstance(key_info, dict):
                    key_info = {}
            except Exception:
                key_info = {}
        else:
            key_info = {}

        if "name" not in key_info:
            key_info["name"] = "Clave principal"
        plan = (str(key_info.get("plan") or "FREE")).upper()
        key_info["plan"] = plan
        key_info["scopes"] = PLAN_SCOPES.get(plan, [])

        try:
            await redis.set(key_key, json.dumps(key_info))
        except Exception as e:
            logger.error(f"Error updating key metadata during migration: {e}")

        return True
    except Exception as e:
        logger.error(f"Error migrating user to multi-key system: {str(e)}")
        return False


async def get_user_api_keys(user_id: str, redis: Redis) -> List[Dict[str, Any]]:
    try:
        client_hash = create_hashed_key(user_id)
        api_key_hashes = await redis.smembers(f"api_keys:{client_hash}") or set()

        keys: List[Dict[str, Any]] = []
        for api_key_hash in api_key_hashes:
            key_hash_str = b2s(api_key_hash) or ""
            if not key_hash_str:
                continue

            key_blob = await redis.get(f"key:{sanitize_redis_key(key_hash_str)}")
            if not key_blob:
                continue

            try:
                key_info = json.loads(b2s(key_blob) or "{}")
                if not isinstance(key_info, dict):
                    continue
                keys.append({
                    "hash": key_hash_str,
                    "name": key_info.get("name", "Sin nombre"),
                    "plan": key_info.get("plan", "FREE"),
                    "created_at": key_info.get("created_at", ""),
                    "revoked": str(key_info.get("revoked", "0")) == "1",
                })
            except Exception as e:
                logger.error(f"Error parsing API key data: {str(e)}")

        return keys
    except Exception as e:
        logger.error(f"Error getting user API keys: {str(e)}")
        return []


async def repair_user_data(user_id: str, email: str, plan: str, redis: Redis) -> bool:
    try:
        user_key = f"user:{sanitize_redis_key(user_id)}"
        user_data = await redis.hgetall(user_key)

        if not user_data:
            await redis.hset(
                user_key,
                mapping={
                    "id": user_id,
                    "email": email,
                    "plan": plan,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )

        email_index_key = f"user:email:{sanitize_redis_key(email, max_len=255)}"
        user_json = await redis.get(email_index_key)
        if not user_json:
            user_info = {
                "id": user_id,
                "email": email,
                "plan": plan,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            await redis.set(email_index_key, json.dumps(user_info))

        await migrate_user_to_multi_key_system(user_id, redis)
        return True
    except Exception as e:
        logger.error(f"Error repairing user data: {str(e)}")
        return False


async def adjust_quotas(user_id: str, redis: Redis):
    usage = int(await redis.get(f"usage:{user_id}") or 0)
    plan = await get_plan_by_key(user_id, redis)

    # Acceder como atributo, no como diccionario
    threshold_percent = settings.dynamic_quotas.threshold_percent

    base_limits = {
        "free": 1,
        "premium": 100,
        "enterprise": 1000,
        "FREE": 1,
        "PREMIUM": 100,
        "ENTERPRISE": 1000
    }
    base_limit = base_limits.get(plan.lower(), 1)
    threshold = base_limit * threshold_percent

    if usage > threshold:
        new_limit = calculate_dynamic_limit(usage, plan)
        await redis.set(f"rate_limit:{user_id}", new_limit)
        logger.info(f"Adjusted quota for {user_id} to {new_limit}")
    

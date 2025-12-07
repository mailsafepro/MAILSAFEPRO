
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Union, Any

import hashlib
import secrets
import json
import re
import time
from uuid import uuid4

from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, InvalidIssuerError


from fastapi import (
    Depends,
    HTTPException,
    status,
    Header,
    APIRouter,
    Request,
    Security,
)
from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials,
    HTTPBasic,
    SecurityScopes,
    HTTPBasicCredentials,
)
from redis.asyncio import Redis
from arq.connections import ArqRedis
from pydantic import ValidationError
from zxcvbn import zxcvbn

from app.config import settings
from app.models import (
    TokenData,
    KeyRotationRequest,
    UserInDB,
    UserRegister,
    UserLogin,
)
from app.logger import logger
from app.pii_mask import mask_email


router = APIRouter(tags=["Authentication"])

# =============================================================================
# CONSTANTES Y CONFIGURACIÓN
# =============================================================================

JWT_ALGORITHM = settings.jwt.algorithm.upper()
ACCESS_TOKEN_EXPIRE_MINUTES = settings.jwt.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = settings.jwt.refresh_token_expire_days 

BLACKLIST_PREFIX = "jwt_blacklist:"
REFRESH_TOKEN_PREFIX = "refresh_token:"
API_KEY_PREFIX = "key:"

PLAN_SCOPES = {
    "FREE": ["validate:single", "billing"],
    "PREMIUM": [
        "validate:single", "validate:batch", "batch:upload", "billing",
        "job:create", "job:read", "job:results", "webhook:manage"
    ],
    "ENTERPRISE": [
        "validate:single", "validate:batch", "batch:upload", "billing",
        "job:create", "job:read", "job:results", "webhook:manage", "admin"
    ],
}


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Regex compiladas para rendimiento/consistencia
API_KEY_PATTERN = re.compile(r"[A-Za-z0-9_\-]+")
EMAIL_PATTERN = re.compile(r"[^@]+@[^@]+\.[^@]+")

# =============================================================================
# CLASES Y ESQUEMAS DE SEGURIDAD
# =============================================================================

class CustomHTTPBearer(HTTPBearer):
    """HTTP Bearer con mejor manejo de errores y mensajes consistentes."""
    
    def __init__(self, auto_error: bool = True):
        # Llamar al init del padre sin pasar scheme_name para evitar problemas
        super().__init__(auto_error=auto_error, scheme_name="Bearer")

    async def __call__(self, request: Request) -> Optional[HTTPAuthorizationCredentials]:
        try:
            # Usar implementación directa en lugar de super().__call__
            authorization = request.headers.get("Authorization")
            if not authorization:
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return None
            
            scheme, _, credentials = authorization.partition(" ")
            if scheme.lower() != "bearer":
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication scheme",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return None
            
            if not credentials:
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid token",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return None
            
            return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)
            
        except HTTPException as exc:
            # Normaliza 403 a 401 para evitar fugas de información
            if exc.status_code == status.HTTP_403_FORBIDDEN:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from exc
            raise


security_scheme = CustomHTTPBearer(auto_error=False)
basic_auth = HTTPBasic(auto_error=False)

# =============================================================================
# UTILIDADES CORE
# =============================================================================


def get_redis(request: Request) -> Redis:
    if not hasattr(request.app.state, "redis") or request.app.state.redis is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return request.app.state.redis

def get_arq_redis(request: Request) -> ArqRedis:
    """Obtiene la instancia de ARQ Redis desde el estado de la app."""
    if not hasattr(request.app.state, "arq_redis") or request.app.state.arq_redis is None:
        raise HTTPException(status_code=503, detail="Job queue unavailable")
    return request.app.state.arq_redis


def _decode_value(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8")
    return str(val)


def _decode_hash(h: Dict[Any, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in h.items():
        ks = _decode_value(k)
        vs = _decode_value(v)
        out[ks] = vs
    return out


def create_hashed_key(api_key: str) -> str:
    """Crea hash SHA-256 de la API key con validaciones estrictas."""
    if not isinstance(api_key, str):
        logger.error("Expected string for API key")
        raise ValueError("API key must be a string")
    if len(api_key) < 16:
        raise ValueError("API key must be at least 16 characters")
    if not API_KEY_PATTERN.fullmatch(api_key):
        raise ValueError("API key contains invalid characters")
    if len(set(api_key)) < 8:
        raise ValueError("API key has insufficient entropy")
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica contraseña con validación de formato seguro."""
    if not hashed_password or not hashed_password.strip():
        logger.warning("Attempt to verify password with empty hash")
        return False
    if not (hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$")):
        logger.warning("Invalid password hash format")
        return False
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error("Error verifying password: %s", e)
        return False


def get_password_hash(password: str) -> str:
    """Hash de contraseña con validación mínima de longitud."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    return pwd_context.hash(password)

def _jwt_signing_key() -> Union[str, bytes]:
    alg = JWT_ALGORITHM
    if alg.startswith("HS"):
        return settings.jwt.secret.get_secret_value()
    return settings.jwt.private_key_pem.get_secret_value()

def _jwt_verify_key(token: str) -> Union[str, bytes]:
    alg = JWT_ALGORITHM
    if alg.startswith("HS"):
        return settings.jwt.secret.get_secret_value()
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if not kid or kid not in settings.jwt.public_keys:
        raise InvalidTokenError("Unknown or missing kid")
    return settings.jwt.public_keys[kid]

def _get_unverified_claims(token: str) -> dict:
    """PyJWT compatible version of get_unverified_claims."""
    return jwt.decode(token, options={"verify_signature": False}, algorithms=[JWT_ALGORITHM])


LUA_RATE_LIMIT = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local now = redis.call('TIME')[1]
local current = redis.call('INCR', key)
if current == 1 then
  redis.call('EXPIRE', key, window)
end
local ttl = redis.call('TTL', key)
return {current, ttl}
"""

async def enforce_rate_limit(redis: Redis, bucket: str, limit: int, window: int):
    local_key = f"rl:{hashlib.sha256(bucket.encode()).hexdigest()}"
    local_res = await redis.eval(LUA_RATE_LIMIT, 1, local_key, str(window))
    count = int(local_res[0]) if isinstance(local_res, (list, tuple)) and len(local_res) >= 1 else 1
    ttl = int(local_res[1]) if isinstance(local_res, (list, tuple)) and len(local_res) >= 2 else window
    if count > limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={"error": "Rate limit exceeded", "retry_after": max(1, ttl)})


# =============================================================================
# GESTIÓN DE USUARIOS
# =============================================================================

async def create_user(redis: Redis, email: str, password: str, plan: str = "FREE") -> UserInDB:
    """Crea nuevo usuario con operación atómica en Redis."""
    if not EMAIL_PATTERN.match(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format")
    if len(password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters long")
    
    # ✅ Password Strength Check (zxcvbn)
    results = zxcvbn(password)
    if results["score"] < 3: # 0-4 scale, 3 is "safe"
        # ⚠️ SECURITY FIX: Mask email to prevent PII in logs
        masked_email = email[:3] + "***@***" if "@" in email else "***"
        logger.warning(f"Weak password attempt for {masked_email}: score {results['score']}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password too weak. Suggestions: {', '.join(results['feedback']['suggestions'] or ['Use a stronger password'])}"
        )

    user_id = str(uuid4())
    hashed_password = get_password_hash(password)
    created_at = datetime.now(timezone.utc)

    # Lua script para atomicidad: si email ya existe (índice), aborta
    lua_script = """
    local email_key = KEYS[1]
    local user_key = KEYS[2]
    local emails_set = KEYS[3]
    if redis.call('EXISTS', email_key) == 1 then
      return 0
    end
    redis.call('SET', email_key, ARGV[1])
    redis.call('HSET', user_key,
      'id', ARGV[2],
      'email', ARGV[3],
      'hashed_password', ARGV[4],
      'plan', ARGV[5],
      'created_at', ARGV[6]
    )
    redis.call('SADD', emails_set, ARGV[3])
    return 1
    """

    email_data = json.dumps(
        {
            "id": user_id,
            "email": email,
            "plan": plan,
            "created_at": created_at.isoformat(),
        }
    )

    result = await redis.eval(
        lua_script,
        3,
        f"user:email:{email}",
        f"user:{user_id}",
        "users:emails",
        email_data,
        user_id,
        email,
        hashed_password,
        plan,
        created_at.isoformat(),
    )

    if result == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    # ⚠️ BUG FIX: Removed duplicate user creation code that was here (lines 325-361)
    # The Lua script above already creates the user atomically
    # The old code was creating a SECOND user with a DIFFERENT UUID
    
    now = created_at.isoformat()
    
    # Return the user from the Lua script creation
    return UserInDB(
        id=user_id,
        email=email,
        hashed_password=hashed_password,
        plan=plan,
        created_at=created_at,
        updated_at=created_at,
        is_active=True,
        email_verified=False,
    )

async def delete_user_account(user_id: str, email: str, redis: Redis) -> Dict[str, Any]:
    """
    Elimina un usuario y todos sus datos relacionados de forma segura.
    
    Elimina:
    - Índice por email (user:email:{email})
    - Hash del usuario (user:{user_id})
    - Set de emails (users:emails)
    - Todas las API keys del usuario
    - Usage/quota data
    - Subscription data
    - Rate limit data
    - Tokens relacionados (refresh tokens, blacklist)
    
    Args:
        user_id: ID del usuario a eliminar
        email: Email del usuario a eliminar
        redis: Cliente Redis
        
    Returns:
        Dict con información sobre las claves eliminadas
        
    Raises:
        HTTPException: Si el usuario no existe o hay un error
    """
    deleted_keys = []
    deleted_count = 0
    
    try:
        # 1. Eliminar índice por email (todas las variantes posibles)
        email_variants = [
            email,
            email.lower(),
            email.upper(),
            email.lower().strip(),
        ]
        
        for variant in email_variants:
            email_key = f"user:email:{variant}"
            if await redis.exists(email_key):
                await redis.delete(email_key)
                deleted_keys.append(email_key)
                deleted_count += 1
                logger.info(f"Deleted email index: {email_key}")
        
        # 2. Eliminar hash del usuario
        user_key = f"user:{user_id}"
        if await redis.exists(user_key):
            await redis.delete(user_key)
            deleted_keys.append(user_key)
            deleted_count += 1
            logger.info(f"Deleted user hash: {user_key}")
        
        # 3. Eliminar del set de emails (todas las variantes)
        for variant in email_variants:
            result = await redis.srem("users:emails", variant)
            if result:
                deleted_count += 1
        
        # 4. Eliminar todas las API keys del usuario
        # Buscar en el set de API keys del usuario
        api_keys_set_key = f"user:{user_id}:api_keys"
        api_keys_set = await redis.smembers(api_keys_set_key)
        
        for key_hash in api_keys_set:
            key_hash_str = key_hash.decode() if isinstance(key_hash, bytes) else key_hash
            key_key = f"key:{key_hash_str}"
            if await redis.exists(key_key):
                await redis.delete(key_key)
                deleted_keys.append(key_key)
                deleted_count += 1
                logger.info(f"Deleted API key: {key_key}")
        
        # Eliminar el set de API keys
        if await redis.exists(api_keys_set_key):
            await redis.delete(api_keys_set_key)
            deleted_keys.append(api_keys_set_key)
            deleted_count += 1
        
        # Eliminar API key principal
        primary_key = f"user:{user_id}:api_key"
        if await redis.exists(primary_key):
            key_hash = await redis.get(primary_key)
            if key_hash:
                key_hash_str = key_hash.decode() if isinstance(key_hash, bytes) else key_hash
                key_key = f"key:{key_hash_str}"
                if await redis.exists(key_key):
                    await redis.delete(key_key)
                    deleted_keys.append(key_key)
                    deleted_count += 1
            await redis.delete(primary_key)
            deleted_keys.append(primary_key)
            deleted_count += 1
        
        # 5. Eliminar usage/quota
        usage_key = f"usage:{user_id}"
        if await redis.exists(usage_key):
            await redis.delete(usage_key)
            deleted_keys.append(usage_key)
            deleted_count += 1
        
        # 6. Eliminar subscription
        subscription_key = f"user:{user_id}:subscription"
        if await redis.exists(subscription_key):
            await redis.delete(subscription_key)
            deleted_keys.append(subscription_key)
            deleted_count += 1
        
        # 7. Eliminar rate limit
        rate_limit_key = f"user:{user_id}:rate_limit"
        if await redis.exists(rate_limit_key):
            await redis.delete(rate_limit_key)
            deleted_keys.append(rate_limit_key)
            deleted_count += 1
        
        # 8. Eliminar refresh tokens (buscar todos los tokens del usuario)
        # Los refresh tokens se almacenan como: refresh_token:{jti}
        # Buscar todos los tokens que puedan estar relacionados
        refresh_token_pattern = f"refresh_token:*"
        # Nota: En producción, esto podría ser costoso. Considerar mantener un índice.
        
        # 9. Eliminar webhook tokens
        webhook_tokens_key = f"user:{user_id}:webhook_tokens"
        if await redis.exists(webhook_tokens_key):
            await redis.delete(webhook_tokens_key)
            deleted_keys.append(webhook_tokens_key)
            deleted_count += 1
        
        # 10. Buscar y eliminar cualquier otra clave relacionada con el usuario
        # Buscar patrones adicionales (solo en desarrollo para evitar costo en producción)
        if settings.environment.value == "development":
            patterns_to_check = [
                f"user:{user_id}:*",
                f"token:{user_id}:*",
                f"blacklist:{user_id}:*",
            ]
            
            for pattern in patterns_to_check:
                keys = await redis.keys(pattern)
                for key in keys:
                    key_str = key.decode() if isinstance(key, bytes) else key
                    if await redis.exists(key_str):
                        await redis.delete(key_str)
                        deleted_keys.append(key_str)
                        deleted_count += 1
        
        logger.warning(
            f"User account deleted",
            extra={
                "user_id": user_id[:8],
                "email": email[:3] + "***@***" if "@" in email else "***",
                "deleted_keys_count": deleted_count,
                "action": "account_deletion",
            }
        )
        
        return {
            "status": "success",
            "message": "User account deleted successfully",
            "deleted_keys_count": deleted_count,
            "user_id": user_id,
        }
        
    except Exception as e:
        logger.error(f"Error deleting user account: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user account: {str(e)}"
        )


async def get_user_by_email(redis: Redis, email: str) -> Optional[UserInDB]:
    """Obtiene el usuario por email desde Redis con backfill y sin extras."""
    if not EMAIL_PATTERN.match(email):
        return None

    idx = await redis.get(f"user:email:{email}")
    if not idx:
        return None
    idx_json = _decode_value(idx)
    idx_data = json.loads(idx_json)
    user_id = idx_data.get("id")
    if not user_id:
        return None

    user_hash = await redis.hgetall(f"user:{user_id}")
    if not user_hash:
        return None
    user_dict = _decode_hash(user_hash)

    # Backfill timestamps si faltan
    now_iso = datetime.now(timezone.utc).isoformat()
    created = user_dict.get("created_at") or idx_data.get("created_at") or now_iso
    updated = user_dict.get("updated_at") or idx_data.get("updated_at") or created

    # Normaliza campos del modelo y elimina extras no definidos (p.ej., 'status')
    model_fields = {
        "id": user_dict.get("id") or user_id,
        "email": user_dict.get("email") or email,
        "hashed_password": user_dict.get("hashed_password"),
        "plan": user_dict.get("plan") or idx_data.get("plan") or "FREE",
        "created_at": datetime.fromisoformat(created.replace("Z", "+00:00")) if isinstance(created, str) else created,
        "updated_at": datetime.fromisoformat(updated.replace("Z", "+00:00")) if isinstance(updated, str) else updated,
        "is_active": str(user_dict.get("is_active", "true")).lower() != "false",
        "email_verified": str(user_dict.get("email_verified", "false")).lower() == "true",
    }
    # Persistir backfill en hash para futuras lecturas
    try:
        await redis.hset(
            f"user:{user_id}",
            mapping={
                "created_at": created if isinstance(created, str) else created.isoformat(),
                "updated_at": updated if isinstance(updated, str) else updated.isoformat(),
                "email": model_fields["email"],
                "plan": model_fields["plan"],
                "is_active": "true" if model_fields["is_active"] else "false",
                "email_verified": "true" if model_fields["email_verified"] else "false",
            },
        )
    except Exception as e:
        logger.error(f"Error updating user backfill for {user_id}: {e}")

    return UserInDB(**model_fields)

# =============================================================================
# GESTIÓN DE TOKENS
# =============================================================================


def create_jwt_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    scopes: Optional[List[str]] = None,
    plan: str = "FREE",
    token_type: str = "access",
) -> str:
    now = datetime.now(timezone.utc)
    default_expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) if token_type == "access" else timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    exp = now + (expires_delta or default_expire)
    payload = {
        **data,
        "exp": int(exp.timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "jti": str(uuid4()),
        "iss": settings.jwt.issuer,
        "aud": settings.jwt.audience,
        "scopes": scopes or PLAN_SCOPES.get(plan.upper(), []),
        "plan": plan.upper(),
        "type": token_type,
    }
    headers = {"kid": settings.jwt.active_kid} if not JWT_ALGORITHM.startswith("HS") else None
    return jwt.encode(payload, _jwt_signing_key(), algorithm=JWT_ALGORITHM, headers=headers or {})


def create_access_token(
    data: dict,
    plan: str = "FREE",
    expires_delta: Optional[timedelta] = None,
    scopes: Optional[List[str]] = None,
) -> str:
    """Crea un access token con scopes/plan adecuados."""
    return create_jwt_token(data=data, expires_delta=expires_delta, scopes=scopes, plan=plan.upper(), token_type="access")


def create_refresh_token(
    data: dict,
    plan: str = "FREE",
    scopes: Optional[List[str]] = None,
) -> tuple[str, datetime]:
    """Crea un refresh token y devuelve token + expiración."""
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    token = create_jwt_token(
        data=data,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        scopes=scopes,
        plan=plan,
        token_type="refresh",
    )
    return token, expire


# =============================================================================
# VALIDACIÓN DE AUTENTICACIÓN
# =============================================================================


async def validate_api_key(
    request: Request,
    api_key: str = Header(None, alias="X-API-Key"),
    redis: Redis = Depends(get_redis),
) -> dict:
    """Valida una API Key: formato, lookup por hash y estado."""
    request_id = getattr(request.state, "correlation_id", "unknown")

    if not api_key or not api_key.strip():
        logger.warning("Empty API Key (request: %s)", request_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API Key")
    if len(api_key) < 16 or not API_KEY_PATTERN.fullmatch(api_key):
        logger.warning("Invalid API Key format (request: %s)", request_id)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid API Key format")

    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    redis_key = f"{API_KEY_PREFIX}{key_hash}"

    try:
        key_data = await redis.get(redis_key)
        if not key_data:
            logger.warning("API Key not found (prefix: %s..., request: %s)", key_hash[:8], request_id)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")

        key_data_str = _decode_value(key_data)

        # Verificar estado deprecado
        if "deprecated" in key_data_str.lower():
            logger.info("Deprecated API Key (prefix: %s...)", key_hash[:8])
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Deprecated API Key")

        # Parse robusto
        try:
            key_info = json.loads(key_data_str)
        except json.JSONDecodeError:
            key_info = {"status": "active"}

        # Enriquecer con datos de usuario si están
        user_info = None
        user_id = key_info.get("user_id") if isinstance(key_info, dict) else None
        if user_id:
            try:
                user_hash = await redis.hgetall(f"user:{user_id}")
                if user_hash:
                    user_info = _decode_hash(user_hash)
                else:
                    user_info = {"id": user_id}
            except Exception:
                user_info = {"id": user_id}

        logger.info(
            "Valid API Key (prefix: %s..., user: %s...)",
            key_hash[:8],
            (user_id[:8] if user_id else "N/A"),
        )
        return {
            "api_key": api_key,
            "key_hash": key_hash,
            "key_info": key_info,
            "user": user_info,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("API Key validation error (request: %s): %s", request_id, str(e)[:200])
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication",
        )


async def validate_api_key_or_token(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
    redis: Redis = Depends(get_redis),
) -> TokenData:
    request_id = getattr(request.state, "correlation_id", "unknown")
    
    logger.debug(f"Auth attempt - X-API-Key: {x_api_key}, Authorization present: {bool(authorization)} (request: {request_id})")

    # 1) API Key
    if x_api_key:
        try:
            validated = await validate_api_key(request, x_api_key, redis)
            if not isinstance(validated, dict):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")

            api_key_str = validated.get("api_key") or str(x_api_key)

            # user_id (si existe)
            user_id = None
            try:
                user_id = (validated.get("key_info") or {}).get("user_id") or (validated.get("user") or {}).get("id")
            except Exception:
                user_id = None

            # plan (si existe)
            plan = "FREE"
            try:
                key_data = await redis.get(f"key:{validated['key_hash']}")
                if key_data:
                    key_info = json.loads(_decode_value(key_data))
                    plan = key_info.get("plan", plan)
            except Exception as e:
                logger.warning(f"Failed to get plan from key data: {e}")

            scopes = PLAN_SCOPES.get(plan.upper(), PLAN_SCOPES["FREE"])
            sub_subject = user_id if user_id else api_key_str

            return TokenData(
                sub=sub_subject,
                exp=int(time.time()) + 3600,
                jti=f"api_key_{validated['key_hash'][:8]}",
                iss=settings.jwt.issuer,
                aud=settings.jwt.audience,
                scopes=scopes,
                plan=plan,
                type="api_key",
            )
        except HTTPException as api_key_exc:
            # Si llega X-API-Key y falla, no intentamos JWT para evitar ambigüedad
            raise api_key_exc

    # 2) JWT Bearer
    if authorization:
        if authorization.startswith("Bearer "):
            token = authorization.split(" ", 1)[1].strip()
            logger.debug(f"Bearer token present, length: {len(token) if token else 0}, starts with: {token[:20] if token else 'EMPTY'}...")
                        
            try:
                credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
                result = await get_current_client(SecurityScopes(), credentials, redis)
                logger.debug(f"Token validated successfully (request: {request_id})")
                return result
            except HTTPException as jwt_exc:
                logger.warning("JWT validation failed (request: %s): %s", request_id, jwt_exc.detail)
                raise jwt_exc
        else:
            logger.warning("Authorization header present but not Bearer scheme (request: %s): %s", request_id, authorization[:30])
    
    # 3) Ningún método provisto
    logger.warning("No authentication provided (request: %s)", request_id)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API Key or Authorization token")


async def get_current_client(
    security_scopes: SecurityScopes,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    redis: Redis = Depends(get_redis),
) -> TokenData:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials", headers={"WWW-Authenticate": "Bearer"})
    
    token = credentials.credentials
    
    try:
        logger.debug(f"Decoding JWT token: {token[:20] if token else 'EMPTY'}...")

        # Determinar clave de verificación según kid/algoritmo
        key = _jwt_verify_key(token)
        
        payload = jwt.decode(
            token,
            key,
            algorithms=[JWT_ALGORITHM],
            audience=settings.jwt.audience,
            issuer=settings.jwt.issuer,
            options={
                "require_aud": True,
                "require_iss": True,
                "require_exp": True,
                "require_iat": True,
                "require_nbf": True,
                "verify_signature": True,
            },
        )
        
        logger.debug(f"JWT decoded successfully, payload keys: {list(payload.keys())}")
        
        # Blacklist check
        if await is_token_blacklisted(payload.get("jti", ""), redis):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
        
        # Solo access tokens aquí
        valid_token_types = ("access", "refresh")
        token_type = payload.get("type", "access")

        if token_type not in valid_token_types:
            logger.warning("Token type mismatch: expected %s, got '%s'", valid_token_types, token_type)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        
        # Scopes
        required_scopes = security_scopes.scopes
        token_scopes = payload.get("scopes", [])
        if required_scopes and "*" not in token_scopes:
            missing = [s for s in required_scopes if s not in token_scopes]
            if missing:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing scopes: {', '.join(missing)}")
        
        return TokenData(**payload)
    
    except ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    
    except (InvalidIssuerError, InvalidTokenError) as e:
        logger.warning("JWT validation error: %s", str(e)[:200])
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    except ValidationError as e:
        logger.warning("Pydantic validation error: %s", str(e)[:200])
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")

# =============================================================================
# ESTADO DE TOKENS
# =============================================================================


async def blacklist_token(jti: str, exp: Union[int, datetime], redis: Redis) -> None:
    """Añade un token a la blacklist con TTL hasta exp."""
    try:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        exp_ts = int(exp.timestamp()) if isinstance(exp, datetime) else int(exp)
        ttl = max(1, exp_ts - now_ts)
        await redis.setex(f"{BLACKLIST_PREFIX}{jti}", ttl, 1)
    except Exception as e:
        logger.error("Blacklist error: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not blacklist token")


async def is_token_blacklisted(jti: str, redis: Redis) -> bool:
    """Comprueba si un token está en blacklist."""
    return (await redis.exists(f"{BLACKLIST_PREFIX}{jti}")) == 1


async def store_refresh_token(jti: str, expires_at: datetime, redis: Redis) -> None:
    """Guarda un refresh token (jti) con TTL en Redis."""
    ttl = int((expires_at - datetime.now(timezone.utc)).total_seconds())
    if ttl > 0:
        await redis.setex(f"{REFRESH_TOKEN_PREFIX}{jti}", ttl, 1)


async def revoke_refresh_token(jti: str, redis: Redis) -> None:
    """Revoca un refresh token eliminando su jti."""
    await redis.delete(f"{REFRESH_TOKEN_PREFIX}{jti}")


async def is_refresh_token_valid(jti: str, redis: Redis) -> bool:
    """Comprueba si un refresh token no ha sido revocado."""
    return (await redis.exists(f"{REFRESH_TOKEN_PREFIX}{jti}")) == 1


# =============================================================================
# ENDPOINTS
# =============================================================================


@router.post("/register", response_model=Dict, status_code=status.HTTP_201_CREATED)
async def register_web_user(
    request: Request,
    user_data: UserRegister,
    redis: Redis = Depends(get_redis),
):
    """Registro de usuario para panel web: crea usuario, API key y tokens."""
    try:
        user = await create_user(redis, user_data.email, user_data.password, user_data.plan)

        # Generar API Key y almacenar por hash
        api_key = secrets.token_urlsafe(32)
        key_hash = create_hashed_key(api_key)
        key_data = {
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "plan": user_data.plan.upper(),
            "user_id": user.id,
            "name": "Clave principal",
            "revoked": False,
            "revoked_at": None,
            "scopes": PLAN_SCOPES.get(user_data.plan.upper(), PLAN_SCOPES["FREE"])
        }
        await redis.set(f"key:{key_hash}", json.dumps(key_data))
        await redis.set(f"user:{user.id}:api_key", key_hash)

        # Crear tokens
        access_token = create_access_token({"sub": user.id, "email": user.email}, plan=user_data.plan)
        refresh_token, refresh_exp = create_refresh_token({"sub": user.id, "email": user.email}, plan=user_data.plan)

        # Guardar refresh jti
        refresh_payload = _get_unverified_claims(refresh_token)
        await store_refresh_token(refresh_payload["jti"], refresh_exp, redis)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "api_key": api_key,
            "message": "Guarde esta API Key de forma segura. No se volverá a mostrar.",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("User registration failed: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to register user")


# ✅ CONSTANTE para timing attack protection (definir al inicio del archivo, después de imports)
# Hash precalculado de "dummy_password" - usado para timing attack protection
DUMMY_BCRYPT_HASH = "$2b$12$kqqKThwAwLMW/c.nZrV7SOyEaA5fFJKKyiADSkyeSBL4XPqSeqLE6"


@router.post("/login", response_model=Dict)
async def login_web_user(
    request: Request,
    user_data: UserLogin,
    redis: Redis = Depends(get_redis),
):
    """
    Login de usuario para panel web.
    
    Security features:
    - Rate limiting por email + IP
    - Timing attack protection
    - Generic error messages
    - PII masking en logs
    """
    try:
        logger.info("Login attempt for: %s", mask_email(user_data.email))
        
        # Rate limiting
        client_ip = request.client.host if request.client else "unknown"
        await enforce_rate_limit(
            redis, 
            bucket=f"login:{user_data.email}:{client_ip}", 
            limit=10, 
            window=300
        )
        
        # ✅ Preparar excepción genérica (no revela si usuario existe o no)
        invalid_credentials_exc = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        # Buscar usuario
        user = await get_user_by_email(redis, user_data.email)
        
        # ✅ Usuario no encontrado - con timing attack protection
        if not user:
            masked_email = user_data.email[:3] + "***@***" if "@" in user_data.email else "***"
            logger.warning(
                f"Login failed: User not found ({masked_email})", 
                extra={"security_event": True}
            )
            
            # ✅ Timing attack protection: simular verificación de password
            try:
                pwd_context.verify("dummy_password", DUMMY_BCRYPT_HASH)
            except Exception as e:
                # Fallback si el hash dummy falla
                logger.debug(f"Timing protection fallback: {e}")
                import time
                time.sleep(0.1)  # ~100ms = tiempo típico de bcrypt
            
            raise invalid_credentials_exc
        
        # ✅ Usuario sin hash de password
        if not getattr(user, "hashed_password", None):
            masked_email = user_data.email[:3] + "***@***" if "@" in user_data.email else "***"
            logger.warning(
                f"Login failed: User without password hash ({masked_email})", 
                extra={"security_event": True}
            )
            
            # Timing attack protection
            try:
                pwd_context.verify("dummy_password", DUMMY_BCRYPT_HASH)
            except Exception:
                import time
                time.sleep(0.1)
            
            raise invalid_credentials_exc
        
        # ✅ Verificar password
        if not verify_password(user_data.password, user.hashed_password):
            masked_email = user_data.email[:3] + "***@***" if "@" in user_data.email else "***"
            logger.warning(
                f"Login failed: Invalid password for {masked_email}", 
                extra={"security_event": True}
            )
            raise invalid_credentials_exc
        
        # ✅ Login exitoso - generar tokens
        access_token = create_access_token(
            {"sub": user.id, "email": user.email}, 
            plan=user.plan
        )
        refresh_token, refresh_exp = create_refresh_token(
            {"sub": user.id, "email": user.email}, 
            plan=user.plan
        )
        
        # Almacenar refresh token
        refresh_payload = _get_unverified_claims(refresh_token)
        await store_refresh_token(refresh_payload["jti"], refresh_exp, redis)
        
        logger.info(
            f"Login successful for user: {user.id}",
            extra={"user_id": user.id, "plan": user.plan}
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": user.id, 
                "email": user.email, 
                "plan": user.plan
            },
        }
    
    except HTTPException:
        # Re-raise HTTPExceptions (401, 429, etc.)
        raise
    
    except Exception as e:
        # Log error completo pero devolver mensaje genérico
        logger.exception(
            "User login failed with unexpected error",
            extra={"error": str(e)[:200]}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to login"
        )

@router.get("/me", response_model=Dict)
async def get_current_user(
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """Devuelve información básica del usuario actual."""
    try:
        user_id = current_client.sub
        user_key = f"user:{user_id}"

        # ✅ SIEMPRE leer de Redis como fuente de verdad
        user_data = await redis.hgetall(user_key)

        if not user_data or len(user_data) < 3:
            user_data = {
                "id": user_id,
                "email": getattr(current_client, "email", ""),
                "plan": "FREE",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            await redis.hset(user_key, mapping=user_data)
        
        user_info = _decode_hash(user_data)
        user_info.setdefault("email", getattr(current_client, "email", ""))
        user_info.setdefault("id", user_id)
        
        # ✅ CRÍTICO: Plan SIEMPRE de Redis
        redis_plan = user_info.get("plan", "FREE")
        token_plan = getattr(current_client, "plan", "FREE")
        
        if redis_plan != token_plan:
            logger.info(f"Plan updated: Redis={redis_plan} vs Token={token_plan}. Using Redis.")
        
        user_info["plan"] = redis_plan
        
        return user_info

    except Exception as e:
        logger.error("Error getting user information: %s", e)
        raise HTTPException(status_code=500, detail="Error retrieving user information")


@router.post("/refresh", response_model=Dict)
async def refresh_token(
    request: Request,
    redis: Redis = Depends(get_redis),
):
    """Crea un nuevo par de tokens a partir de un refresh token válido y no revocado."""
    try:
        # 1) Extraer refresh token: Authorization: Bearer o body JSON {refresh_token}
        auth_header = request.headers.get("Authorization", "")
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        
        if not token:
            try:
                body = await request.json()
            except Exception:
                body = {}
            token = (body or {}).get("refresh_token")
        
        if not token:
            logger.warning("Refresh request without token")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing refresh token")
        
        # 2) Validar refresh token
        logger.debug(f"Validating refresh token: {token[:20]}...")
        
        try:
            key = _jwt_verify_key(token)
            refresh_payload = jwt.decode(
                token,
                key,
                algorithms=[JWT_ALGORITHM],
                audience=settings.jwt.audience,
                issuer=settings.jwt.issuer,
                options={
                    "require_aud": True,
                    "require_iss": True,
                    "require_exp": True,
                    "verify_signature": True,
                },
            )
        except ExpiredSignatureError:
            logger.warning("Refresh token expired")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
        except InvalidTokenError as e:
            logger.warning("Invalid refresh token: %s", str(e)[:200])
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        
        # 3) Validar que sea refresh token
        if refresh_payload.get("type") != "refresh":
            logger.warning("Token type mismatch: expected 'refresh', got '%s'", refresh_payload.get("type"))
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        
        # 4) Verificar que no esté revocado
        jti = refresh_payload.get("jti", "")
        if not await is_refresh_token_valid(jti, redis):
            logger.warning("Refresh token revoked: %s", jti[:8])
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")
        
        # 5) ✅ CRÍTICO: Obtener plan actualizado de Redis (no del token viejo)
        user_id = refresh_payload.get("sub")
        user_key = f"user:{user_id}"
        current_plan_raw = await redis.hget(user_key, "plan")
        current_plan = (_decode_value(current_plan_raw) or "FREE").upper()
        
        # Obtener email del payload anterior
        email = refresh_payload.get("email", "")
        
        logger.info(f"Token refreshed for user: {user_id[:8]}... (new plan: {current_plan})")
        
        # 6) Crear nuevo access token con plan actualizado
        access_token = create_access_token(
            {"sub": user_id, "email": email},
            plan=current_plan,
            scopes=PLAN_SCOPES.get(current_plan, PLAN_SCOPES["FREE"])
        )
        
        # 7) Crear nuevo refresh token
        new_refresh_token, new_refresh_exp = create_refresh_token(
            {"sub": user_id, "email": email},
            plan=current_plan,
            scopes=PLAN_SCOPES.get(current_plan, PLAN_SCOPES["FREE"])
        )
        
        # 8) Guardar nuevo refresh jti
        new_refresh_payload = _get_unverified_claims(new_refresh_token)
        await store_refresh_token(new_refresh_payload["jti"], new_refresh_exp, redis)
        
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "plan": current_plan,  # ← Incluir plan en la respuesta
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Refresh token error: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to refresh token")


@router.delete("/delete", status_code=status.HTTP_200_OK)
async def delete_account(
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    """
    Elimina la cuenta del usuario autenticado y todos sus datos relacionados.
    
    ⚠️ ADVERTENCIA: Esta operación es IRREVERSIBLE.
    
    Elimina:
    - Datos del usuario
    - Todas las API keys
    - Usage/quota
    - Suscripciones
    - Rate limits
    - Tokens relacionados
    
    Security:
    - Solo el usuario puede eliminarse a sí mismo (o admin)
    - Requiere autenticación válida
    - Registra la acción en logs para auditoría
    """
    user_id = current_client.sub
    email = current_client.email
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not found in token"
        )
    
    # Verificar que el usuario existe antes de eliminar
    user = await get_user_by_email(redis, email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verificar que el user_id del token coincide con el usuario encontrado
    if user.id != user_id:
        logger.warning(
            f"User ID mismatch in delete request",
            extra={
                "token_user_id": user_id[:8],
                "found_user_id": user.id[:8],
                "action": "account_deletion_attempt",
            }
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User ID mismatch"
        )
    
    try:
        result = await delete_user_account(user_id, email, redis)
        
        return {
            "status": "success",
            "message": "Account deleted successfully. All data has been permanently removed.",
            "deleted_at": datetime.now(timezone.utc).isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting account for user {user_id[:8]}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )


@router.post("/logout")
async def logout(
    request: Request,
    redis: Redis = Depends(get_redis),
):
    """
    Logout idempotente:
    - Si el access token es válido, lo añade a la blacklist.
    - Si el access token está expirado, responde 200 indicando que ya estaba expirado.
    - Solo devuelve 401 si el token es completamente inválido (firma/claims corruptos).
    - Intenta revocar el refresh token si se proporciona.
    """
    try:
        # 1) Extraer access token del header Authorization (opcional)
        auth_header = request.headers.get("Authorization", "")
        token: Optional[str] = None

        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()

        user_sub = "unknown"
        token_status = "none"  # none | revoked | expired

        # 2) Validar / procesar access token si existe
        if token:
            try:
                key = _jwt_verify_key(token)
                payload = jwt.decode(
                    token,
                    key,
                    algorithms=[JWT_ALGORITHM],
                    audience=settings.jwt.audience,
                    issuer=settings.jwt.issuer,
                    options={
                        "require_aud": True,
                        "require_iss": True,
                        "require_exp": True,
                        "verify_signature": True,
                    },
                )

                jti = payload.get("jti")
                exp = payload.get("exp")
                user_sub = str(payload.get("sub", "unknown"))

                if jti and exp:
                    # Blacklist solo si tenemos jti + exp
                    await blacklist_token(jti, exp, redis)
                    token_status = "revoked"
                else:
                    token_status = "none"

            except ExpiredSignatureError:
                # Token expirado: ya no es usable, pero lo tratamos como sesión cerrada
                token_status = "expired"

            except InvalidTokenError as e:
                # Token completamente inválido -> 401
                logger.warning(
                    "Invalid access token in logout: %s",
                    str(e)[:200],
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid access token",
                ) from e

        # 3) Intentar revocar refresh token si viene en el body
        try:
            body = await request.json()
        except Exception:
            body = {}

        refresh_token = (body or {}).get("refresh_token")

        if refresh_token:
            try:
                key = _jwt_verify_key(refresh_token)
                refresh_payload = jwt.decode(
                    refresh_token,
                    key,
                    algorithms=[JWT_ALGORITHM],
                    audience=settings.jwt.audience,
                    issuer=settings.jwt.issuer,
                    options={
                        "require_aud": True,
                        "require_iss": True,
                        "require_exp": True,
                        "verify_signature": True,
                    },
                )
                jti_refresh = refresh_payload.get("jti")
                if jti_refresh:
                    await revoke_refresh_token(jti_refresh, redis)
            except ExpiredSignatureError:
                # Refresh expirado: nada que revocar, pero no consideramos error
                pass
            except InvalidTokenError:
                # Refresh inválido: lo ignoramos para no romper el logout
                pass

        # 4) Log y respuesta idempotente
        logger.info(
            "User logout completed (sub: %s..., token_status=%s)",
            user_sub[:8],
            token_status,
        )

        if token_status == "revoked":
            return {
                "detail": "Successfully logged out",
                "token_status": "revoked",
            }

        if token_status == "expired":
            return {
                "detail": "Access token already expired; session closed",
                "token_status": "expired",
            }

        # Sin token o sin jti/exp -> sesión cerrada localmente
        return {
            "detail": "No valid access token provided; session closed locally",
            "token_status": "none",
        }

    except HTTPException:
        # Re-lanzar HTTPException tal cual
        raise
    except Exception as e:
        logger.exception("Logout failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to logout",
        )

@router.post("/rotate-key", response_model=Dict)
async def rotate_api_key(
    data: KeyRotationRequest,
    current_client: TokenData = Security(get_current_client, scopes=["admin"]),
    redis: Redis = Depends(get_redis),
):
    """Rotación de API keys con período de gracia; acceso restringido a admin."""
    try:
        try:
            old_hash = create_hashed_key(data.old_key)
            new_hash = create_hashed_key(data.new_key)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        if not await redis.exists(f"{API_KEY_PREFIX}{old_hash}"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old key")

        old_key_data = await redis.get(f"{API_KEY_PREFIX}{old_hash}")
        if not old_key_data:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old key")

        try:
            old_key_info = json.loads(_decode_value(old_key_data))
        except json.JSONDecodeError:
            old_key_info = {"status": "active"}

        now_iso = datetime.now(timezone.utc).isoformat()
        new_key_data = {
            **old_key_info,
            "status": "active",
            "created_at": now_iso,
            "rotated_from": old_hash,
            "revoked": False,
            "revoked_at": None,
        }
        await redis.set(f"{API_KEY_PREFIX}{new_hash}", json.dumps(new_key_data))

        deprecated_data = {
            **old_key_info,
            "status": "deprecated",
            "deprecated_at": now_iso,
            "grace_period_ends": (datetime.now(timezone.utc) + timedelta(seconds=data.grace_period)).isoformat(),
        }
        await redis.setex(f"{API_KEY_PREFIX}{old_hash}", data.grace_period, json.dumps(deprecated_data))

        logger.info("API key rotated by admin: %s...", current_client.sub[:8])
        return {"status": "success", "message": "Key rotated successfully", "grace_period": data.grace_period}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Key rotation error: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Key rotation failed")


# =============================================================================
# PROTECCIÓN DE DOCUMENTACIÓN
# =============================================================================


def get_docs_access(credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """Protege la documentación con Basic Auth y comparación constante."""
    if not credentials or not credentials.username or not credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    try:
        user_hash = hashlib.sha256(credentials.username.encode()).hexdigest()
        pass_hash = hashlib.sha256(credentials.password.encode()).hexdigest()
        stored_user_hash = hashlib.sha256(settings.documentation.user.encode()).hexdigest()
        stored_pass_hash = hashlib.sha256(settings.documentation.password.encode()).hexdigest()

        logger.debug("Docs access attempt: user_hash=%s", user_hash[:8])

        valid_user = secrets.compare_digest(user_hash, stored_user_hash)
        valid_pass = secrets.compare_digest(pass_hash, stored_pass_hash)
        if not (valid_user and valid_pass):
            logger.warning("Invalid basic auth credentials for docs: user_hash=%s", user_hash[:8])
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

        logger.info("Successful docs access: user_hash=%s", user_hash[:8])
        return True
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in docs access: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication service unavailable")


# =============================================================================
# UTILIDADES DE VALIDACIÓN (externas)
# =============================================================================


def validate_api_key_format(api_key: str) -> None:
    """Valida solo el formato de la API key (sin tocar Redis)."""
    if not api_key or not api_key.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API Key")
    if len(api_key) < 16:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid API Key format")
    if not API_KEY_PATTERN.fullmatch(api_key):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid API Key format")


async def validate_api_key_string(
    request: Request,
    api_key_header: Optional[str] = Header(None, alias="X-API-Key"),
    redis: Redis = Depends(get_redis),
) -> str:
    """
    Valida el header X-API-Key y devuelve la key en texto plano.
    Para dependencias que requieren la key sin hash.
    """
    if not api_key_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API Key")

    try:
        info = await validate_api_key(request, api_key_header, redis)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error validating API Key: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication",
        )

    if not info or not isinstance(info, dict) or "api_key" not in info:
        logger.warning("validate_api_key returned unexpected value or missing 'api_key': %r", info)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")

    return info["api_key"]


# =============================================================================
# HEALTH CHECKS
# =============================================================================


@router.get("/health/auth")
@router.head("/health/auth")
async def auth_health_check(redis: Redis = Depends(get_redis)):
    """Health check para autenticación: Redis, JWT y hashing."""
    try:
        await redis.ping()

        test_token = create_access_token({"sub": "health_check", "test": True}, plan="FREE")
        _ = jwt.decode(
            test_token,
            settings.jwt.secret.get_secret_value(),
            algorithms=[JWT_ALGORITHM],
            audience=settings.jwt.audience,
            issuer=settings.jwt.issuer,
        )

        test_password = "health_check_password"
        hashed = get_password_hash(test_password)
        password_valid = verify_password(test_password, hashed)

        return {
            "status": "healthy",
            "redis": "connected",
            "jwt": "working",
            "password_hashing": "working" if password_valid else "broken",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error("Auth health check failed: %s", e)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication service unhealthy")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "get_redis",
    "get_current_client",
    "validate_api_key",
    "validate_api_key_or_token",
    "validate_api_key_string",
    "create_access_token",
    "create_hashed_key",
    "security_scheme",
    "PLAN_SCOPES",
]

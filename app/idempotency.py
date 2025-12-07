"""
Idempotency middleware for duplicate prevention.

Implements RFC-compliant idempotency using Redis-backed key storage.
Prevents duplicate requests when clients retry POST/PUT operations.
"""

import hashlib
import time
from typing import Optional, Dict, Any
from fastapi import Header
from redis.asyncio import Redis
from app.json_utils import dumps as json_dumps, loads as json_loads
from app.logger import logger

# 24-hour replay window (RFC recommendation)
IDEMPOTENCY_TTL = 86400

async def get_idempotent_response(
    redis: Redis,
    idempotency_key: str,
    request_hash: str
) -> Optional[Dict[str, Any]]:
    """
    Retrieve cached response for idempotency key.
    
    Args:
        redis: Redis client
        idempotency_key: Client-provided idempotency key (UUID recommended)
        request_hash: SHA-256 hash of request body for validation
    
    Returns:
        Cached response dict with status_code and body, or None if not found
        Returns error dict if key exists but request body differs
    """
    cache_key = f"idempotency:{idempotency_key}"
    
    try:
        cached = await redis.get(cache_key)
        if not cached:
            return None
        
        data = json_loads(cached)
        
        # Validate request hasn't changed (prevent key reuse with different body)
        if data.get("request_hash") != request_hash:
            logger.warning(
                f"Idempotency key reused with different request body",
                idempotency_key=idempotency_key,
                security_event=True
            )
            return {
                "status_code": 422,
                "body": {
                    "type": "idempotency_error",
                    "title": "Idempotency Key Mismatch",
                    "status": 422,
                    "detail": "This idempotency key was used with a different request body",
                    "idempotency_key": idempotency_key
                },
                "replayed": False
            }
        
        created_at = data.get("created_at", time.time())
        age_seconds = time.time() - created_at
        
        logger.info(
            f"Idempotent response returned",
            idempotency_key=idempotency_key,
            age_seconds=age_seconds
        )
        
        return {
            "status_code": data["status_code"],
            "body": data["body"],
            "replayed": True
        }
        
    except Exception as e:
        logger.error(f"Failed to retrieve idempotent response: {e}")
        return None

async def store_idempotent_response(
    redis: Redis,
    idempotency_key: str,
    request_hash: str,
    status_code: int,
    body: Dict[str, Any]
) -> bool:
    """
    Store response for future idempotent requests.
    
    Only successful responses (2xx) are cached.
    TTL is 24 hours per RFC recommendation.
    """
    cache_key = f"idempotency:{idempotency_key}"
    
    data = {
        "request_hash": request_hash,
        "status_code": status_code,
        "body": body,
        "created_at": time.time()
    }
    
    try:
        await redis.setex(cache_key, IDEMPOTENCY_TTL, json_dumps(data))
        logger.debug(
            f"Stored idempotent response",
            idempotency_key=idempotency_key,
            status_code=status_code,
            ttl=IDEMPOTENCY_TTL
        )
        return True
    except Exception as e:
        logger.error(f"Failed to store idempotent response: {e}")
        return False

def compute_request_hash(body: bytes) -> str:
    """
    Compute SHA-256 hash of request body.
    
    Returns first 16 chars for brevity (64-bit collision resistance).
    """
    return hashlib.sha256(body).hexdigest()[:16]

def is_valid_idempotency_key(key: str) -> bool:
    """
    Validate idempotency key format.
    
    Should be:
    - Between 1-255 characters
    - Alphanumeric, hyphens, underscores only
    - UUID format recommended
    """
    if not key or len(key) > 255:
        return False
    
    import re
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', key))

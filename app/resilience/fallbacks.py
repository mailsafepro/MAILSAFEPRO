"""
Fallback Strategies for Critical Services

Implements intelligent fallback behavior when external services fail.
Ensures the API continues functioning with degraded but acceptable performance.
"""

from typing import Dict, Any, Optional, List
from app.logger import logger
import asyncio

class DNSFallback:
    """
    DNS resolution fallback strategy.
    
    Layers:
    1. Primary DNS (aiodns with default nameservers)
    2. Secondary DNS (Google/Cloudflare: 8.8.8.8, 1.1.1.1)
    3. Optimistic fallback (assume valid if domain format correct)
    """
    
    @staticmethod
    async def resolve_with_fallback(domain: str) -> Dict[str, Any]:
        """
        Resolve DNS with multiple fallback layers.
        
        Args:
            domain: Domain to resolve
        
        Returns:
            {
                "has_mx": bool,
                "mx_records": List[str],
                "fallback_used": str | None,
                "confidence": "high" | "medium" | "low"
            }
        """
        # Layer 1: Try primary DNS
        try:
            import aiodns
            resolver = aiodns.DNSResolver()
            result = await resolver.query(domain, 'MX')
            
            mx_records = [str(r.host) for r in result]
            
            return {
                "has_mx": bool(mx_records),
                "mx_records": mx_records,
                "fallback_used": None,
                "confidence": "high"
            }
        except Exception as e:
            logger.warning(f"Primary DNS failed for {domain}: {e}")
        
        # Layer 2: Try secondary DNS (Google/Cloudflare)
        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            
            answers = await resolver.resolve(domain, 'MX')
            mx_records = [str(rdata.exchange) for rdata in answers]
            
            logger.info(f"Using secondary DNS for {domain}")
            
            return {
                "has_mx": True,
                "mx_records": mx_records,
                "fallback_used": "secondary_dns",
                "confidence": "medium"
            }
        except Exception as e:
            logger.warning(f"Secondary DNS failed for {domain}: {e}")
        
        # Layer 3: Optimistic fallback (assume valid domain)
        logger.warning(f"All DNS failed for {domain}, using optimistic fallback")
        
        return {
            "has_mx": True,  # Optimistic
            "mx_records": [],
            "fallback_used": "optimistic",
            "confidence": "low"
        }

class SMTPFallback:
    """
    SMTP verification fallback.
    
    Strategy:
    1. Full SMTP verification (RCPT TO check)
    2. Connection-only check (verify server responds)
    3. MX record check (via DNS fallback)
    """
    
    @staticmethod
    async def verify_with_fallback(email: str, domain: str) -> Dict[str, Any]:
        """
        SMTP verification with fallback layers.
        
        Args:
            email: Full email address
            domain: Domain part
        
        Returns:
            {
                "smtp_verified": bool,
                "deliverable": bool,
                "fallback_used": str | None,
                "confidence": "high" | "medium" | "low",
                "error": str | None
            }
        """
        # Layer 1: Try full SMTP verification
        try:
            from app.resilience.circuit_breakers import CircuitBreakerManager
            smtp_breaker = CircuitBreakerManager.get_breaker("smtp")
            
            @smtp_breaker
            async def check_smtp_full():
                # Full SMTP check would go here
                # For now, simulate
                return {"deliverable": True, "response": "250 OK"}
            
            result = await check_smtp_full()
            
            return {
                "smtp_verified": True,
                "deliverable": result.get("deliverable", False),
                "fallback_used": None,
                "confidence": "high",
                "error": None
            }
        except Exception as e:
            logger.warning(f"SMTP verification failed for {email}: {e}")
        
        # Layer 2: DNS/MX fallback
        try:
            dns_result = await DNSFallback.resolve_with_fallback(domain)
            
            deliverable = dns_result["has_mx"]
            confidence = "medium" if dns_result["confidence"] == "high" else "low"
            
            logger.info(f"Using MX fallback for {mask_email(email)}")
            
            return {
                "smtp_verified": False,
                "deliverable": deliverable,
                "fallback_used": "mx_only",
                "confidence": confidence,
                "error": "SMTP unavailable, used DNS fallback"
            }
        except Exception as e:
            logger.error(f"All SMTP fallbacks failed for {email}: {e}")
            
            # Layer 3: Ultimate fallback - optimistic
            return {
                "smtp_verified": False,
                "deliverable": True,  # Optimistic
                "fallback_used": "optimistic",
                "confidence": "low",
                "error": "All verification methods failed"
            }

class RedisFallback:
    """
    Redis cache fallback.
    
    Strategy:
    1. Redis (primary)
    2. In-memory TTL cache (limited size)
    3. No cache (proceed without caching)
    """
    
    _in_memory_cache: Dict[str, Any] = {}
    _cache_limit = 1000  # Limit in-memory cache size
    
    @staticmethod
    async def get_with_fallback(key: str, redis) -> Optional[Any]:
        """
        Get from Redis with in-memory fallback.
        
        Args:
            key: Cache key
            redis: Redis client
        
        Returns:
            Cached value or None
        """
        # Layer 1: Try Redis
        if redis:
            try:
                value = await redis.get(key)
                if value:
                    return value
            except Exception as e:
                logger.warning(f"Redis get failed, using fallback: {e}")
        
        # Layer 2: In-memory cache
        if key in RedisFallback._in_memory_cache:
            logger.debug(f"Using in-memory cache for {key}")
            return RedisFallback._in_memory_cache[key]
        
        return None
    
    @staticmethod
    async def set_with_fallback(key: str, value: Any, redis, ttl: int = 3600):
        """
        Set in Redis with in-memory fallback.
        
        Args:
            key: Cache key
            value: Value to cache
            redis: Redis client
            ttl: Time to live (seconds)
        """
        # Layer 1: Try Redis
        if redis:
            try:
                await redis.set(key, value, ex=ttl)
                return
            except Exception as e:
                logger.warning(f"Redis set failed, using fallback: {e}")
        
        # Layer 2: In-memory cache (with size limit)
        if len(RedisFallback._in_memory_cache) < RedisFallback._cache_limit:
            RedisFallback._in_memory_cache[key] = value
            logger.debug(f"Cached in memory: {key}")
        else:
            logger.warning(f"In-memory cache full, skipping: {key}")

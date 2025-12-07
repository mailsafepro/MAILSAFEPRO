# providers.py (versión ultra) – timeouts de alto nivel, TaskGroup 3.11+, RedisLike Protocol, SCAN iterativo, DKIM robusto
from __future__ import annotations

import asyncio
import base64
import inspect
import binascii
import hashlib
import json
import os
import random
import re
import socket
import time
import ipaddress
import threading
import textwrap
from dataclasses import asdict
from datetime import datetime
from contextlib import asynccontextmanager
from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import (
    Optional,
    Dict,
    Any,
    Tuple,
    List,
    TYPE_CHECKING,
    Protocol,
    AsyncIterator,
    Union
)
import aiodns
from ipwhois import IPWhois
from app.validation import get_mx_records, dns_resolver, check_smtp_mailbox_safe
from app.cache import UnifiedCache, AsyncTTLCache  # Unified Cache + AsyncTTLCache
from app.pii_mask import mask_email


async def query_mx_with_pref(domain: str):
    mx = await dns_resolver.query_mx_async(domain)
    return [(r.preference, r.exchange) for r in mx]


# Tipos para Redis: aislados para análisis estático sin forzar dependencia en runtime
class RedisLike(Protocol):
    async def get(self, key: str) -> Any: ...
    async def set(self, key: str, value: str, ex: int | None = ...) -> Any: ...
    def scan_iter(self, match: str = "*", count: int | None = None) -> AsyncIterator[bytes]: ...
    async def delete(self, *keys: Any) -> Any: ...

if TYPE_CHECKING:
    from redis.asyncio import Redis as AsyncRedis  # opcional, solo tipos

try:
    from prometheus_client import Counter, Histogram
    PROM_AVAILABLE = True if os.getenv("DISABLE_PROMETHEUS") != "1" else False
except Exception:
    PROM_AVAILABLE = False


# SPF/DKIM libs (opcionales)
try:
    import spf  # pyspf
    SPF_AVAILABLE = True
except Exception:
    SPF_AVAILABLE = False

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

from app.logger import logger

# -----------------------
# Configuración
# -----------------------

class DNSRecordType(Enum):
    MX = "MX"
    TXT = "TXT"
    A = "A"


# providers.py - ProviderConfig uses dataclass from line 22
from app.config import settings  # Settings central

@dataclass
class ProviderConfig:
    # Campos propios de providers (con defaults seguros)
    whois_timeout: float = 5.0
    whois_max_concurrent: int = 10
    whois_failure_threshold: int = 5
    whois_block_seconds: int = 300

    # Cachés
    general_cache_maxsize: int = 5000
    mx_cache_ttl: int = 3600
    ip_cache_ttl: int = 3600
    asn_cache_ttl: int = 3600
    general_cache_ttl: int = 1800

    # DNS y preferencias normalizadas desde settings.validation/email_validation
    @property
    def dns_timeout(self) -> float:
        # env alias primero, luego settings.validation/email_validation
        env = os.getenv("DNS_TIMEOUT")
        if env is not None:
            try:
                return float(env)
            except ValueError:
                pass
        ev = getattr(settings, "validation", getattr(settings, "email_validation", settings))
        return float(getattr(ev, "dns_timeout", getattr(ev, "mx_lookup_timeout", 2.0)))  # noqa

    @property
    def dns_nameservers(self):
        ev = getattr(settings, "validation", getattr(settings, "email_validation", settings))
        ns = getattr(ev, "dns_nameservers", None)
        return ns or None

    @property
    def mx_limit(self) -> int:
        env = os.getenv("MX_LIMIT")
        if env is not None:
            try:
                return int(env)
            except ValueError:
                pass
        ev = getattr(settings, "validation", getattr(settings, "email_validation", settings))
        return int(getattr(ev, "mx_limit", 10))

    @property
    def retry_attempts(self) -> int:
        env = os.getenv("RETRY_ATTEMPTS")
        if env is not None:
            try:
                return int(env)
            except ValueError:
                pass
        
        ev = getattr(settings, "validation", getattr(settings, "email_validation", settings))
        # Reduce default de 3 a 2 en Docker
        return int(getattr(ev, "max_retries", 2))  # ← Cambiar de 3 a 2

    @property
    def retry_base_backoff(self) -> float:
        """Backoff base para reintentos exponenciales."""
        env = os.getenv("RETRY_BASE_BACKOFF")
        if env is not None:
            try:
                return float(env)
            except ValueError:
                pass
        ev = getattr(settings, "validation", getattr(settings, "email_validation", settings))
        return float(getattr(ev, "retry_base_backoff", 0.25))

    @property
    def retry_max_backoff(self) -> float:
        """Backoff máximo para reintentos exponenciales."""
        env = os.getenv("RETRY_MAX_BACKOFF")
        if env is not None:
            try:
                return float(env)
            except ValueError:
                pass
        ev = getattr(settings, "validation", getattr(settings, "email_validation", settings))
        return float(getattr(ev, "retry_max_backoff", 2.0))


    @property
    def prefer_ipv4(self) -> bool:
        ev = getattr(settings, "validation", getattr(settings, "email_validation", settings))
        return bool(getattr(ev, "prefer_ipv4", True))

    # Aliases legacy
    @property
    def dnstimeout(self) -> float:
        return self.dns_timeout

    @property
    def preferipv4(self) -> bool:
        return self.prefer_ipv4

    # NUEVO: método utilizado por tests y por la app para construir la config desde settings
    @classmethod
    def from_settings(cls, s=settings) -> "ProviderConfig":
        # Soporta tanto settings.validation como settings.email_validation y bloque providers
        ev = getattr(s, "validation", getattr(s, "email_validation", s))
        base_ttl = int(getattr(ev, "cache_ttl", 3600))
        prov = getattr(s, "providers", None)

        return cls(
            whois_timeout=float(getattr(prov, "whois_timeout", 5.0)),
            whois_max_concurrent=int(getattr(prov, "whois_max_concurrent", 10)),
            whois_failure_threshold=int(getattr(prov, "whois_failure_threshold", 5)),
            whois_block_seconds=int(getattr(prov, "whois_block_seconds", 300)),
            general_cache_maxsize=int(getattr(prov, "general_cache_maxsize", 5000)),
            mx_cache_ttl=int(getattr(prov, "mx_cache_ttl", base_ttl)),
            ip_cache_ttl=int(getattr(prov, "ip_cache_ttl", base_ttl)),
            asn_cache_ttl=int(getattr(prov, "asn_cache_ttl", base_ttl)),
            general_cache_ttl=int(getattr(prov, "general_cache_ttl", max(300, base_ttl // 2))),
        )

# Instanciación unificada de configuración
config = ProviderConfig.from_settings()

# Prefijos de cache
CACHE_MX = "mx:"
CACHE_IP = "ip:"
CACHE_ASN = "asn:"
CACHE_DKIM = "dkim:"
CACHE_REP = "reputation:"

# -----------------------
# Prometheus metrics (si está disponible)
# -----------------------
if PROM_AVAILABLE:
    MET_DNS_FAILURES = Counter("providers_dns_failures_total", "DNS failures")
    MET_WHOIS_FAILURES = Counter("providers_whois_failures_total", "WHOIS failures")
    MET_CACHE_HITS = Counter("providers_cache_hits_total", "Cache hits")
    MET_CACHE_MISSES = Counter("providers_cache_misses_total", "Cache misses")
    MET_LATENCY = Histogram("providers_step_latency_seconds", "Latency per internal step", buckets=(.01, .05, .1, .25, .5, 1, 2, 5))
    MET_RETRY_ATTEMPTS = Counter("providers_retry_attempts_total", "Retry attempts total")
    MET_WHOIS_BLOCKED = Counter("providers_whois_blocked_total", "WHOIS blocked by circuit breaker")
else:
    class _Dummy:
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
    MET_DNS_FAILURES = MET_WHOIS_FAILURES = MET_CACHE_HITS = MET_CACHE_MISSES = MET_LATENCY = MET_RETRY_ATTEMPTS = MET_WHOIS_BLOCKED = _Dummy()

# -----------------------
# -----------------------
# In-memory caches (AsyncTTLCache)
# -----------------------

# Migrated from sync TTLCache to async AsyncTTLCache for consistency
MX_CACHE = AsyncTTLCache(maxsize=config.general_cache_maxsize, ttl=config.mx_cache_ttl, name="mx")
MX_IP_CACHE = AsyncTTLCache(maxsize=config.general_cache_maxsize, ttl=config.ip_cache_ttl, name="mx_ip")
ASN_CACHE = AsyncTTLCache(maxsize=config.general_cache_maxsize, ttl=config.asn_cache_ttl, name="asn")
GENERAL_CACHE = AsyncTTLCache(maxsize=config.general_cache_maxsize, ttl=config.general_cache_ttl, name="general")

# -----------------------
# Redis-backed cache adapter (optional)
# -----------------------

REDIS_CLIENT: Optional[RedisLike] = None

def set_redis_client(redis_client: RedisLike) -> None:
    global REDIS_CLIENT
    REDIS_CLIENT = redis_client
    if redis_client:
        UnifiedCache.initialize(redis_client)
    else:
        # Clear UnifiedCache redis client if None passed
        UnifiedCache._redis = None


async def async_cache_get(key: str) -> Any:
    """
    Layered cache get: Redis (via UnifiedCache) -> In-Memory Fallback.
    """
    # Try Redis first via UnifiedCache
    cached = await UnifiedCache.get(key)
    if cached is not None:
        return cached

    # Fallback en memoria por prefijo (async)
    if key.startswith("mx:"):
        return await MX_CACHE.get(key)
    if key.startswith("ip:") or key.startswith("mx_ip:"):
        return await MX_IP_CACHE.get(key)
    if key.startswith("asn:"):
        return await ASN_CACHE.get(key)
    return await GENERAL_CACHE.get(key)


async def async_cache_set(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """
    Layered cache set: Redis (via UnifiedCache) + In-Memory.
    """
    # Set in Redis via UnifiedCache
    await UnifiedCache.set(key, value, ttl=ttl)

    # Also set in memory
    storable = value
    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        storable = value.to_dict()

    if key.startswith("mx:"):
        await MX_CACHE.set(key, storable, ttl=ttl)
    elif key.startswith("ip:") or key.startswith("mx_ip:"):
        await MX_IP_CACHE.set(key, storable, ttl=ttl)
    elif key.startswith("asn:"):
        await ASN_CACHE.set(key, storable, ttl=ttl)
    else:
        await GENERAL_CACHE.set(key, storable, ttl=ttl)


async def async_cache_clear(prefix: Optional[str] = None) -> None:
    """
    Clear cache: Redis (via UnifiedCache) + In-Memory.
    """
    if prefix:
        # Clear Redis via UnifiedCache
        await UnifiedCache.clear(prefix)
        
        # Clear memory (async)
        if prefix.startswith("mx:"):
            await MX_CACHE.clear()
        elif prefix.startswith("ip:") or prefix.startswith("mx_ip:"):
            await MX_IP_CACHE.clear()
        elif prefix.startswith("asn:"):
            await ASN_CACHE.clear()
    else:
        # Clear all (async)
        await UnifiedCache.clear()
        await MX_CACHE.clear()
        await MX_IP_CACHE.clear()
        await ASN_CACHE.clear()
        await GENERAL_CACHE.clear()

# -----------------------
# Circuit Breaker WHOIS
# -----------------------

# providers.py — inicialización perezosa
class WHOISCircuitBreaker:
    def __init__(self):
        self.failures: Dict[str, int] = defaultdict(int)
        self.blocked_until: Dict[str, float] = {}
        self._lock: Optional[asyncio.Lock] = None

    async def _ensure_lock(self):
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def is_blocked(self, ip: str) -> bool:
        await self._ensure_lock()
        async with self._lock:
            if ip in self.blocked_until and time.time() < self.blocked_until[ip]:
                MET_WHOIS_BLOCKED.inc()
                return True
            self.blocked_until.pop(ip, None)
            self.failures[ip] = 0
            return False

    async def record_failure(self, ip: str) -> None:
        await self._ensure_lock()
        async with self._lock:
            self.failures[ip] += 1
            if self.failures[ip] >= config.whois_failure_threshold:
                self.blocked_until[ip] = time.time() + config.whois_block_seconds
                logger.warning(f"WHOIS: IP {ip} blocked until {self.blocked_until[ip]} due to {self.failures[ip]} failures")

WHOIS_CB = WHOISCircuitBreaker()
WHOIS_SEMAPHORE: Optional[asyncio.Semaphore] = None

async def _ensure_whois_semaphore():
    global WHOIS_SEMAPHORE
    if WHOIS_SEMAPHORE is None:
        WHOIS_SEMAPHORE = asyncio.Semaphore(config.whois_max_concurrent)


# -----------------------
# Helper: retry async con backoff exponencial + jitter
# -----------------------

async def async_retry(fn, *args, attempts: Optional[int] = None, base_backoff: Optional[float] = None, max_backoff: Optional[float] = None, on_retry=None, **kwargs):
    attempts = attempts if attempts is not None else config.retry_attempts
    base_backoff = base_backoff if base_backoff is not None else config.retry_base_backoff
    max_backoff = max_backoff if max_backoff is not None else config.retry_max_backoff
    last_exc: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            if attempt > 1:
                MET_RETRY_ATTEMPTS.inc()
            return await fn(*args, **kwargs)
        except Exception as e:
            last_exc = e
            backoff = min(max_backoff, base_backoff * (2 ** (attempt - 1)))
            jitter = random.uniform(0, backoff * 0.3)
            wait = backoff + jitter
            logger.debug("Retry %d/%d for %s, sleeping %.3fs due to %s", attempt, attempts, getattr(fn, "__name__", str(fn)), wait, str(e))
            if on_retry:
                try:
                    on_retry(e, attempt)
                except Exception:
                    pass
            await asyncio.sleep(wait)
    raise last_exc if last_exc else RuntimeError("Unknown retry failure")


# -----------------------
# Modelos de datos
# -----------------------

@dataclass
class ASNInfo:
    asn: Optional[str]
    asn_description: str
    network_name: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ASNInfo:
        return cls(
            asn=data.get("asn"),
            asn_description=data.get("asn_description", "") or "",
            network_name=data.get("network_name", "") or "",
        )

@dataclass
class DKIMInfo:
    status: str
    record: Optional[str]
    selector: Optional[str]
    key_type: Optional[str]
    key_length: Optional[int]

@dataclass
class DNSAuthResults:
    spf: str
    dkim: DKIMInfo
    dmarc: str

@dataclass
class ProviderAnalysis:
    domain: str
    primary_mx: Optional[str]
    ip: Optional[str]
    asn_info: Optional[ASNInfo]
    dns_auth: DNSAuthResults
    provider: str
    fingerprint: str
    reputation: float
    cached: bool
    error: Optional[str] = None

# -----------------------
# Helpers
# -----------------------

def normalize_domain(domain: str) -> str:
    d = (domain or "").strip().rstrip(".")
    try:
        d_ascii = d.encode("idna").decode("ascii")
    except Exception:
        d_ascii = d
    return d_ascii.lower()


def normalize_email_full(email: str) -> str:
    """
    Normalizes email address for deduplication and comparison.
    
    Normalization rules:
    - Always lowercase
    - Gmail/Googlemail: remove dots from local part + strip +alias
    - Other domains: strip +alias only
    
    Examples:
        John.Doe+spam@gmail.com → johndoe@gmail.com
        user+tag@example.com → user@example.com
        no.dots@yahoo.com → no.dots@yahoo.com (keeps dots for non-Gmail)
    
    Args:
        email: Email address to normalize
        
    Returns:
        Normalized email address
    """
    if not email or "@" not in email:
        return email.lower().strip()
    
    try:
        local, domain = email.rsplit("@", 1)
        
        # Normalize domain (already implemented)
        domain_normalized = normalize_domain(domain)
        
        # Lowercase local part
        local = local.lower().strip()
        
        # Gmail/Googlemail special handling
        if domain_normalized in ('gmail.com', 'googlemail.com'):
            # Remove all dots from local part
            local = local.replace('.', '')
            # Remove everything after + (alias)
            if '+' in local:
                local = local.split('+')[0]
        else:
            # For other domains, only remove alias (keep dots)
            if '+' in local:
                local = local.split('+')[0]
        
        return f"{local}@{domain_normalized}"
    
    except Exception as e:
        logger.debug(f"Email normalization failed for {email}: {e}")
        return email.lower().strip()

def safe_base64_decode(key_str: str) -> Optional[bytes]:
    try:
        s = key_str.strip()
        missing = len(s) % 4
        if missing:
            s += "=" * (4 - missing)
        return base64.b64decode(s, validate=False)
    except (binascii.Error, Exception):
        return None

def _try_load_pem_public_key_from_b64(b64: str):
    try:
        pem = "-----BEGIN PUBLIC KEY-----\n" + textwrap.fill(b64.strip(), 64) + "\n-----END PUBLIC KEY-----\n"
        return serialization.load_pem_public_key(pem.encode("ascii"), backend=default_backend())
    except Exception:
        return None


def extract_dkim_parts(dkim_record: str) -> DKIMInfo:
    info = DKIMInfo(status="unknown", record=dkim_record, selector=None, key_type=None, key_length=None)
    if not dkim_record:
        info.status = "not found"
        return info

    try:
        parts = [p.strip() for p in re.split(r';\s*', dkim_record) if p.strip()]
        kv: Dict[str, str] = {}
        for p in parts:
            if '=' in p:
                k, v = p.split('=', 1)
                kv[k.strip().lower()] = v.strip()

        info.selector = kv.get('s')
        ktype = kv.get('k')
        info.key_type = ktype.lower() if ktype else None

        key_str = kv.get('p')
        key_bytes = safe_base64_decode(key_str) if key_str else None

        length_bits: Optional[int] = None
        if key_bytes and CRYPTO_AVAILABLE:
            pub = None
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.backends import default_backend
                pub = serialization.load_der_public_key(key_bytes, backend=default_backend())
            except Exception:
                pub = _try_load_pem_public_key_from_b64(key_str or "")
            if pub is not None and hasattr(pub, "key_size"):
                length_bits = int(getattr(pub, "key_size"))
        if length_bits is None and key_bytes:
            length_bits = len(key_bytes) * 8
        if length_bits is None and key_str:
            # Heurística mínima cuando no pudo decodificar
            length_bits = max(0, len(key_str) * 6)

        info.key_length = length_bits
        info.status = "valid" if key_str else "not found"
    except Exception as e:
        logger.debug("Error parsing DKIM record: %s", str(e))
        info.status = "error"

    return info


def _is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return False

# -----------------------
# Operaciones DNS
# -----------------------

async def resolve_mx_to_ip(mx_host: str) -> Optional[str]:
    if not mx_host:
        return None
    
    # Normalizar si es un objeto
    if hasattr(mx_host, 'exchange'):
        mx_host = str(mx_host.exchange)
    
    mx_host = mx_host.strip().rstrip('.').lower()
    
    cache_key = UnifiedCache.build_key("mx_ip", mx_host)
    cached = await async_cache_get(cache_key)
    if cached is not None:
        return cached  # type: ignore[return-value]
    try:
        loop = asyncio.get_running_loop()
        # timeout: env > ProviderConfig > fallback
        env_to = os.getenv("DNS_TIMEOUT")
        base_timeout = float(env_to) if env_to else getattr(config, "dns_timeout", 5.0)
        addrinfo = await asyncio.wait_for(
            loop.getaddrinfo(
                mx_host,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=0,
                flags=socket.AI_ADDRCONFIG,
            ),
            timeout=base_timeout * 2,
        )
        v4: list[str] = []
        v6: list[str] = []
        for family, _, _, _, sockaddr in addrinfo:
            ip = sockaddr[0]
            if _is_public_ip(ip):
                if family == socket.AF_INET:
                    v4.append(ip)
                elif family == socket.AF_INET6:
                    v6.append(ip)
        prefer4 = os.getenv("PREFER_IPV4")
        prefer4 = prefer4.strip().lower() in ("1", "true", "yes", "on") if prefer4 is not None else getattr(config, "prefer_ipv4", True)
        chosen = (v4[0] if (prefer4 and v4) else (v6[0] if (not prefer4 and v6) else (v4 or v6 or [None])[0]))
        if chosen:
            await async_cache_set(cache_key, chosen, ttl=config.ip_cache_ttl)
        return chosen
    except Exception as e:
        logger.debug(f"DNS resolution failed for {mx_host}: {str(e)}")
        MET_DNS_FAILURES.inc()
        return None

# -----------------------
# WHOIS / ASN (con retries, breaker y timeout)
# -----------------------

def _get_asn_info_blocking(ip: str) -> Optional[Dict[str, Any]]:
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        return {
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description", "") or "",
            "network_name": result.get("network", {}).get("name", "") if isinstance(result.get("network"), dict) else "",
        }
    except Exception as e:
        logger.debug("IPWhois lookup failed for %s: %s", ip, str(e))
        return None

async def _whois_call(ip: str):
    return await asyncio.to_thread(_get_asn_info_blocking, ip)

@asynccontextmanager
async def whois_operation(ip: str):
    if not ip:
        yield None
        return
    if await WHOIS_CB.is_blocked(ip):
        logger.debug(f"WHOIS blocked for {ip} by circuit breaker")
        MET_WHOIS_BLOCKED.inc()
        yield None
        return
    await _ensure_whois_semaphore()
    async with WHOIS_SEMAPHORE:
        try:
            # timeout total por operación WHOIS
            result = await asyncio.wait_for(async_retry(_whois_call, ip, attempts=3, on_retry=lambda e, a: None), timeout=config.whois_timeout)
            yield result
        except asyncio.TimeoutError:
            logger.warning(f"WHOIS timeout for {ip}")
            await WHOIS_CB.record_failure(ip)
            MET_WHOIS_FAILURES.inc()
            yield None
        except Exception as e:
            logger.warning(f"WHOIS error for {ip}: {str(e)}")
            await WHOIS_CB.record_failure(ip)
            MET_WHOIS_FAILURES.inc()
            yield None

async def get_asn_info(ip: str) -> Optional[ASNInfo]:
    if not ip:
        return None
    cache_key = UnifiedCache.build_key("asn", ip)
    cached = await async_cache_get(cache_key)
    if isinstance(cached, dict):
        return ASNInfo.from_dict(cached)
    if isinstance(cached, ASNInfo):
        return cached
    # ignora otros tipos como str

    # asegurar semáforo antes de usar
    await _ensure_whois_semaphore()

    async with whois_operation(ip) as result:
        if result:
            await async_cache_set(cache_key, result, ttl=config.asn_cache_ttl)
            return ASNInfo.from_dict(result)
    return None


# -----------------------
# Verificaciones SPF/DKIM/DMARC
# -----------------------

def _is_mock(obj) -> bool:
    try:
        mod = obj.__class__.__module__
        name = obj.__class__.__name__
        return ("unittest.mock" in mod or mod.startswith("mock")) and "Mock" in name
    except Exception:
        return False

async def check_spf(domain: str) -> str:
    """Búsqueda SPF robusta con fallback. Retorna el record SPF completo o 'no-spf'."""
    name = (domain or "").strip().lower()
    if not name:
        return "no-spf"
    
    try:
        import dns.resolver
        import dns.rdatatype
        
        answers = await asyncio.to_thread(
            dns.resolver.resolve,
            name,
            dns.rdatatype.TXT,
            raise_on_no_answer=False
        )
        
        if answers:
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_str = txt_string.decode('utf-8', errors='ignore').strip()
                    if txt_str.startswith('v=spf1'):
                        logger.debug(f"[SPF] Found for {name}: {txt_str[:80]}...")
                        return txt_str  # ← RETORNA EL RECORD COMPLETO
        
        return "no-spf"
    
    except Exception as e:
        logger.debug(f"SPF check failed for {name}: {str(e)}")
        return "no-spf"


async def check_dkim(domain: str) -> DKIMInfo:
    """DKIM con búsqueda multi-selector mejorada y caché."""
    if not domain:
        return DKIMInfo(status="not_found", record=None, selector=None, key_type=None, key_length=None)
        
    cache_key = UnifiedCache.build_key("dkim", domain)
    cached = await async_cache_get(cache_key)
    
    if cached:
        if isinstance(cached, dict):
            return DKIMInfo(**cached)
        # Si es string u otro tipo, ignorar por seguridad
        
    result = await enhanced_dkim_check(domain)
    
    # Cachear solo si se encontró algo válido o si se quiere cachear también los fallos (opcional)
    # Aquí cacheamos todo para evitar re-lookup inmediato
    if result.status == "valid":
        await async_cache_set(cache_key, asdict(result), ttl=config.mx_cache_ttl)
        
    return result


async def check_dmarc(domain: str) -> str:
    """Búsqueda DMARC robusta. Retorna el record DMARC completo o 'no-dmarc'."""
    d = normalize_domain(domain)
    
    try:
        import dns.resolver
        import dns.rdatatype
        
        qname = f"_dmarc.{d}"
        answers = await asyncio.to_thread(
            dns.resolver.resolve,
            qname,
            dns.rdatatype.TXT,
            raise_on_no_answer=False
        )
        
        if answers:
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_str = txt_string.decode('utf-8', errors='ignore').strip()
                    if txt_str.lower().startswith('v=dmarc1'):
                        logger.debug(f"[DMARC] Found for {d}: {txt_str[:80]}...")
                        return txt_str  # ← RETORNA EL RECORD COMPLETO
        
        return "no-dmarc"
    
    except Exception as e:
        logger.debug(f"DMARC check failed for {d}: {str(e)}")
        return "no-dmarc"


# -----------------------
# Clasificación de proveedor
# -----------------------

class ProviderClassifier:
    def __init__(self, feed_path: Optional[str] = None):
        self.asn_number_map: Dict[int, str] = {
            15169: "gmail",
            8075: "outlook",
            16509: "aws_ses",
        }
        self.provider_patterns: Dict[str, Dict[str, List[str]]] = {
            "gmail": {
                "mx_patterns": [
                    r"(^|\.)gmail-smtp-in\.l\.google\.com$",
                    r"(^|\.)aspmx\.l\.google\.com$",
                    r"(^|\.)google\.com$",
                    r"(^|\.)googlemail\.com$",
                ],
                "asn_patterns": ["google"],
            },
            "outlook": {
                "mx_patterns": [
                    r"(^|\.)mail\.protection\.outlook\.com$",
                    r"(^|\.)protection\.outlook\.com$",
                    r"(^|\.)outlook\.com$",
                    r"(^|\.)office365\.com$",
                ],
                "asn_patterns": ["microsoft"],
            },
            "yahoo": {
                "mx_patterns": [r"yahoodns\.net", r"yahoo\.com", r"yahoodns"],
                "asn_patterns": ["yahoo", "oath"],
            },
            "zoho": {
                "mx_patterns": [r"mx\.zohomail\.com", r"zoho\.com"],
                "asn_patterns": ["zoho"],
            },
            "protonmail": {
                "mx_patterns": [r"protonmail\.ch", r"protonmail\.com"],
                "asn_patterns": ["proton"],
            },
            "aws_ses": {
                "mx_patterns": [r"amazonses\.com", r"amazon\.com"],
                "asn_patterns": ["amazon"],
            },
        }
        self.feed: Dict[str, Any] = {}
        if feed_path:
            try:
                with open(feed_path, "r", encoding="utf-8") as fh:
                    self.feed = json.load(fh)
                asn_map = self.feed.get("asn_map", {})
                for k, v in asn_map.items():
                    try:
                        self.asn_number_map[int(k)] = v
                    except Exception:
                        continue
            except Exception as e:
                logger.debug("Failed to load provider fingerprint feed %s: %s", feed_path, str(e))

    def _asn_to_number(self, asn: Optional[str]) -> Optional[int]:
        if not asn:
            return None
        m = re.search(r"(\d+)", str(asn))
        if m:
            try:
                return int(m.group(1))
            except Exception:
                return None
        return None

    def classify(self, mx: Union[str, Any], asn_info: Optional[ASNInfo]) -> str:
        """
        Classify email provider from MX record or string.
        
        Args:
            mx: MX hostname (string) or MXRecord object with .exchange attribute
            asn_info: Optional ASN information
            
        Returns:
            Provider name (gmail, outlook, yahoo, etc.) or 'generic'/'unknown'
        """
        # Normalizar mx: extraer .exchange si es objeto MXRecord
        if hasattr(mx, 'exchange'):
        # Es un objeto MXRecord - extrae el exchange
            mx_hostname = str(mx.exchange).strip().lower()
        elif isinstance(mx, str):
            mx_hostname = mx.strip().lower()
        else:
            # Fallback para tipos desconocidos
            mx_hostname = str(mx).strip().lower()
        
        if not mx_hostname:
            return "unknown"
        
        # Normalizar a lowercase
        mx_lower = mx_hostname.strip().lower()
        
        # ASN info
        asn_desc = (asn_info.asn_description.lower() if asn_info and asn_info.asn_description else "")
        asn_network = (asn_info.network_name.lower() if asn_info and asn_info.network_name else "")
        asn_num = self._asn_to_number(asn_info.asn) if asn_info and asn_info.asn else None
        
        # Verificar feed primero (si existe)
        if self.feed:
            asn_feed = self.feed.get("asn_map", {})
            if asn_num and str(asn_num) in asn_feed:
                return asn_feed[str(asn_num)]
        
        # Verificar mapa ASN local
        if asn_num and asn_num in self.asn_number_map:
            return self.asn_number_map[asn_num]
        
        # Verificar patrones de proveedores
        for provider, patterns in self.provider_patterns.items():
            # MX patterns
            for pat in patterns.get("mx_patterns", []):
                try:
                    if re.search(pat, mx_lower):
                        return provider
                except re.error:
                    # Si es un regex inválido, try literal match
                    if pat in mx_lower:
                        return provider
            
            # ASN patterns
            for p in patterns.get("asn_patterns", []):
                if p in asn_desc or p in asn_network:
                    return provider
        
        return "generic"


provider_classifier = ProviderClassifier(feed_path=os.getenv("PROVIDER_FINGERPRINTS_JSON"))

# -----------------------
# Reputación y fingerprint
# -----------------------

def generate_fingerprint(mx: str, asn_info: Optional[ASNInfo], spf: str, dkim: DKIMInfo, dmarc: str) -> str:
    components = [
        mx or "NA",
        asn_info.asn if asn_info and asn_info.asn else "NA",
        asn_info.asn_description if asn_info else "NA",
        spf or "no-spf",
        (dkim.status if dkim and dkim.status else "no-dkim"),
        dmarc or "no-dmarc",
        str(dkim.key_length) if dkim and dkim.key_length else "NA",
    ]
    fp = "|".join(str(c) for c in components)
    return hashlib.sha256(fp.encode("utf-8")).hexdigest()

def calculate_initial_reputation(
    provider_name: str,
    spf: str,
    dkim: DKIMInfo,
    dmarc: str
) -> float:
    """
    Calcula reputación 0-1 basada en:
    - Proveedor conocido: 1.0
    - Dominio tiene DKIM: 0.9
    - Dominio tiene SPF+DMARC: 0.8
    - Dominio nuevo/desconocido: 0.5
    - Dominio sin seguridad: 0.3
    """
    
    provider_name_lower = (provider_name or "").lower()
    
    # ✅ TIER 1: Proveedores PREMIUM (siempre 1.0)
    tier1_providers = {
        "gmail", "google", "outlook", "microsoft", 
        "yahoo", "aol", "protonmail", "fastmail"
    }
    
    if provider_name_lower in tier1_providers:
        return 1.0
    
    # ✅ TIER 2: Dominio con excelente seguridad (0.9)
    has_dkim = dkim and dkim.status == "valid"
    has_spf = spf and spf != "no-spf" and spf.startswith("v=spf1")
    has_dmarc = dmarc and dmarc != "no-dmarc" and dmarc.startswith("v=DMARC1")
    
    if has_dkim and has_spf and has_dmarc:
        return 0.9
    
    # ✅ TIER 3: Dominio con SPF+DMARC pero sin DKIM (0.75)
    if has_spf and has_dmarc:
        return 0.75
    
    # ✅ TIER 4: Dominio con solo SPF o DMARC (0.6)
    if has_spf or has_dmarc:
        return 0.6
    
    # ✅ TIER 5: Dominio con DKIM pero sin SPF/DMARC (0.65)
    if has_dkim:
        return 0.65
    
    # ✅ TIER 6: Dominio sin seguridad (0.4)
    if not provider_name_lower:
        return 0.3
    
    # ✅ Neutral: Dominio desconocido (0.5)
    return 0.5

async def update_reputation(redis: Optional[RedisLike], fingerprint: str, success: bool) -> None:
    if not fingerprint:
        return
    rep_key = f"{CACHE_REP}{fingerprint}"
    try:
        current = await async_cache_get(rep_key)
        current_rep = float(current) if current else 0.5
        delta = 0.05 if success else -0.10
        new_rep = min(max(current_rep + delta, 0.0), 1.0)
        await async_cache_set(rep_key, str(new_rep), ttl=7 * 24 * 3600)
    except Exception as e:
        logger.warning("Failed to update reputation in cache/Redis: %s", str(e))


# ========================================
# DISPOSABLE DOMAINS CHECKER
# ========================================
DISPOSABLE_DOMAINS = {
    "tempmail.com", "temp-mail.com", "temp-mails.com",
    "10minutemail.com", "10minutemails.com",
    "mailinator.com", "maildrop.cc",
    "guerrillamail.com", "grr.la",
    "trash-mail.com", "trashmail.de",
    "throwaway.email", "temp.email",
    "mailnesia.com", "yopmail.com",
    "fakeinbox.com", "fakemail.net",
    "tempmail.org", "temporary-mail.net",
    "dispostable.com", "spam4.me",
    "mailsac.com", "maildump.net",
    "mailpoof.com", "sneakemail.com",
    "min.us", "no-spam.ws",
    "tempemails.org", "test.mail.tm",
    "tmail.ws", "truemail.net",
    "tempmail.com",
    "temp-mail.com",
    "temp-mail.org",
}

def is_disposable_email(email: str) -> bool:
    """Detecta si es un email descartable/temporal."""
    if not email or '@' not in email:
        return False
    domain = email.split('@')[-1].lower().strip('.')
    return domain in DISPOSABLE_DOMAINS

# ========================================
# DKIM SELECTOR SCANNING MEJORADO
# ========================================
async def enhanced_dkim_check(domain: str) -> DKIMInfo:
    """Búsqueda DKIM con múltiples selectores y resolvers robustos."""
    import dns.resolver
    import dns.rdatatype
    import dns.exception
    
    d = normalize_domain(domain)
    
    # ✅ SELECTORES ORDENADOS POR PROBABILIDAD
    selectors = [
        # Gmail/Google específico
        "google",
        "default",
        # Outlook/Microsoft
        "selector1", "selector2", "s1", "s2", "s201709", "s202003",
        # Genéricos
        "k1", "k2", "mail", "dkim",
        # Sendgrid, AWS SES
        "amazonses",
        "sendgrid",
    ]
    
    for selector in selectors:
        try:
            qname = f"{selector}._domainkey.{d}"
            logger.debug(f"[DKIM] Trying selector '{selector}' for {d}: {qname}")
            
            # ✅ Usar dns.resolver.resolve (bloqueante en thread)
            answers = await asyncio.to_thread(
                dns.resolver.resolve,
                qname,
                dns.rdatatype.TXT,
                raise_on_no_answer=False
            )
            
            if answers:
                for rdata in answers:
                    for txt_string in rdata.strings:
                        txt_str = txt_string.decode('utf-8', errors='ignore').strip()
                        
                        if 'v=dkim1' in txt_str.lower():
                            # ✅ Encontrado: parsear e informar
                            info = extract_dkim_parts(txt_str)
                            info.selector = selector
                            info.status = "valid"
                            info.record = txt_str  # ← NUEVO: guardar el record completo
                            logger.info(f"[DKIM] Found for {d} with selector '{selector}'")
                            return info
        
        except (dns.exception.DNSException, Exception) as e:
            logger.debug(f"[DKIM] Selector '{selector}' failed: {str(e)[:100]}")
            continue
    
    logger.debug(f"[DKIM] No selectors found for {d}")
    return DKIMInfo(
        status="not_found",
        record=None,
        selector=None,
        key_type=None,
        key_length=None
    )


# ========================================
# SMTP VALIDATION MEJORADO
# ========================================
async def enhanced_smtp_check(email: str, mx_host: Optional[str], timeout: float = 10.0) -> Dict[str, Any]:
    """
    Validación SMTP mejorada con respuesta clara.
    Retorna: {
        "checked": bool,
        "mailbox_exists": bool | None,
        "detail": str,
        "mx_server": str
    }
    """
    if not mx_host:
        return {
            "checked": False,
            "mailbox_exists": None,
            "detail": "No MX server available",
            "mx_server": None
        }
    
    try:
        # Intenta verificar con VRFY (método simple)
        exists, detail = await asyncio.wait_for(
            check_smtp_mailbox_safe(email, dorcpt=True),
            timeout=timeout
        )
        
        return {
            "checked": True,
            "mailbox_exists": exists,
            "detail": detail,
            "mx_server": mx_host
        }
    except asyncio.TimeoutError:
        return {
            "checked": False,
            "mailbox_exists": None,
            "detail": "SMTP check timed out",
            "mx_server": mx_host
        }
    except Exception as e:
        logger.debug(f"SMTP check failed for {email}: {e}")
        return {
            "checked": False,
            "mailbox_exists": None,
            "detail": f"SMTP check failed: {str(e)[:50]}",
            "mx_server": mx_host
        }


# -----------------------
# Función principal
# -----------------------

async def analyze_email_provider(
    email: str,
    redis: Optional[RedisLike] = None,
    timeout: float = 5.0  # ✅ TIMEOUT EXPLÍCITO
) -> ProviderAnalysis:
    """
    ✅ Pipeline completo con timeout robusto y fallback inteligente.
    
    Pasos:
    1) Extraer dominio y resolver MX records
    2) Obtener IP y ASN del MX primario
    3) Verificar SPF/DKIM/DMARC en paralelo (con timeout)
    4) Clasificar proveedor y calcular reputación
    5) Guardar en caché (Redis o in-memory)
    
    Args:
        email: Email a analizar (extrae dominio)
        redis: Cliente Redis opcional para caché distribuida
        timeout: Timeout en segundos para operación completa (default 5s)
    
    Returns:
        ProviderAnalysis con todos los campos populados
    """
    
    if redis is not None:
        try:
            set_redis_client(redis)
        except Exception:
            pass
    
    # Extraer y normalizar dominio
    domain = normalize_domain(email.split("@")[-1]) if "@" in email else normalize_domain(email)
    
    try:
        # ✅ TIMEOUT GLOBAL para todo el análisis
        result = await asyncio.wait_for(
            _analyze_provider_internal(email, domain),
            timeout=timeout
        )
        return result
        
    except asyncio.TimeoutError:
        logger.warning(f"Provider analysis timeout for {email} after {timeout}s")
        
        # ✅ FALLBACK INTELIGENTE: Retorna análisis básico válido
        return ProviderAnalysis(
            domain=domain,
            primary_mx=None,
            ip=None,
            asn_info=None,
            dns_auth=DNSAuthResults(
                spf="no-spf",
                dkim=DKIMInfo(status="not_found", record=None, selector=None, 
                             key_type=None, key_length=None),
                dmarc="no-dmarc"
            ),
            provider="generic",
            fingerprint="",
            reputation=0.5,  # ✅ Reputación neutra en fallback
            cached=False,
            error="timeout"
        )
    
    except Exception as e:
        logger.error(f"Provider analysis failed for {email}: {str(e)}", exc_info=True)
        
        return ProviderAnalysis(
            domain=domain or "unknown",
            primary_mx=None,
            ip=None,
            asn_info=None,
            dns_auth=DNSAuthResults(
                spf="error",
                dkim=DKIMInfo(status="error", record=None, selector=None,
                             key_type=None, key_length=None),
                dmarc="error"
            ),
            provider="unknown",
            fingerprint="",
            reputation=0.0,
            cached=False,
            error=str(e)[:200]
        )


async def _analyze_provider_internal(email: str, domain: str) -> ProviderAnalysis:
    """
    ✅ Lógica interna del análisis (sin timeout principal, usa timeouts específicos).
    """
    
    try:
        # PASO 1: Obtener MX records
        mx_records = await asyncio.wait_for(get_mx_records(domain), timeout=2.0)
        
        if not mx_records:
            return ProviderAnalysis(
                domain=domain,
                primary_mx=None,
                ip=None,
                asn_info=None,
                dns_auth=DNSAuthResults(
                    spf="no-spf",
                    dkim=DKIMInfo(status="not_found", record=None, selector=None,
                                 key_type=None, key_length=None),
                    dmarc="no-dmarc"
                ),
                provider="unknown",
                fingerprint="",
                reputation=0.1,
                cached=False,
                error="No MX records found"
            )
        
        # Normalizar primary_mx a string
        primary_mx = mx_records[0]
        if hasattr(primary_mx, 'exchange'):
            primary_mx = str(primary_mx.exchange).strip().rstrip('.').lower()
        else:
            primary_mx = str(primary_mx).strip().rstrip('.').lower() if primary_mx else None
        
        if not primary_mx:
            return ProviderAnalysis(
                domain=domain,
                primary_mx=None,
                ip=None,
                asn_info=None,
                dns_auth=DNSAuthResults(
                    spf="no-spf",
                    dkim=DKIMInfo(status="not_found", record=None, selector=None,
                                 key_type=None, key_length=None),
                    dmarc="no-dmarc"
                ),
                provider="unknown",
                fingerprint="",
                reputation=0.1,
                cached=False,
                error="No valid MX record"
            )
        
        # PASO 2: Resolver IP y obtener ASN
        ip = await asyncio.wait_for(resolve_mx_to_ip(primary_mx), timeout=2.0)
        asn_info = None
        
        if ip:
            try:
                asn_info = await asyncio.wait_for(get_asn_info(ip), timeout=2.0)
            except asyncio.TimeoutError:
                logger.debug(f"ASN lookup timeout for {ip}")
        
        # PASO 3: Obtener DNS records en paralelo (SPF/DKIM/DMARC) con timeout individual
        try:
            if hasattr(asyncio, "TaskGroup"):
                async with asyncio.TaskGroup() as tg:  # type: ignore[attr-defined]
                    spf_task = tg.create_task(asyncio.wait_for(check_spf(domain), timeout=1.5))
                    dkim_task = tg.create_task(asyncio.wait_for(check_dkim(domain), timeout=1.5))
                    dmarc_task = tg.create_task(asyncio.wait_for(check_dmarc(domain), timeout=1.5))
                    
                spf = spf_task.result() if not spf_task.cancelled() else "no-spf"
                dkim_info = dkim_task.result() if not dkim_task.cancelled() else DKIMInfo(...)
                dmarc = dmarc_task.result() if not dmarc_task.cancelled() else "no-dmarc"
            else:
                # Python 3.10 o anterior
                spf, dkim_info, dmarc = await asyncio.gather(
                    asyncio.wait_for(check_spf(domain), timeout=1.5),
                    asyncio.wait_for(check_dkim(domain), timeout=1.5),
                    asyncio.wait_for(check_dmarc(domain), timeout=1.5),
                    return_exceptions=True  # ← CRÍTICO
                )
        
        except Exception as e:
            logger.debug(f"DNS checks failed: {e}")
            spf = "no-spf"
            dkim_info = DKIMInfo(status="not_found", record=None, selector=None,
                                key_type=None, key_length=None)
            dmarc = "no-dmarc"
        
        # PASO 4: Clasificar y calcular reputación
        provider = provider_classifier.classify(primary_mx, asn_info)
        fingerprint = generate_fingerprint(primary_mx, asn_info, spf, dkim_info, dmarc)
        reputation = calculate_initial_reputation(provider, spf, dkim_info, dmarc)
        
        # Intentar obtener reputación cacheada
        cached_rep = None
        if REDIS_CLIENT and fingerprint:
            try:
                val = await asyncio.wait_for(
                    async_cache_get(f"{CACHE_REP}{fingerprint}"),
                    timeout=0.5
                )
                if val is not None:
                    cached_rep = float(val)
            except Exception as e:
                logger.debug(f"Failed to get cached reputation: {e}")
        
        if cached_rep is not None:
            reputation = cached_rep
        else:
            if fingerprint:
                try:
                    await asyncio.wait_for(
                        async_cache_set(
                            f"{CACHE_REP}{fingerprint}",
                            reputation,
                            ttl=7 * 24 * 3600
                        ),
                        timeout=0.5
                    )
                except Exception as e:
                    logger.debug(f"Failed to cache reputation: {e}")
        

        # ✅ CALCULAR reputation ANTES de usarla
        try:
            reputation = calculate_initial_reputation(
                provider_name=provider,
                spf=spf,
                dkim=dkim_info,
                dmarc=dmarc
            )
        except Exception as e:
            logger.warning(f"Failed to calculate reputation: {e}")
            reputation = 0.5  # Valor por defecto si falla

        # ✅ AHORA sí retornar con reputation
        return ProviderAnalysis(
            domain=domain,
            primary_mx=primary_mx,
            ip=ip,
            asn_info=asn_info,
            dns_auth=DNSAuthResults(spf=spf, dkim=dkim_info, dmarc=dmarc),
            provider=provider,
            fingerprint=fingerprint,
            reputation=reputation,  # ← Ahora existe
            cached=False,
            error=None
        )
 
    except Exception as e:
        logger.error(f"Internal analysis failed: {e}", exc_info=True)
        raise

# -----------------------
# Utilidades
# -----------------------

def analyze_email_provider_sync(email: str, redis: Optional[RedisLike] = None) -> ProviderAnalysis:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(analyze_email_provider(email, redis))
    else:
        raise RuntimeError("Existing running event loop detected. Use 'await analyze_email_provider(...)' in async contexts.")

async def get_provider_cache_stats() -> Dict[str, Any]:
    if REDIS_CLIENT is not None:
        try:
            # Contar con scan_iter para no bloquear
            count = 0
            async for _ in REDIS_CLIENT.scan_iter(match="*"):
                count += 1
            return {
                "redis_key_count": count,
                "mx_cache": MX_CACHE.stats(),
                "mx_ip_cache": MX_IP_CACHE.stats(),
                "asn_cache": ASN_CACHE.stats(),
                "general_cache": GENERAL_CACHE.stats(),
            }
        except Exception as e:
            logger.debug("Redis stats failed: %s", str(e))
    return {
        "mx_cache": MX_CACHE.stats(),
        "mx_ip_cache": MX_IP_CACHE.stats(),
        "asn_cache": ASN_CACHE.stats(),
        "general_cache": GENERAL_CACHE.stats(),
    }

async def clear_caches() -> None:
    await async_cache_clear()


# ==================== TYPO DETECTION ====================

import difflib
from typing import Optional, Tuple

COMMON_DOMAINS = {
    # Gmail variants
    "gmail.com": ["gmai.com", "gmial.com", "gmai1.com", "gmil.com"],
    "googlemail.com": ["googlemial.com", "gogglemail.com"],
    
    # Outlook/Microsoft
    "outlook.com": ["outlok.com", "outloo.com", "outlook.co", "outlok.co"],
    "hotmail.com": ["hotmai.com", "hotmial.com", "hotmal.com", "hotmil.com"],
    "microsoft.com": ["microsft.com", "microsot.com"],
    
    # Yahoo
    "yahoo.com": ["yaho.com", "yahooo.com", "yaho.co"],
    
    # Empresa comunes
    "company.com": ["compnay.com", "cmpany.com", "copany.com"],
    "business.com": ["buisness.com", "bussiness.com"],
    
    # Genéricos
    "example.com": ["exmple.com", "exampl.com", "exaple.com"],
    "test.com": ["tes.com", "tst.com"],
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calcula distancia de Levenshtein entre dos strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # j+1 instead of j since previous_row and current_row are one character longer than s2
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def check_typo_suggestion(email: str) -> Optional[Tuple[str, float]]:
    """
    Sugiere dominio si detecta typo.
    Retorna (suggested_email, confidence) o None.
    """
    if "@" not in email:
        return None
    
    local, domain = email.rsplit("@", 1)
    domain_lower = domain.lower()
    
    best_match = None
    best_distance = 2  # Máximo 2 caracteres de diferencia
    best_confidence = 0.0
    
    # Buscar en diccionario de dominios comunes
    for correct_domain, typo_list in COMMON_DOMAINS.items():
        for typo in typo_list:
            if typo_lower := typo.lower():
                distance = levenshtein_distance(domain_lower, typo_lower)
                
                # Si el dominio introducido es el typo conocido
                if domain_lower == typo_lower:
                    # Confianza: basada en cuán similar es
                    similarity = 1.0 - (distance / max(len(domain_lower), len(typo_lower)))
                    confidence = similarity * 100
                    
                    if distance <= best_distance and confidence > best_confidence:
                        best_match = f"{local}@{correct_domain}"
                        best_distance = distance
                        best_confidence = confidence
        
        # También comparar contra el dominio correcto directamente
        distance = levenshtein_distance(domain_lower, correct_domain.lower())
        
        if distance > 0 and distance <= 2:  # 1-2 caracteres de diferencia
            similarity = 1.0 - (distance / max(len(domain_lower), len(correct_domain)))
            confidence = similarity * 100
            
            if confidence > best_confidence:
                best_match = f"{local}@{correct_domain}"
                best_distance = distance
                best_confidence = confidence
    
    if best_match and best_confidence >= 80:  # Mínimo 80% confianza
        return (best_match, best_confidence / 100.0)
    
    return None


# ==================== HAVEIBEENPWNED INTEGRATION ====================

import hashlib
import aiohttp
from typing import Optional, Dict

class HaveIBeenPwnedChecker:
    """
    Integración con HaveIBeenPwned API v3 (gratuita + respetuosa).
    
    Documentación: https://haveibeenpwned.com/API/v3
    Rate limit: 1 request/1.5 segundos
    """
    
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    BREACHES_ENDPOINT = f"{BASE_URL}/breachedaccount"
    TIMEOUT = 10  # segundos
    CACHE_TTL = 7 * 24 * 3600  # 7 días
    
    # User-Agent requerido por HIBP
    HEADERS = {
        "User-Agent": "EmailValidationAPI/1.0 (+https://yourapi.com)"
    }
    
    @staticmethod
    async def check_email_in_breach(
        email: str,
        redis: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Consulta si un email está en algún breach conocido."""
        import httpx
        
        email_lower = email.lower().strip()
        logger.info(f"[HIBP] ✅ Starting HIBP check for {mask_email(email_lower)}")
        
        # ✅ Intentar obtener de Redis
        if redis:
            cache_key = UnifiedCache.build_key("hibp", email_lower)
            try:
                cached = await asyncio.wait_for(
                    redis.get(cache_key),
                    timeout=2
                )
                if cached:
                    logger.info(f"[HIBP] Cache HIT for {mask_email(email_lower)}")
                    data = json.loads(cached)
                    data["cached"] = True
                    return data
            except Exception as e:
                logger.warning(f"[HIBP] Cache error: {e}")
        
        try:
            logger.info(f"[HIBP] Making async HTTP request to HIBP API...")
            
            # ✅ Pure async httpx client (no thread blocking)
            headers = {
                "User-Agent": "EmailValidationAPI/1.0 (+https://yourapi.com)"
            }
            url = "https://haveibeenpwned.com/api/v3/breachedaccount"
            
            # Use async httpx client with timeout
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    url,
                    params={"account": email_lower, "truncateResponse": False},
                    headers=headers
                )
            
            logger.info(f"[HIBP] Response status: {response.status_code}")
            
            if response.status_code == 200:
                logger.info(f"[HIBP] Email IN BREACH")
                breaches_raw = response.json()
                breaches = [
                    {
                        "name": b.get("Name", "Unknown"),
                        "date": b.get("BreachDate", "Unknown"),
                    }
                    for b in breaches_raw
                ]
                result = {
                    "in_breach": True,
                    "breach_count": len(breaches),
                    "breaches": breaches,
                    "cached": False,
                    "checked_at": datetime.utcnow().isoformat() + "Z",
                    "risk_level": "high" if len(breaches) > 2 else "medium"
                }
            
            elif response.status_code == 404:
                logger.info(f"[HIBP] Email NOT in breach")  # ← NUEVO
                result = {
                    "in_breach": False,
                    "breach_count": 0,
                    "breaches": [],
                    "cached": False,
                    "checked_at": datetime.utcnow().isoformat() + "Z",
                    "risk_level": "low"
                }
            
            else:
                logger.warning(f"[HIBP] Unexpected status: {response.status_code}")  # ← NUEVO
                result = {
                    "in_breach": None,
                    "breach_count": None,
                    "breaches": [],
                    "cached": False,
                    "checked_at": datetime.utcnow().isoformat() + "Z",
                    "error": f"API returned {response.status_code}"
                }
            
            # ✅ Cachear
            if redis:
                try:
                    await asyncio.wait_for(
                        redis.setex(
                            f"hibp:{email_lower}",
                            7 * 24 * 3600,
                            json.dumps(result)
                        ),
                        timeout=2
                    )
                    logger.info(f"[HIBP] Result cached")  # ← NUEVO
                except Exception as e:
                    logger.warning(f"[HIBP] Cache save failed: {e}")
            
            logger.info(f"[HIBP] ✅ Result: {result}")  # ← NUEVO
            return result
        
        except Exception as e:
            logger.error(f"[HIBP] Exception: {str(e)[:200]}", exc_info=True)  # ← NUEVO
            return {
                "in_breach": None,
                "breach_count": None,
                "breaches": [],
                "cached": False,
                "checked_at": datetime.utcnow().isoformat() + "Z",
                "error": str(e)[:100]
            }

# ==================== ROLE EMAIL DETECTION ====================

ROLE_EMAILS = {
    # Administrativas
    "admin", "administrator", "root", "superuser",
    
    # Soporte/Servicio
    "support", "help", "helpdesk", "support-team",
    
    # Ventas
    "sales", "sales-team", "sales@", "business",
    
    # Marketing
    "marketing", "mktg", "market",
    
    # Desarrolladores
    "dev", "developer", "development", "engineering", "engineers",
    
    # Infraestructura
    "ops", "operations", "devops", "sysadmin", "infrastructure",
    
    # Notificaciones automáticas
    "noreply", "no-reply", "donotreply", "do-not-reply", "notif", "notifications",
    "alert", "alerts", "info", "info@",
    
    # Correos de sistema
    "postmaster", "abuse", "security", "compliance", "legal",
    "billing", "billing-team", "invoices", "payments",
    
    # Buzones genéricos
    "contact", "hello", "team", "office", "inbox",
    "mail", "webmaster", "hostmaster",
    
    # Pruebas/Desarrollo
    "test", "testing", "qa", "demo", "example", "sample",
    
    # Redes sociales / Bots
    "bot", "noreply", "automated", "system",
    
    # Recursos Humanos
    "hr", "human-resources", "recruitment", "careers", "jobs",
    
    # Finanzas
    "finance", "accounting", "accounts", "treasurer",
    
    # Servicio al cliente
    "customer", "customers", "client", "clients",
}

def detect_role_email(email: str) -> Dict[str, Any]:
    """
    Detecta si un email es de rol/grupo (no personal).
    
    Retorna:
    {
        "is_role_email": bool,
        "role_type": str | None,  # "admin", "support", "noreply", etc
        "deliverability_risk": float,  # 0-1
        "confidence": float  # 0-1
    }
    """
    if "@" not in email:
        return {
            "is_role_email": False,
            "role_type": None,
            "deliverability_risk": 0.0,
            "confidence": 1.0
        }
    
    local_part = email.split("@")[0].lower().strip()
    
    # ✅ Búsqueda exacta
    if local_part in ROLE_EMAILS:
        return {
            "is_role_email": True,
            "role_type": local_part,
            "deliverability_risk": 0.3,  # Riesgo de bouncing
            "confidence": 1.0
        }
    
    # ✅ Búsqueda parcial (e.g., "support-team", "sales_group")
    for role in ROLE_EMAILS:
        if role in local_part:
            # Calcular confianza basada en similitud
            similarity = len(role) / len(local_part)
            
            if similarity > 0.6:  # Al menos 60% del email es el rol
                return {
                    "is_role_email": True,
                    "role_type": role,
                    "deliverability_risk": 0.25,
                    "confidence": similarity
                }
    
    # ✅ Patrones comunes
    patterns = [
        (r"^info[_\-.]?", "info"),
        (r"^admin[_\-.]?", "admin"),
        (r"^support[_\-.]?", "support"),
        (r"^contact[_\-.]?", "contact"),
        (r"^hello[_\-.]?", "hello"),
        (r"^no[_\-]?reply", "noreply"),
    ]
    
    import re
    for pattern, role_type in patterns:
        if re.match(pattern, local_part):
            return {
                "is_role_email": True,
                "role_type": role_type,
                "deliverability_risk": 0.25,
                "confidence": 0.85
            }
    
    # No es email de rol
    return {
        "is_role_email": False,
        "role_type": None,
        "deliverability_risk": 0.0,
        "confidence": 1.0
    }


# ============================================================================
# SPAM TRAP DETECTION - Sistema de detección de honeypots y dominios tóxicos
# ============================================================================

# ============================================================================
# SPAM TRAP DETECTION - Sistema de detección de honeypots y dominios tóxicos
# ============================================================================

class SpamTrapDetector:
    """
    Detecta spam traps (honeypots), dominios de abuso y emails tóxicos.
    
    Tipos de spam traps detectados:
    - Pristine: Emails falsos creados solo para capturar spammers
    - Recycled: Emails abandonados convertidos en traps
    - Typo: Variaciones comunes de dominios populares (gmial.com, etc.)
    - Role-based abuse: abuse@, spam@, postmaster@ en dominios sospechosos
    """
    
    # Dominios conocidos de spam traps (pristine y recycled)
    KNOWN_SPAM_TRAP_DOMAINS = {
        # Honeypots conocidos
        "spamtrap.com", "honeypot.com", "spam-trap.net", "spamcop.net",
        "spamhaus.org", "example.invalid", "blackhole.email",
        "trap.email", "honeypot.email", "spamtrap.email",
        
        # Dominios de reciclaje conocidos
        "recycled-email.com", "abandoned-mail.net", "old-email.org",
        "inactive-mail.com", "expired-email.net",
        
        # Dominios de test/abuse
        "abuse-mailbox.com", "spam-test.net", "honeypot-test.org",
        "email-trap.com", "spam-detector.net", "trap-address.com",
        
        # Servicios específicos de honeypot
        "project-honeypot.org", "stopforumspam.com",
    }
    
    # Typos comunes de dominios populares (typo traps)
    TYPO_TRAP_DOMAINS = {
        # Gmail typos
        "gmial.com", "gmai.com", "gmali.com", "gmaol.com", 
        "gnail.com", "gmil.com", "gmal.com", "gimail.com",
        "gmeil.com", "gmsil.com", "gmailc.om", "gmaill.com",
        
        # Hotmail typos
        "hotmial.com", "hotmali.com", "hotmai.com", "hotmal.com",
        "hotmil.com", "hotmaill.com", "hotmailc.om", "homtail.com",
        
        # Yahoo typos
        "yahooo.com", "yaho.com", "yhoo.com", "yahhoo.com",
        "yahho.com", "yhaoo.com", "yaoo.com", "yahooc.om",
        
        # Outlook typos
        "outlok.com", "outllook.com", "outlook.co", "outlok.co",
        "outloo.com", "outlookc.om",
        
        # AOL typos
        "aol.co", "aoll.com", "al.com", "aol.comm",
        
        # Otros populares
        "iclod.com", "icloud.co", "protonmial.com", "prtonmail.com",
    }
    
    # Patrones de role-based clasificados por riesgo
    HIGH_RISK_ROLE_PATTERNS = {
        "abuse", "spam", "spamtrap", "honeypot", "blackhole", 
        "devnull", "nobody", "void", "null", "trap", "bounce"
    }
    
    MEDIUM_RISK_ROLE_PATTERNS = {
        "noreply", "no-reply", "donotreply", "mailer-daemon",
        "postmaster", "hostmaster", "webmaster"
    }
    
    LOW_RISK_ROLE_PATTERNS = {
        "test", "demo", "info", "contact", "support", 
        "hello", "sales", "marketing", "admin"
    }
    
    # Whitelist de proveedores legítimos
    LEGITIMATE_PROVIDERS = {
        # Proveedores grandes de email
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.es", 
        "yahoo.co.uk", "hotmail.com", "outlook.com", "live.com",
        "msn.com", "icloud.com", "me.com", "mac.com",
        "protonmail.com", "proton.me", "aol.com", "zoho.com",
        "mail.com", "gmx.com", "yandex.com", "qq.com",
        
        # Proveedores empresariales conocidos
        "microsoft.com", "apple.com", "google.com", "amazon.com",
        "salesforce.com", "oracle.com", "ibm.com",
        
        # ← AÑADIR ESTOS:
        "github.com", "gitlab.com", "bitbucket.org",  # Plataformas dev
        "linkedin.com", "facebook.com", "twitter.com", "x.com",  # Social media
        "stripe.com", "paypal.com", "square.com",  # Payment processors
        "slack.com", "discord.com", "zoom.us",  # Communication
        "shopify.com", "wix.com", "squarespace.com",  # Ecommerce
        "dropbox.com", "box.com", "onedrive.com",  # Storage
        "atlassian.com", "jira.com", "confluence.com",  # Enterprise tools
        "hubspot.com", "mailchimp.com", "sendgrid.com",  # Marketing
    }

    
    # Cache en memoria (atributos de clase)
    _cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
    _cache_lock = threading.Lock()
    _cache_ttl = 3600  # 1 hora
    
    @classmethod
    async def is_spam_trap(cls, email: str) -> Dict[str, Any]:
        """
        Detecta si un email es un spam trap con scoring contextual.
        """
        email_lower = email.lower().strip()
        
        # Verificar cache
        cached = cls._get_from_cache(email_lower)
        if cached:
            logger.debug(f"Spam trap check cache hit for {email_lower}")
            return cached
        
        # Extraer dominio y local part
        try:
            local_part, domain = email_lower.rsplit("@", 1)
        except ValueError:
            result = {
                "is_spam_trap": False,
                "confidence": 0.0,
                "trap_type": "unknown",
                "source": "invalid_format",
                "details": "Invalid email format"
            }
            cls._save_to_cache(email_lower, result)
            return result
        
        # 1. Verificar dominios conocidos de spam traps
        if domain in cls.KNOWN_SPAM_TRAP_DOMAINS:
            result = {
                "is_spam_trap": True,
                "confidence": 1.0,
                "trap_type": "pristine" if "honeypot" in domain or "trap" in domain else "recycled",
                "source": "internal_list",
                "details": f"Domain {domain} is a known spam trap"
            }
            cls._save_to_cache(email_lower, result)
            logger.warning(f"Spam trap detected (known domain): {email_lower}")
            return result
        
        # 2. Verificar typo traps
        if domain in cls.TYPO_TRAP_DOMAINS:
            result = {
                "is_spam_trap": True,
                "confidence": 0.9,
                "trap_type": "typo",
                "source": "typo_list",
                "details": f"Domain {domain} is a common typo trap"
            }
            cls._save_to_cache(email_lower, result)
            logger.warning(f"Typo trap detected: {email_lower}")
            return result
        
        # 3. Verificar role-based patterns con scoring contextual
        is_legitimate_provider = domain in cls.LEGITIMATE_PROVIDERS
        is_suspicious_domain = cls._is_suspicious_domain(domain)
        
        risk_level = None
        matched_pattern = None
        
        for pattern in cls.HIGH_RISK_ROLE_PATTERNS:
            if pattern in local_part:
                risk_level = "high"
                matched_pattern = pattern
                break
        
        if not risk_level:
            for pattern in cls.MEDIUM_RISK_ROLE_PATTERNS:
                if pattern in local_part:
                    risk_level = "medium"
                    matched_pattern = pattern
                    break
        
        if not risk_level:
            for pattern in cls.LOW_RISK_ROLE_PATTERNS:
                if pattern in local_part:
                    risk_level = "low"
                    matched_pattern = pattern
                    break
        
        if risk_level:
            confidence, is_trap = cls._calculate_role_pattern_score(
                risk_level, 
                is_legitimate_provider, 
                is_suspicious_domain
            )
            
            result = {
                "is_spam_trap": is_trap,
                "confidence": confidence,
                "trap_type": "role_abuse" if is_trap else "role_based",
                "source": "role_pattern",
                "details": (
                    f"Role-based pattern '{matched_pattern}' detected "
                    f"(risk: {risk_level}, provider: "
                    f"{'legitimate' if is_legitimate_provider else 'unknown'})"
                )
            }
            cls._save_to_cache(email_lower, result)
            
            if is_trap:
                logger.warning(
                    f"Role-based trap detected: {email_lower} | "
                    f"Pattern: {matched_pattern} | Confidence: {confidence}"
                )
            
            return result
        
        # 4. Verificar patrones sospechosos en el dominio
        suspicious_score = cls._calculate_domain_suspicion(domain)
        
        if suspicious_score >= 0.7:
            result = {
                "is_spam_trap": True,
                "confidence": suspicious_score,
                "trap_type": "suspicious_domain",
                "source": "pattern_match",
                "details": f"Domain {domain} shows suspicious patterns"
            }
            cls._save_to_cache(email_lower, result)
            logger.warning(f"Suspicious domain detected: {email_lower} (score: {suspicious_score})")
            return result
        
        # No es spam trap
        result = {
            "is_spam_trap": False,
            "confidence": 0.0,
            "trap_type": "unknown",
            "source": "no_match",
            "details": "No spam trap indicators found"
        }
        cls._save_to_cache(email_lower, result)
        return result
    
    @classmethod
    def _calculate_role_pattern_score(
        cls, 
        risk_level: str, 
        is_legitimate_provider: bool, 
        is_suspicious_domain: bool
    ) -> Tuple[float, bool]:
        """Calcula el score de confianza y si debe bloquearse según el contexto."""
        base_scores = {
            "high": 0.95,
            "medium": 0.75,
            "low": 0.50,
        }
        
        confidence = base_scores.get(risk_level, 0.5)
        
        if is_legitimate_provider:
            if risk_level == "high":
                confidence = 0.85
            elif risk_level == "medium":
                confidence = 0.50
            else:
                confidence = 0.30
        elif is_suspicious_domain:
            if risk_level == "high":
                confidence = 1.0
            elif risk_level == "medium":
                confidence = 0.90
            else:
                confidence = 0.75
        
        is_trap = confidence > 0.7
        return confidence, is_trap
    
    @classmethod
    def _is_suspicious_domain(cls, domain: str) -> bool:
        """Verifica si un dominio es sospechoso."""
        generic_tlds = {".test", ".invalid", ".localhost", ".example", ".local"}
        if any(domain.endswith(tld) for tld in generic_tlds):
            return True
        
        suspicious_keywords = [
            "trap", "spam", "abuse", "honeypot", "blackhole", 
            "test", "fake", "temp", "disposable", "throwaway"
        ]
        if any(keyword in domain for keyword in suspicious_keywords):
            return True
        
        return False
    
    @classmethod
    def _calculate_domain_suspicion(cls, domain: str) -> float:
        """Calcula un score de sospecha para un dominio."""
        score = 0.0
        
        suspicious_keywords = ["trap", "spam", "abuse", "honeypot", "fake", "test", "null", "blackhole"]
        for keyword in suspicious_keywords:
            if keyword in domain:
                score += 0.3
        
        if len(domain) < 5:
            score += 0.2
        elif len(domain) > 50:
            score += 0.1
        
        if "--" in domain or "---" in domain:
            score += 0.2
        
        digit_count = sum(c.isdigit() for c in domain)
        if digit_count > len(domain) * 0.5:
            score += 0.2
        
        return min(1.0, score)
    
    @classmethod
    def _get_from_cache(cls, email: str) -> Optional[Dict[str, Any]]:
        """Obtiene resultado del cache si existe y no ha expirado."""
        with cls._cache_lock:
            if email in cls._cache:
                cached_data, timestamp = cls._cache[email]
                if time.time() - timestamp < cls._cache_ttl:
                    return cached_data
                else:
                    del cls._cache[email]
        return None
    
    @classmethod
    def _save_to_cache(cls, email: str, result: Dict[str, Any]) -> None:
        """Guarda resultado en cache."""
        with cls._cache_lock:
            cls._cache[email] = (result, time.time())
            
            # Limpieza simple
            if len(cls._cache) > 10000:
                now = time.time()
                expired = [k for k, (_, ts) in cls._cache.items() if now - ts >= cls._cache_ttl]
                for k in expired:
                    del cls._cache[k]


# ====================================================================================
# UNIFIED RISK SCORING SYSTEM
# ====================================================================================

from typing import Literal
from dataclasses import dataclass

RiskLevel = Literal['low', 'medium', 'high', 'critical']

@dataclass
class RiskAssessment:
    """Unified risk assessment result."""
    score: int  # 0-100
    level: RiskLevel
    factors: Dict[str, int]
    explanation: str
    confidence: float  # 0.0-1.0


class RiskScorer:
    """
    Unified risk scoring system for email validation.
    
    Aggregates multiple validation factors into single 0-100 risk score.
    Higher score = higher risk.
    
    Risk Levels:
    - 0-24: low (safe to send)
    - 25-49: medium (caution)
    - 50-74: high (avoid unless confident)
    - 75-100: critical (do not send)
    """
    
    WEIGHT_SPAM_TRAP = 40
    WEIGHT_DISPOSABLE = 35
    WEIGHT_SMTP_FAILED = 30
    WEIGHT_BREACH = 25
    WEIGHT_INVALID_SYNTAX = 20
    WEIGHT_ROLE_BASED = 15
    WEIGHT_CATCH_ALL = 12
    WEIGHT_TOXIC_DOMAIN = 30
    
    @classmethod
    def calculate_risk(
        cls,
        validation_result: Dict[str, Any],
        spam_trap_result: Optional[Dict[str, Any]] = None,
        breach_result: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        """Calculate unified risk score from validation results."""
        score = 0
        factors: Dict[str, int] = {}
        confidence_values: List[float] = []
        
        # 1. Spam trap (highest priority)
        if spam_trap_result and spam_trap_result.get('is_spam_trap'):
            trap_confidence = spam_trap_result.get('confidence', 1.0)
            points = int(cls.WEIGHT_SPAM_TRAP * trap_confidence)
            factors['spam_trap'] = points
            score += points
            confidence_values.append(trap_confidence)
        
        # 2. Invalid syntax
        if not validation_result.get('syntax_valid', True):
            factors['invalid_syntax'] = cls.WEIGHT_INVALID_SYNTAX
            score += cls.WEIGHT_INVALID_SYNTAX
            confidence_values.append(1.0)
        
        # 3. SMTP check failed
        if not validation_result.get('smtp_checked', True):
            factors['smtp_failed'] = cls.WEIGHT_SMTP_FAILED
            score += cls.WEIGHT_SMTP_FAILED
            confidence_values.append(0.85)
        
        # 4. Disposable email
        if validation_result.get('disposable', False):
            factors['disposable'] = cls.WEIGHT_DISPOSABLE
            score += cls.WEIGHT_DISPOSABLE
            confidence_values.append(0.95)
        
        # 5. Data breach
        if breach_result:
            is_breached = (
                breach_result.get('breached', False) or 
                breach_result.get('is_breached', False) or
                (breach_result.get('breach_count', 0) > 0)
            )
            if is_breached:
                factors['data_breach'] = cls.WEIGHT_BREACH
                score += cls.WEIGHT_BREACH
                confidence_values.append(1.0)
        
        # 6. Role-based email
        if validation_result.get('role_based', False):
            factors['role_based'] = cls.WEIGHT_ROLE_BASED
            score += cls.WEIGHT_ROLE_BASED
            confidence_values.append(0.9)
        
        # 7. Catch-all domain
        if validation_result.get('catch_all', False):
            factors['catch_all'] = cls.WEIGHT_CATCH_ALL
            score += cls.WEIGHT_CATCH_ALL
            confidence_values.append(0.7)
        
        # 8. Toxic/abuse domain
        if validation_result.get('toxic_domain', False):
            factors['toxic_domain'] = cls.WEIGHT_TOXIC_DOMAIN
            score += cls.WEIGHT_TOXIC_DOMAIN
            confidence_values.append(0.85)
        
        # Cap at 100
        score = min(100, score)
        
        # Overall confidence
        overall_confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.5
        
        # Determine level
        if score >= 75:
            level: RiskLevel = 'critical'
            explanation = "Critical risk. Do not send. High probability of bounce or spam complaint."
        elif score >= 50:
            level = 'high'
            explanation = "High risk. Avoid unless verified. Significant delivery issues likely."
        elif score >= 25:
            level = 'medium'
            explanation = "Moderate risk. Use caution and monitor engagement metrics."
        else:
            level = 'low'
            explanation = "Low risk. Safe to send with normal precautions."
        
        if factors:
            factor_details = ", ".join([f"{k}(+{v})" for k, v in factors.items()])
            explanation += f" Factors: {factor_details}."
        
        return RiskAssessment(
            score=score,
            level=level,
            factors=factors,
            explanation=explanation,
            confidence=overall_confidence
        )


# -----------------------
# Ejemplo
# -----------------------

async def example_usage():
    email = "example@gmail.com"
    try:
        analysis = await analyze_email_provider(email)
        print(f"Domain: {analysis.domain}")
        print(f"Provider: {analysis.provider}")
        print(f"Reputation: {analysis.reputation}")
        print(f"SPF: {analysis.dns_auth.spf != 'no-spf'}")
        print(f"DKIM: {analysis.dns_auth.dkim.status}")
        print(f"DMARC: {analysis.dns_auth.dmarc != 'no-dmarc'}")
    except Exception as e:
        logger.error("Example failed: %s", str(e))

if __name__ == "__main__":
    asyncio.run(example_usage())


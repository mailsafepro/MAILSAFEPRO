# validation.py — versión refactorizada y endurecida

from __future__ import annotations

import asyncio
import json
import logging
import random
import inspect
import re
import socket
import ssl
import time
import threading
import ipaddress
import smtplib
from app.resilience.per_host_breaker import PerHostCircuitBreaker
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Deque, List, Optional, Set, Tuple
from collections import defaultdict, deque

import aiodns
import dns.resolver
import tldextract

# Integración opcional de Redis asíncrono (inyectable vía set_redis_client)
try:
    from redis.asyncio import Redis  # type: ignore
except Exception:  # pragma: no cover
    Redis = None  # type: ignore

# SPF opcional (pyspf)
try:
    import spf  # type: ignore
    SPF_AVAILABLE = True
except Exception:  # pragma: no cover
    SPF_AVAILABLE = False

from typing import Optional, Any, TYPE_CHECKING  # ya importas Optional

# Solo para type checkers: trae el símbolo real sin afectar runtime
if TYPE_CHECKING:
    from redis.asyncio import Redis as RedisT
else:
    RedisT = Any 

import os

try:
    from prometheus_client import Counter, Histogram
    PROM_AVAILABLE = True if os.getenv("DISABLE_PROMETHEUS") != "1" else False
except Exception:
    PROM_AVAILABLE = False


# Dependencias del proyecto (deben existir en tu app)
from app.logger import logger
from app.config import settings
from app.cache import AsyncTTLCache, UnifiedCache  # Unified Cache + L1

# ---------------------------
# Configuración y Constantes
# ---------------------------

class ValidationResult(Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    RESTRICTED = "restricted"
    DISPOSABLE = "disposable"


class SMTPResult(Enum):
    SUCCESS = "success"
    MAILBOX_NOT_FOUND = "mailbox_not_found"
    CONNECTION_FAILED = "connection_failed"
    TIMEOUT = "timeout"
    TLS_ERROR = "tls_error"
    RESTRICTED = "restricted"


@dataclass
class ValidationConfig:
    mx_lookup_timeout: float = 2.0
    smtp_timeout: float = 5.0
    smtp_ports: List[int] = None  # se inicializa en __post_init__
    smtp_use_tls: bool = True
    smtp_max_retries: int = 2
    mx_cache_ttl: int = 3600
    mx_cache_maxsize: int = 500
    disposable_domains: Set[str] = None
    dns_nameservers: List[str] = None
    advanced_mx_check: bool = True
    prefer_ipv4: bool = True
    retry_attempts: int = 3
    retry_base_backoff: float = 0.25
    retry_max_backoff: float = 2.0
    smtp_max_total_time: int = 10
    smtp_sender: str = "noreply@emailvalidator.com"
    smtp_skip_tls_verify: bool = False
    SMTP_HOST_LIMIT_PER_MIN: int = 60


    def __post_init__(self) -> None:
        if self.smtp_ports is None:
            self.smtp_ports = [25, 587, 465]
        if self.disposable_domains is None:
            self.disposable_domains = set()


def _get_nested(attr_root: Any, path: str, default: Any) -> Any:
    """
    Obtiene un atributo anidado por nombre desde settings con fallback.
    """
    try:
        value = getattr(attr_root, path, default)
        return value
    except Exception:
        return default


# Cargar configuración desde settings.validation si existe
validation_ns = getattr(settings, "validation", settings)
config = ValidationConfig(
    mx_lookup_timeout=getattr(validation_ns, "mx_lookup_timeout", 2.0),
    smtp_timeout=getattr(validation_ns, "smtp_timeout", 8.0),
    smtp_ports=getattr(validation_ns, "smtp_ports", [25, 587, 465]),
    smtp_use_tls=getattr(validation_ns, "smtp_use_tls", True),
    smtp_max_retries=getattr(validation_ns, "smtp_max_retries", 2),
    mx_cache_ttl=getattr(validation_ns, "mx_cache_ttl", 3600),
    mx_cache_maxsize=getattr(validation_ns, "mx_cache_maxsize", 500),
    disposable_domains=getattr(validation_ns, "disposable_domains", set()),
    dns_nameservers=getattr(validation_ns, "dns_nameservers", None),
    advanced_mx_check=getattr(validation_ns, "advanced_mx_check", True),
    prefer_ipv4=getattr(validation_ns, "prefer_ipv4", True),
    retry_attempts=getattr(validation_ns, "retry_attempts", 3),
    retry_base_backoff=getattr(validation_ns, "retry_base_backoff", 0.25),
    retry_max_backoff=getattr(validation_ns, "retry_max_backoff", 2.0),
    smtp_max_total_time=getattr(validation_ns, "smtp_max_total_time", 15),
    smtp_sender=getattr(validation_ns, "smtp_sender", "noreply@emailvalidator.com"),
    smtp_skip_tls_verify=getattr(validation_ns, "smtp_skip_tls_verify", False),
    SMTP_HOST_LIMIT_PER_MIN=getattr(settings, "SMTP_HOST_LIMIT_PER_MIN", 60),
)

# ---------------------------
# Modelos de Datos
# ---------------------------

@dataclass
class MXRecord:
    exchange: str
    preference: int
    def __post_init__(self) -> None:
        self.exchange = self.exchange.rstrip(".").lower()


@dataclass
class VerificationResult:
    valid: bool
    detail: str
    mx_host: Optional[str] = None
    error_type: Optional[str] = None
    smtp_response: Optional[str] = None
    provider: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "detail": self.detail,
            "mx_host": self.mx_host,
            "error_type": self.error_type,
            "smtp_response": self.smtp_response,
            "provider": self.provider,
        }


@dataclass
class SMTPTestResult:
    success: Optional[bool]
    message: str
    response_code: Optional[int] = None
    response_text: Optional[str] = None
    used_tls: bool = False
    tested_ports: List[int] = None

    def __post_init__(self) -> None:
        if self.tested_ports is None:
            self.tested_ports = []

# ---------------------------
# Circuit Breaker
# ---------------------------

smtp_circuit_breaker: Optional[PerHostCircuitBreaker] = None

# ---------------------------
# Caches en memoria + Redis
# ---------------------------

mx_cache = AsyncTTLCache(ttl=config.mx_cache_ttl, maxsize=config.mx_cache_maxsize)
domain_cache = AsyncTTLCache(ttl=3600, maxsize=1000)
smtp_cache = AsyncTTLCache(ttl=300, maxsize=1000)

REDIS_CLIENT: Optional["RedisT"] = None


def set_redis_client(redis_client: "RedisT") -> None:
    """
    Inyecta el cliente Redis opcional para cache distribuida.
    """
    global REDIS_CLIENT, smtp_circuit_breaker
    REDIS_CLIENT = redis_client
    if redis_client:
        UnifiedCache.initialize(redis_client)
        smtp_circuit_breaker = PerHostCircuitBreaker(
            service_name="smtp",
            redis_client=redis_client,
            fail_max=getattr(settings, "smtp_failure_threshold", 5),
            timeout_duration=getattr(settings, "smtp_recovery_timeout", 300)
        )

async def async_cache_get(key: str) -> Any:
    # Use UnifiedCache
    cached = await UnifiedCache.get(key)
    if cached is not None:
        return cached

    # Fallback en memoria por prefijo
    if key.startswith("mx:"):
        return await mx_cache.get(key)
    if key.startswith("domain:"):
        return await domain_cache.get(key)
    if key.startswith("smtp:"):
        return await smtp_cache.get(key)
    return None


async def async_cache_set(key: str, value: Any, ttl: Optional[int] = None) -> None:
    # Use UnifiedCache
    await UnifiedCache.set(key, value, ttl=ttl)

    # Fallback memoria
    storable = value.to_dict() if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")) else value
    
    try:
        if key.startswith("mx:"):
            await mx_cache.set(key, storable, ttl=ttl or config.mx_cache_ttl)
        elif key.startswith("domain:"):
            await domain_cache.set(key, storable, ttl=ttl or 3600)
        elif key.startswith("smtp:"):
            await smtp_cache.set(key, storable, ttl=ttl or 300)
    except TypeError:
        if key.startswith("mx:"):
            await mx_cache.set(key, storable)
        elif key.startswith("domain:"):
            await domain_cache.set(key, storable)
        elif key.startswith("smtp:"):
            await smtp_cache.set(key, storable)


async def async_cache_clear(prefix: Optional[str] = None) -> None:
    """
    Limpieza de caché; en Redis usa SCAN para evitar bloqueos por KEYS.
    """
    # Use UnifiedCache
    if prefix:
        await UnifiedCache.clear(prefix)
    else:
        await UnifiedCache.clear()

    # Fallback
    if not prefix:
        await mx_cache.clear()
        await domain_cache.clear()
        await smtp_cache.clear()
    else:
        # No soportado selectivamente en fallback simple
        pass
        if prefix.startswith("mx:"):
            await mx_cache.clear()
        if prefix.startswith("domain:"):
            await domain_cache.clear()
        if prefix.startswith("smtp:"):
            await smtp_cache.clear()

# ---------------------------
# Listas y constantes
# ---------------------------

SMTP_RESTRICTED_DOMAINS: Set[str] = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "comcast.net", "zoho.com",
    "mail.ru", "yandex.ru", "protonmail.com", "icloud.com", "gmx.com",
    "fastmail.com", "me.com", "mac.com", "tutanota.com", "qq.com", "126.com",
    "163.com", "naver.com", "daum.net", "seznam.cz", "web.de", "optonline.net",
    "bellsouth.net",
}

RESERVED_DOMAINS: Set[str] = {
    "example.com", "example.org", "example.net", "example.test",
    "invalid.com", "test.com", "test.org",
}

COMMON_DISPOSABLE: Set[str] = {
    "tempmail.com", "10minutemail.com", "guerrillamail.com",
    "mailinator.com", "yopmail.com", "throwawaymail.com",
    "fakeinbox.com", "temp-mail.org", "getairmail.com",
}

# ============================================================================
# ABUSE DOMAINS - Dominios conocidos por actividad maliciosa o quejas de spam
# ============================================================================

ABUSE_DOMAINS: Set[str] = {
    # Dominios reportados por actividad maliciosa
    "abuse-domain.com", "spam-sender.net", "phishing-site.org",
    "malicious-mail.com", "scam-email.net", "fraud-domain.com",
    
    # Dominios con alto historial de quejas
    "complaint-source.com", "reported-spam.net", "blacklisted-mail.org",
    "spam-history.com", "abuse-record.net",
    
    # Dominios asociados con bots y scrapers
    "bot-mail.com", "scraper-email.net", "automated-sender.com",
    "fake-sender.org", "bot-domain.net",
    
    # Dominios temporales maliciosos
    "temp-abuse.com", "disposable-spam.net", "throwaway-abuse.org",
    
    # Añade más según tu investigación y reportes
}


def is_abuse_domain(domain: str) -> bool:
    """
    Verifica si un dominio está en la lista de dominios de abuso.
    
    Args:
        domain: Dominio a verificar (sin @)
        
    Returns:
        bool: True si el dominio es conocido por abuso
    """
    domain_lower = domain.lower().strip().rstrip(".")
    return domain_lower in ABUSE_DOMAINS


# ---------------------------
# Utilidades de Dominio
# ---------------------------

class DomainExtractor:
    """
    Wrapper de tldextract con caché deshabilitada (entornos efímeros).
    """
    def __init__(self) -> None:
        self._extractor = tldextract.TLDExtract(cache_dir=False)

    def extract_base_domain(self, domain: str) -> str:
        try:
            extracted = self._extractor(domain)
            if extracted and extracted.suffix:
                base_domain = f"{extracted.domain}.{extracted.suffix}"
                return base_domain.lower()
            return (domain or "").lower()
        except Exception as e:  # pragma: no cover
            logger.debug("Domain extraction failed for %s: %s", domain, str(e))
            return (domain or "").lower()


domain_extractor = DomainExtractor()


def _idna_ascii(domain: str) -> Optional[str]:
    """
    Normaliza un dominio a ASCII (IDNA) con límites básicos anti-DoS.
    """
    try:
        d = (domain or "").strip()  # ¡No hacer rstrip(".")!
        if len(d) > 512:
            return None
        return d.encode("idna").decode("ascii")
    except Exception:
        return None


class DomainValidator:
    @staticmethod
    def is_valid_domain_format(domain: str) -> bool:
        ascii_domain = _idna_ascii(domain)
        if not ascii_domain:
            return False
        if len(ascii_domain) > 253:
            return False
        # Coincidencia completa sobre el dominio
        if not re.fullmatch(r"[A-Za-z0-9.-]+", ascii_domain):
            return False
        if ascii_domain.startswith("-") or ascii_domain.endswith("-"):
            return False
        if ascii_domain.startswith(".") or ascii_domain.endswith("."):
            return False
        parts = ascii_domain.split(".")
        if len(parts) < 2:
            return False
        for part in parts:
            if not part or len(part) > 63:
                return False
            if part.startswith("-") or part.endswith("-"):
                return False
            # Coincidencia completa por label
            if not re.fullmatch(r"[A-Za-z0-9-]+", part):
                return False
        return True

    @staticmethod
    def is_safe_mx_host(mx_host: str) -> bool:
        if not mx_host or mx_host.startswith(".") or mx_host.endswith("."):
            return False
        blocked_hosts = {
            "localhost", "localhost.localdomain", "0.0.0.0",
            "127.0.0.1", "::1", "0.0.0.1",
        }
        if mx_host.lower() in blocked_hosts:
            logger.warning("Blocked dangerous MX host: %s", mx_host)
            return False
        try:
            ip = ipaddress.ip_address(mx_host)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_unspecified
            ):
                logger.warning("MX host %s is non-public IP: %s", mx_host, ip)
                return False
            s = str(ip)
            if s.startswith("169.254.") or s.lower().startswith("fe80:"):
                logger.warning("MX host %s resolves to link-local IP", mx_host)
                return False
            return True
        except ValueError:
            # no es un literal IP
            return True
        except Exception as e:  # pragma: no cover
            logger.debug("MX host safety check error for %s: %s", mx_host, str(e))
            return False


domain_validator = DomainValidator()

# ---------------------------
# Helpers: retry con backoff
# ---------------------------

async def async_retry(
    fn,
    *args,
    attempts: Optional[int] = None,
    base_backoff: Optional[float] = None,
    max_backoff: Optional[float] = None,
    on_retry=None,
    **kwargs,
):
    """
    Reintentos exponenciales con jitter para funciones async o wrappers en ejecutor.
    """
    attempts = attempts if attempts is not None else config.retry_attempts
    base_backoff = base_backoff if base_backoff is not None else config.retry_base_backoff
    max_backoff = max_backoff if max_backoff is not None else config.retry_max_backoff

    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            if attempt > 1:
                logger.debug(f"Retrying {getattr(fn, '__name__', str(fn))} attempt {attempt}/{attempts}")
            return await fn(*args, **kwargs)
        except Exception as e:
            last_exc = e
            backoff = min(max_backoff, base_backoff * (2 ** (attempt - 1)))
            jitter = random.uniform(0, backoff * 0.3)
            wait = backoff + jitter
            logger.debug(f"Retry {attempt}/{attempts} for {getattr(fn, '__name__', str(fn))} sleeping {wait:.3f}s due to {str(e)}")
            if on_retry:
                try:
                    on_retry(e, attempt)
                except Exception:
                    pass
            await asyncio.sleep(wait)
    raise last_exc  # pragma: no cover

# ---------------------------
# DNS Resolver con fallback
# ---------------------------

class DNSResolver:
    def __init__(self) -> None:
        timeout = float(getattr(settings.validation, "mx_lookup_timeout", 2.0))
        
        # ✅ Obtener nameservers con fallback a DNS públicos
        ns = getattr(settings.validation, "dns_nameservers", None)
        if not ns:
            env_ns = os.getenv("DNS_NAMESERVERS", "").strip()
            if env_ns:
                ns = [x.strip() for x in env_ns.split(",") if x.strip()]
        
        # ✅ CRÍTICO: Fallback a DNS públicos si no hay configuración
        if not ns:
            ns = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
            logger.info(f"No DNS nameservers configured, using public DNS: {ns}")
        else:
            logger.info(f"Using custom nameservers: {ns}")
        
        # ✅ SIEMPRE configurar nameservers (incluso con fallback)
        self._sync_resolver = dns.resolver.Resolver(configure=False)  # ← configure=False para control manual
        self._sync_resolver.nameservers = ns
        self._sync_resolver.timeout = timeout
        self._sync_resolver.lifetime = max(timeout * 5.0, 10.0)  # ← AUMENTAR de 2.0 a 5.0
        
        # ✅ SIEMPRE pasar nameservers a aiodns
        self._async_resolver = aiodns.DNSResolver(
            timeout=timeout,
            nameservers=ns
        )

    # Alias esperados por tests
    async def _query_mx_primary(self, domain: str) -> List["MXRecord"]:
        return await self._async_query_mx_primary(domain)

    async def _query_mx_fallback(self, domain: str) -> List["MXRecord"]:
        return await self._async_query_mx_fallback(domain)

    # -------- MX (implementación real) --------
    async def _async_query_mx_primary(self, domain: str) -> List["MXRecord"]:
        answers = await self._async_resolver.query(domain, "MX")
        records: List["MXRecord"] = []
        for answer in answers or []:
            records.append(MXRecord(exchange=answer.host, preference=int(answer.priority)))
        return sorted(records, key=lambda x: x.preference)

    async def _async_query_mx_fallback(self, domain: str) -> List["MXRecord"]:
        loop = asyncio.get_running_loop()
        def sync_resolve() -> List["MXRecord"]:
            rs = list(self._sync_resolver.resolve(domain, "MX"))
            out: List["MXRecord"] = []
            for r in rs:
                out.append(MXRecord(exchange=str(r.exchange).rstrip("."), preference=int(r.preference)))
            return sorted(out, key=lambda x: x.preference)
        return await loop.run_in_executor(None, sync_resolve)

    async def query_mx_async(self, domain: str) -> list["MXRecord"]:
        # Usar los alias que los tests parchean
        try:
            recs = await async_retry(self._query_mx_primary, domain)
        except Exception as e:
            logger.debug(f"Async MX primary failed for {domain}: {str(e)}")
            recs = None

        if not recs:
            try:
                recs = await async_retry(self._query_mx_fallback, domain)
            except Exception as e2:
                logger.debug(f"Fallback MX query failed for {domain}: {str(e2)}")
                recs = []

        # Normalizar a MXRecord y filtrar vacíos
        out: list[MXRecord] = []
        for item in recs or []:
            if isinstance(item, MXRecord):
                if item.exchange:
                    out.append(item)
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                pref, host = item
                ex = str(host).strip().rstrip(".").lower()
                if ex:
                    out.append(MXRecord(exchange=ex, preference=int(pref)))
            elif isinstance(item, dict):
                ex = str(item.get("exchange", "")).strip().rstrip(".").lower()
                if ex:
                    out.append(MXRecord(exchange=ex, preference=int(item.get("preference", 0))))
            else:
                ex = str(item).strip().rstrip(".").lower()
                if ex:
                    out.append(MXRecord(exchange=ex, preference=0))

        return sorted(out, key=lambda x: x.preference)

    async def query_mx_with_pref(self, domain: str) -> list[tuple[int, str]]:
        mx_records = await self.query_mx_async(domain)
        if mx_records and not hasattr(mx_records[0], "preference"):
            return [(int(p), str(h)) for p, h in mx_records]  # type: ignore[index]
        return [(r.preference, r.exchange) for r in mx_records]  # type: ignore[union-attr]

    # -------- TXT --------
    async def _async_query_txt_primary(self, name: str) -> list[str]:
        answers = await self._async_resolver.query(name, "TXT")
        out: list[str] = []
        for ans in answers or []:
            try:
                piece = b"".join(getattr(ans, "text", [])).decode("utf-8", errors="ignore")
            except Exception:
                parts = [
                    (x.decode("utf-8", "ignore") if isinstance(x, (bytes, bytearray)) else str(x))
                    for x in getattr(ans, "text", [])
                ]
                piece = "".join(parts)
            if piece:
                out.append(piece)
        return out

    async def _async_query_txt_fallback(self, name: str) -> list[str]:
        def sync_txt():
            try:
                resp = self._sync_resolver.resolve(name, "TXT")
            except Exception:
                return []
            out: list[str] = []
            for r in resp:
                for s in getattr(r, "strings", []):
                    out.append(s.decode("utf-8", "ignore") if isinstance(s, (bytes, bytearray)) else str(s))
            return out
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, sync_txt)

    async def query_txt(self, name: str) -> list[str]:
        try:
            return await async_retry(self._async_query_txt_primary, name)
        except Exception as e:
            logger.debug(f"Async TXT primary failed for {name}: {str(e)}")
        try:
            return await async_retry(self._async_query_txt_fallback, name)
        except Exception as e2:
            logger.debug(f"Fallback TXT query failed for {name}: {str(e2)}")
            return []

dns_resolver = DNSResolver()

# Nuevo contrato estable público: siempre devuelve list[str]
async def get_mx_hosts(domain: str, max_records: int = 5) -> list[str]:
    recs = await get_mx_records(domain, max_records=max_records)
    hosts: list[str] = []
    for r in recs or []:
        if hasattr(r, "exchange"):
            h = getattr(r, "exchange", "")
        else:
            h = str(r)
        h = h.strip().rstrip(".").lower()
        if h:
            hosts.append(h)
    # deduplicación preservando orden
    out: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out[:max_records]

# Opcional: cuando caches, guarda list[str] para compatibilidad multinodo
async def _cache_mx_hosts(domain: str, hosts: list[str], ttl: int | None = None) -> None:
    try:
        await async_cache_set(f"mx:{domain.lower().strip()}", hosts, ttl=ttl or settings.validation.cache_ttl)
    except Exception:
        pass

# ---------------------------
# Resolución IP pública
# ---------------------------

async def resolve_public_ip(hostname: str, prefer_ipv4: bool = True) -> Optional[str]:
    """
    Obtiene una IP pública (no privada/loopback/etc.) para un hostname.
    """
    try:
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=0,
            flags=socket.AI_ADDRCONFIG,
        )
        v4: List[str] = []
        v6: List[str] = []
        for family, _, _, _, sockaddr in addrinfo:
            ip = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                if (
                    ip_obj.is_private
                    or ip_obj.is_loopback
                    or ip_obj.is_link_local
                    or ip_obj.is_multicast
                    or ip_obj.is_reserved
                    or ip_obj.is_unspecified
                ):
                    continue
                if family == socket.AF_INET:
                    v4.append(ip)
                elif family == socket.AF_INET6:
                    v6.append(ip)
            except Exception:
                continue
        if prefer_ipv4:
            return (v4 or v6 or [None])[0]
        else:
            return (v6 or v4 or [None])[0]
    except Exception as e:
        logger.debug("Failed to resolve public IP for %s: %s", hostname, str(e))
        return None

# ---------------------------
# MX records con caché
# ---------------------------

def _to_mx_list(seq: Any) -> list[MXRecord]:
    out: list[MXRecord] = []
    for item in seq or []:
        if isinstance(item, MXRecord):
            r = item
        elif isinstance(item, dict):
            ex = str(item.get("exchange", "")).strip().rstrip(".").lower()
            if not ex:
                continue
            r = MXRecord(exchange=ex, preference=int(item.get("preference", 0)))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            pref, host = item
            ex = str(host).strip().rstrip(".").lower()
            if not ex:
                continue
            r = MXRecord(exchange=ex, preference=int(pref))
        else:
            ex = str(item).strip().rstrip(".").lower()
            if not ex:
                continue
            r = MXRecord(exchange=ex, preference=0)
        if r.exchange:
            out.append(r)
    return out

def _to_host_list(seq: Any) -> list[str]:
    hosts: list[str] = []
    for item in seq or []:
        if isinstance(item, MXRecord):
            h = item.exchange
        elif isinstance(item, dict):
            h = str(item.get("exchange", ""))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            h = str(item[1])
        else:
            h = str(item)
        h = h.strip().rstrip(".").lower()
        if h:
            hosts.append(h)
    # dedup preservando orden
    out: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out

async def get_mx_records(domain: str, max_records: int = 5):
    d = (domain or "").lower().strip()
    cache_key = UnifiedCache.build_key("mx", d)

    # 1) Caché de validation -> devolver MXRecord
    try:
        cached = await async_cache_get(cache_key)
        if isinstance(cached, list) and cached:
            mx_list = _to_mx_list(cached)
            if mx_list:
                return mx_list[:max_records]
    except Exception:
        pass

    # 2) Resolver de validation -> devolver MXRecord
    try:
        res_or = dns_resolver.query_mx_async(d)
        recs = await res_or if inspect.isawaitable(res_or) else res_or
        mx_list = _to_mx_list(recs)
        if mx_list:
            try:
                # opcional: cachear tal cual como MXRecord serializable (si tu cache soporta)
                await async_cache_set(cache_key, [r.__dict__ for r in mx_list], ttl=config.mx_cache_ttl)
            except Exception:
                pass
            return mx_list[:max_records]
    except Exception as e:
        logger.debug(f"Native MX resolver failed for {d}: {str(e)}")

    # 3) Fallback providers -> devolver list[str]
    try:
        from app import providers as prov

        # 3a) caché de providers (puede ser list[str])
        pcached_or = prov.async_cache_get(cache_key)
        pcached = await pcached_or if inspect.isawaitable(pcached_or) else pcached_or
        if isinstance(pcached, list) and pcached:
            hosts = _to_host_list(pcached)
            if hosts:
                return hosts[:max_records]

        # 3b) resolver de providers (lista de (pref, host))
        pairs_or = prov.dns_resolver.query_mx_with_pref(d)
        pairs = await pairs_or if inspect.isawaitable(pairs_or) else pairs_or
        hosts = _to_host_list(pairs)
        if hosts:
            return hosts[:max_records]
    except Exception:
        pass

    return []


# ---------------------------
# Verificación de Dominio
# ---------------------------

class DomainChecker:
    """
    Verifica configuración básica de un dominio para recepción SMTP.
    """
    def __init__(self) -> None:
        self.connection_timeout = min(config.smtp_timeout, 15.0)

    async def check_domain_async(self, domain: str) -> VerificationResult:
        """
        ✅ Verifica configuración básica de un dominio para recepción SMTP.

        Cambios:
        - Si MX exists pero conexión falla → valid: true (dominio válido, solo red)
        - Si no hay MX records → valid: false (dominio inválido)
        - En Docker, MX exists es suficiente para considerar valid: true
        - Detecta dominios reservados, de abuso y descartables antes de tocar MX/DNS.
        """

        # Validación de formato
        if not domain_validator.is_valid_domain_format(domain):
            return VerificationResult(False, "Invalid domain format", error_type="invalid_format")

        base = domain_extractor.extract_base_domain(domain)

        # En PRODUCCIÓN: bloquear dominios reservados
        if base in RESERVED_DOMAINS:
            if not getattr(settings, "testing_mode", False):
                return VerificationResult(False, "Reserved domain", error_type="reserved_domain")

        # 🔹 NUEVO: dominios de abuso conocidos (ABUSE_DOMAINS)
        # Se comprueba sobre el base domain para que ej. sub.spam-sender.net también caiga.
        if is_abuse_domain(base):
            return VerificationResult(
                False,
                f"Known abuse domain: {base}",
                error_type="abuse_domain",
            )

        # IMPORTANTE: Verificar disposable ANTES de intentar MX
        is_disposable = await is_disposable_domain(base, REDIS_CLIENT)
        if is_disposable:
            return VerificationResult(
                False,
                f"Disposable domain: {base}",
                error_type="disposable_domain"
            )

        # ✅ Obtener MX records
        mx_records = await get_mx_records(domain)
        if not mx_records:
            # ❌ Sin MX records = dominio no válido, pero intenta A para distinguir
            try:
                loop = asyncio.get_running_loop()

                def sync_a():
                    return dns_resolver.sync_resolver.resolve(domain, "A")

                await loop.run_in_executor(None, sync_a)
                return VerificationResult(
                    True,  # ← A record existe, puede recibir email
                    f"{domain} has A record but no MX",
                    error_type="no_mx_has_a",
                    mx_host=domain,  # Usar dominio como MX
                )
            except Exception:
                return VerificationResult(
                    False,
                    "No MX or A records for domain",
                    error_type="no_dns_records",
                )

        # ✅ MX records existen = dominio válido
        # Ahora intento de conexión SMTP (pero si falla, no invalida el email)
        connection_succeeded = False
        last_error = None

        for mx in mx_records:
            mx_host = mx.exchange if hasattr(mx, "exchange") else str(mx)

            if await smtp_circuit_breaker.is_open(mx_host):
                logger.info("Circuit breaker open for %s", mx_host)
                last_error = "Circuit breaker open"
                continue

            if not domain_validator.is_safe_mx_host(mx_host):
                logger.warning("Unsafe MX host: %s", mx_host)
                await smtp_circuit_breaker.record_failure(mx_host)
                last_error = "Unsafe MX host"
                continue

            public_ip = await resolve_public_ip(mx_host, prefer_ipv4=config.prefer_ipv4)
            if not public_ip:
                logger.debug("MX %s has no public IP", mx_host)
                await smtp_circuit_breaker.record_failure(mx_host)
                last_error = "No public IP"
                continue

            connection_result = await self._test_smtp_connection(mx_host)
            if connection_result.success:
                # ✅ Conexión exitosa
                return VerificationResult(
                    True,
                    f"Connected to {mx_host}",
                    mx_host=mx_host,
                )
            else:
                await smtp_circuit_breaker.record_failure(mx_host)
                logger.debug(f"Connection failed to {mx_host}: {connection_result.message}")
                last_error = connection_result.message
                # Continuar intentando otros MX

        # ✅ CAMBIO CLAVE:
        # MX records existen pero todos fallan conexión.
        # En Docker es normal (sin acceso a red externa).
        # Retornar valid: true pero con error_type informativo.
        return VerificationResult(
            True,
            f"Domain {domain} has valid MX records but SMTP connection failed ({last_error})",
            error_type="mx_connection_failed",
            mx_host=str(mx_records[0].exchange) if mx_records else domain,
        )


    async def _test_smtp_connection(self, mx_host: str) -> SMTPTestResult:
        """
        Conecta y EHLO/STARTTLS sin RCPT para validar reachability.
        """
        preferred_ports = config.smtp_ports[:2] if len(config.smtp_ports) >= 2 else config.smtp_ports
        loop = asyncio.get_running_loop()

        for port in preferred_ports:
            try:
                result: SMTPTestResult = await async_retry(
                    lambda: loop.run_in_executor(None, lambda: self._test_smtp_sync(mx_host, port)),
                    attempts=config.retry_attempts,
                    base_backoff=config.retry_base_backoff,
                    max_backoff=config.retry_max_backoff,
                )
                if result and getattr(result, "success", None):
                    return result
            except Exception as e:
                logger.debug(f"SMTP connection attempt failed for {mx_host}:{port} — {str(e)}")
                continue

        return SMTPTestResult(success=False, message="All connection attempts failed", tested_ports=list(preferred_ports))

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if config.smtp_skip_tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _test_smtp_sync(self, mx_host: str, port: int) -> SMTPTestResult:
        server: Optional[smtplib.SMTP] = None
        used_tls = False
        try:
            if port == 465:
                ctx = self._build_ssl_context()
                server = smtplib.SMTP_SSL(timeout=self.connection_timeout, context=ctx)
                server.connect(mx_host, port)
                server.ehlo()
                used_tls = True
            else:
                server = smtplib.SMTP(timeout=self.connection_timeout)
                server.connect(mx_host, port)
                server.ehlo_or_helo_if_needed()
                if config.smtp_use_tls and server.has_extn("starttls"):
                    try:
                        ctx = self._build_ssl_context()
                        server.starttls(context=ctx)
                        server.ehlo()
                        used_tls = True
                    except Exception as e:
                        logger.debug(f"STARTTLS attempt failed for {mx_host}:{port} — {str(e)}")

            sender = config.smtp_sender
            mail_options: List[str] = []
            try:
                local_part = sender.split("@", 1)[0]
                if any(ord(c) > 127 for c in local_part):
                    mail_options.append("SMTPUTF8")
            except Exception:
                pass

            server.mail(sender, options=mail_options)
            return SMTPTestResult(
                success=True,
                message=f"Connected to {mx_host}:{port}",
                used_tls=used_tls,
                tested_ports=[port],
            )
        except smtplib.SMTPResponseException as e:
            response_text = SMTPChecker._parse_smtp_response_static(e.smtp_error)
            return SMTPTestResult(
                success=False,
                message="SMTP response exception",
                response_code=getattr(e, "smtp_code", None),
                response_text=response_text,
                tested_ports=[port],
            )
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, socket.timeout) as e:
            return SMTPTestResult(success=False, message=f"Connection error: {str(e)}", tested_ports=[port])
        except Exception as e:
            logger.error(f"Unexpected SMTP error for {mx_host}:{port} — {str(e)}")
            return SMTPTestResult(success=False, message="unexpected_error", tested_ports=[port])
        finally:
            try:
                if server:
                    try:
                        server.quit()
                    except Exception:
                        try:
                            server.close()
                        except Exception:
                            pass
            except Exception:
                pass


domain_checker = DomainChecker()

# ---------------------------
# Rate limiter local por host
# ---------------------------

_smtp_host_history: Dict[str, Deque[float]] = defaultdict(deque)
_smtp_history_lock = threading.Lock()
_SMTP_HOST_LIMIT_PER_MIN = config.SMTP_HOST_LIMIT_PER_MIN

# ---------------------------
# Verificación SMTP (sync)
# ---------------------------

class SMTPChecker:
    _host_request_times: Dict[str, Deque[float]] = defaultdict(deque)
    _history_lock = threading.Lock()
    _HOST_LIMIT_PER_MIN = config.SMTP_HOST_LIMIT_PER_MIN

    def __init__(self):
        self.timeout = min(getattr(settings, "smtptimeout", config.smtp_timeout), 15.0)
        self.max_retries = getattr(settings, "smtpmaxretries", config.smtp_max_retries)
        self.maxretries = self.max_retries  # alias de compatibilidad
        self.sender = config.smtp_sender

    @staticmethod
    def _smtp_host_allow_request(host: str) -> bool:
        now = time.time()
        window = 60.0
        with SMTPChecker._history_lock:
            hist = SMTPChecker._host_request_times[host]
            cutoff = now - window
            while hist and hist[0] < cutoff:
                hist.popleft()
            if len(hist) >= SMTPChecker._HOST_LIMIT_PER_MIN:
                return False
            hist.append(now)
            return True

    @staticmethod
    def _parse_smtp_response_static(response: Any) -> str:
        if not response:
            return "No response"
        try:
            if isinstance(response, (bytes, bytearray)):
                response = response.decode("utf-8", errors="ignore")
            first_line = str(response).split("\n", 1)[0].strip()
            return first_line[:500]
        except Exception:
            return str(response)[:500]

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if config.smtp_skip_tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def check_smtp_mailbox(self, email: str, do_rcpt: bool = False) -> Tuple[Optional[bool], str]:
        try:
            domain = email.split("@", 1)[1].lower()
        except (IndexError, AttributeError):
            return False, "Invalid email format"

        if domain in SMTP_RESTRICTED_DOMAINS:
            return None, f"SMTP verification not allowed for {domain}"

        # Obtener MX host válido mediante checker asíncrono
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            domain_result = asyncio.run(cached_check_domain(domain))
        else:
            fut = asyncio.run_coroutine_threadsafe(cached_check_domain(domain), loop)
            try:
                domain_result = fut.result(timeout=30)
            except Exception as e:
                logger.error("Failed to obtain domain_result in synchronous SMTP check: %s", str(e))
                return False, "Domain validation error"

        if not getattr(domain_result, "valid", False) or not getattr(domain_result, "mx_host", None):
            return False, "Invalid domain configuration"

        mx_host = domain_result.mx_host
        if not domain_validator.is_safe_mx_host(mx_host):
            return False, "Unsafe MX host"

        smtp_result = self._perform_smtp_check(email, mx_host, do_rcpt)
        if getattr(smtp_result, "success", None) is True:
            return True, getattr(smtp_result, "response_text", getattr(smtp_result, "message", "Mailbox verified"))
        elif getattr(smtp_result, "response_code", None):
            # 4xx/5xx se devuelven como False con el texto
            return False, getattr(smtp_result, "response_text", getattr(smtp_result, "message", "Mailbox verification failed"))
        else:
            return None, getattr(smtp_result, "message", "Unknown SMTP result")

    def _perform_smtp_check(self, email: str, mx_host: str, do_rcpt: bool) -> SMTPTestResult:
        if not SMTPChecker._smtp_host_allow_request(mx_host):
            logger.warning("SMTP checks rate-limited for host %s", mx_host)
            return SMTPTestResult(success=None, message="rate_limited_for_host", tested_ports=[])

        tested_ports: List[int] = []
        ports = getattr(settings, "smtp_ports", config.smtp_ports)

        for port in ports:
            tested_ports.append(port)

            attempt = 0
            backoff = 0.5
            while attempt < max(1, int(self.max_retries)):
                attempt += 1
                server = None
                used_tls = False
                try:
                    if port == 465:
                        ctx = self._build_ssl_context()
                        server = smtplib.SMTP_SSL(timeout=self.timeout, context=ctx)
                        server.connect(mx_host, port)
                        server.ehlo()
                        used_tls = True
                    else:
                        server = smtplib.SMTP(timeout=self.timeout)
                        server.connect(mx_host, port)
                        server.ehlo_or_helo_if_needed()
                        if server.has_extn("starttls") and getattr(settings, "smtp_use_tls", config.smtp_use_tls):
                            try:
                                ctx = self._build_ssl_context()
                                server.starttls(context=ctx)
                                server.ehlo()
                                used_tls = True
                            except Exception as e:
                                logger.debug("STARTTLS attempt failed for %s:%d — %s", mx_host, port, str(e))

                    mail_options: List[str] = []
                    try:
                        local_part = self.sender.split("@", 1)[0]
                        if any(ord(c) > 127 for c in local_part):
                            mail_options.append("SMTPUTF8")
                    except Exception:
                        pass

                    server.mail(self.sender, options=mail_options)

                    if do_rcpt:
                        code, resp = server.rcpt(email)
                        response_text = SMTPChecker._parse_smtp_response_static(resp)
                        if code == 250:
                            return SMTPTestResult(
                                success=True,
                                message="Mailbox exists",
                                response_code=code,
                                response_text=response_text,
                                used_tls=used_tls,
                                tested_ports=tested_ports,
                            )
                        else:
                            return SMTPTestResult(
                                success=False,
                                message="SMTP RCPT rejected",
                                response_code=code,
                                response_text=response_text,
                                used_tls=used_tls,
                                tested_ports=tested_ports,
                            )
                    else:
                        return SMTPTestResult(
                            success=None,
                            message="completed_no_rcpt",
                            used_tls=used_tls,
                            tested_ports=tested_ports,
                        )

                except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, socket.timeout) as e:
                    logger.debug("Transient SMTP error for %s:%d (attempt %d): %s", mx_host, port, attempt, str(e))
                    time.sleep(backoff)
                    backoff = min(backoff * 2.0, 8.0)
                    continue
                except smtplib.SMTPResponseException as e:
                    response_text = SMTPChecker._parse_smtp_response_static(e.smtp_error)
                    return SMTPTestResult(
                        success=False,
                        message="SMTP response exception",
                        response_code=getattr(e, "smtp_code", None),
                        response_text=response_text,
                        tested_ports=tested_ports,
                    )
                except Exception as e:
                    logger.error(f"Unexpected SMTP error for {mx_host}:{port} — {str(e)}")
                    return SMTPTestResult(success=False, message="unexpected_error", tested_ports=tested_ports)
                finally:
                    try:
                        if server:
                            try:
                                server.quit()
                            except Exception:
                                try:
                                    server.close()
                                except Exception:
                                    pass
                    except Exception:
                        pass

        return SMTPTestResult(success=False, message="all_ports_failed", tested_ports=tested_ports)

    def _parse_smtp_response(self, response: Any) -> str:
        return SMTPChecker._parse_smtp_response_static(response)


smtpchecker = SMTPChecker()
smtp_checker = smtpchecker

# ---------------------------
# Wrappers async seguros
# ---------------------------

MAX_SMTP_TIMEOUT_ABSOLUTE = 30  # ✅ Límite máximo: 30 segundos

async def check_smtp_mailbox_safe(
    email: str, 
    max_total_time: Optional[int] = None,
    do_rcpt: bool = False
) -> Tuple[Optional[bool], str]:
    """
    Safe SMTP check with absolute timeout protection.
    
    Even if called internally with high timeout, this enforces a maximum.
    """
    # ✅ Aplicar timeout del config
    requested_timeout = max_total_time or config.smtp_max_total_time
    
    # ✅ NUEVO: Límite máximo absoluto
    max_total_time = min(requested_timeout, MAX_SMTP_TIMEOUT_ABSOLUTE)
    
    # ✅ Log si se intenta timeout muy alto
    if requested_timeout > MAX_SMTP_TIMEOUT_ABSOLUTE:
        logger.warning(
            "SMTP timeout capped",
            extra={
                "requested": requested_timeout,
                "applied": max_total_time,
                "email": email[:30],
            }
        )
    try:
        result_or_coro = smtp_checker.check_smtp_mailbox(email, do_rcpt)
        if inspect.isawaitable(result_or_coro):
            result = await asyncio.wait_for(result_or_coro, timeout=max_total_time)
        else:
            loop = asyncio.get_running_loop()
            fut = loop.run_in_executor(None, lambda: result_or_coro)
            result = await asyncio.wait_for(fut, timeout=max_total_time)
    except asyncio.TimeoutError:
        logger.warning("SMTP check timeout for %s", email)
        return None, "SMTP check timeout"
    except asyncio.CancelledError:
        logger.info("SMTP check cancelled")
        raise
    except Exception as e:
        logger.error("SMTP wrapper unexpected error: %s", str(e))
        return None, f"SMTP error: {str(e)}"

    if isinstance(result, tuple) and len(result) >= 2:
        return result[0], result[1]
    if hasattr(result, "success"):
        return result.success, getattr(result, "response_text", getattr(result, "message", ""))
    return None, "Unknown result"


# ---------------------------
# APIs públicas de dominio
# ---------------------------

async def cached_check_domain(domain: str) -> VerificationResult:
    norm = domain.strip().lower()
    cache_key = UnifiedCache.build_key("domain", norm)
    cached = await async_cache_get(cache_key)
    if isinstance(cached, dict):
        return VerificationResult(**cached)
    if isinstance(cached, VerificationResult):
        return cached

    res_or_await = domain_checker.check_domain_async(norm)
    result = await res_or_await if inspect.isawaitable(res_or_await) else res_or_await
    await async_cache_set(cache_key, result.to_dict(), ttl=3600)
    return result


def check_domain_sync(domain: str) -> VerificationResult:
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(cached_check_domain(domain))
        else:
            fut = asyncio.run_coroutine_threadsafe(cached_check_domain(domain), loop)
            return fut.result(timeout=30)
    except Exception as e:
        logger.error("Sync domain check failed for %s: %s", domain, str(e))
        return VerificationResult(False, "Domain validation service error", error_type="validation_error")


# ---------------------------
# Dominios desechables
# ---------------------------

async def is_disposable_domain(domain: str, redis_client: Optional["RedisT"] = None) -> bool:
    """
    Detecta dominios desechables: configuración local, Redis opcional y lista común.
    """
    try:
        base_domain = domain_extractor.extract_base_domain(domain)
        if base_domain in config.disposable_domains:
            return True
        if redis_client is not None:
            try:
                is_disposable = await redis_client.sismember("disposable_domains", base_domain)
                if is_disposable:
                    return True
            except Exception as e:
                logger.debug("Redis disposable check failed: %s", str(e))
        return base_domain in COMMON_DISPOSABLE
    except Exception as e:
        logger.error("Disposable domain check failed for %s: %s", domain, str(e))
        return False


async def detect_catch_all_domain(domain: str, mx_records: Optional[List[MXRecord]] = None) -> Dict[str, Any]:
    """
    Detects if a domain is configured as catch-all (accepts all email addresses).
    Uses SMTP verification with a random non-existent user to test.
    Caches results for 24h to avoid repeated checks.
    """
    domain_lower = domain.strip().lower()
    
    # Check cache first
    cache_key = UnifiedCache.build_key("catch_all", domain_lower)
    cached = await UnifiedCache.get(cache_key)
    if cached:
        return cached
    
    result = {
        "is_catch_all": False,
        "confidence": 0.0,
        "details": "",
        "method": "none"
    }
    
    try:
        # Generate random non-existent user
        random_user = f"test_{int(time.time())}_{random.randint(1000, 9999)}"
        test_email = f"{random_user}@{domain_lower}"
        
        # Perform SMTP check
        valid, detail = await check_smtp_mailbox_safe(test_email, max_total_time=10, do_rcpt=True)
        
        if valid is True:
            # If random email is valid, domain is catch-all
            result['is_catch_all'] = True
            result['confidence'] = 0.95
            result['details'] = 'Domain accepts non-existent addresses (catch-all)'
            result['method'] = 'smtp'
        elif valid is False:
            # Random email rejected = likely NOT catch-all
            result['is_catch_all'] = False
            result['confidence'] = 0.90
            result['details'] = 'Domain rejects non-existent addresses'
            result['method'] = 'smtp'
        else:
            # Inconclusive
            result['confidence'] = 0.0
            result['details'] = f'SMTP check inconclusive: {detail}'
            result['method'] = 'error'
        
        # Cache result for 24h
        if REDIS_CLIENT and result['confidence'] > 0.5:
            try:
                await UnifiedCache.set(cache_key, result, ttl=86400)  # 24h TTL
                logger.debug(f"Cached catch-all result for {domain_lower}")
            except Exception as e:
                logger.debug(f"Failed to cache catch-all result: {e}")
        
        return result
    
    except asyncio.TimeoutError:
        result['details'] = 'SMTP check timeout'
        result['method'] = 'error'
        logger.debug(f"Catch-all check timeout for {domain_lower}")
        return result
    
    except Exception as e:
        result['details'] = f'SMTP check error: {str(e)[:100]}'
        result['method'] = 'error'
        logger.debug(f"Catch-all check error for {domain_lower}: {e}")
        return result


# ---------------------------
# Monitoreo / Stats
# ---------------------------

async def get_smtp_circuit_breaker_status() -> Dict[str, Any]:
    if smtp_circuit_breaker:
        return {
            "failure_threshold": smtp_circuit_breaker.fail_max,
            "recovery_timeout": smtp_circuit_breaker.timeout_duration,
        }
    return {"status": "disabled"}


async def get_cache_stats() -> Dict[str, Any]:
    if REDIS_CLIENT is not None:
        try:
            # Evitar KEYS; contar con SCAN
            cursor = 0
            mx_count = 0
            while True:
                cursor, batch = await REDIS_CLIENT.scan(cursor=cursor, match="mx:*", count=1000)
                mx_count += len(batch or [])
                if cursor == 0:
                    break
            return {
                "redis_enabled": True,
                "mx_keys": mx_count,
                "mx_cache_size": await mx_cache.size() if hasattr(mx_cache, "size") else "N/A",
            }
        except Exception:
            pass
    return {
        "redis_enabled": False,
        "mx_cache": mx_cache.stats() if hasattr(mx_cache, "stats") else "N/A",
        "domain_cache": domain_cache.stats() if hasattr(domain_cache, "stats") else "N/A",
        "smtp_cache": smtp_cache.stats() if hasattr(smtp_cache, "stats") else "N/A",
    }


def parse_smtp_response(response: Any) -> str:
    return SMTPChecker._parse_smtp_response_static(response)

# ---------------------------
# Ejemplo (main)
# ---------------------------

async def example_usage() -> None:
    email = "example@gmail.com"
    res = await cached_check_domain("gmail.com")
    print(res.to_dict())


if __name__ == "__main__":
    asyncio.run(example_usage())

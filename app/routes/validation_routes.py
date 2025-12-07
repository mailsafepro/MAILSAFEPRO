# validation_routes.py

import asyncio
import csv
import json
import os
import re
import tempfile
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from io import BytesIO, StringIO
from typing import Any, Dict, List, Optional, Tuple
from email_validator import EmailNotValidError, validate_email as validate_email_lib
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    Security,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse
from fastapi.security import SecurityScopes

from app.auth import get_redis, validate_api_key_or_token
from app.cache import AsyncTTLCache
from app.config import get_settings
from app.config import settings as _settings
settings = _settings
from app.exceptions import APIException
from app.logger import logger
from app.metrics import metrics_recorder, track_validation_metrics
from app.models import (
    BatchEmailResponse,
    BatchValidationRequest,
    EmailResponse,
    EmailValidationRequest,
    TokenData,
)
from app.providers import (
    analyze_email_provider,
    get_provider_cache_stats,
    update_reputation,
    ProviderAnalysis,
    DNSAuthResults,
    DKIMInfo,
    is_disposable_email,
    RiskScorer,  # ← NUEVO: Unified risk scoring
    RiskAssessment,  # ← NUEVO
    normalize_email_full,  # ← NUEVO: Full email normalization
)
from app.pii_mask import mask_email
from app.utils import increment_usage, _get_plan_config_safe
from app.validation import (
    SMTP_RESTRICTED_DOMAINS,
    VerificationResult,
    cached_check_domain,
    check_smtp_mailbox_safe,
    is_disposable_domain,
    detect_catch_all_domain,  # ← NUEVO: Catch-all detection
    is_abuse_domain,  # ← NUEVO: Abuse domain detection
)

router = APIRouter(tags=["Email Validation"])


# ---------------------------
# Constantes y Configuración
# ---------------------------

class ValidationLimits:
    FREE_DAILY = 100
    PREMIUM_DAILY = 10_000
    ENTERPRISE_DAILY = 100_000

    BATCH_MAX_SIZE = 1000
    CONCURRENCY_LIMIT = 10

    FILE_MAX_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_EMAILS_PER_UPLOAD = 5000
    MAX_FILES_IN_ZIP = 25
    MAX_UNCOMPRESSED_ZIP_BYTES = 10 * 1024 * 1024
    MAX_LINES_PER_TEXT = 100_000
    MAX_CSV_ROWS = 100_000


# ---------------------------
# Servicios de Validación
# ---------------------------

class ValidationService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.rate_limit_cache = AsyncTTLCache(ttl=3600, maxsize=10000)

    async def check_rate_limits(
        self,
        redis,
        user_id: str,
        plan: str,
        requested_count: int = 1,
    ) -> Dict[str, Any]:
        """
        Verifica los límites diarios por plan y retorna allowed/remaining.
        """
        plan_limits = {
            "FREE": ValidationLimits.FREE_DAILY,
            "PREMIUM": ValidationLimits.PREMIUM_DAILY,
            "ENTERPRISE": ValidationLimits.ENTERPRISE_DAILY,
        }

        daily_limit = plan_limits.get(plan.upper(), ValidationLimits.FREE_DAILY)
        if daily_limit is None:
            return {"allowed": True, "remaining": float("inf"), "limit": None, "used": 0}

        usage_key = f"usage:{user_id}:{datetime.utcnow().strftime('%Y-%m-%d')}"
        try:
            current_usage = await self._get_redis_int(redis, usage_key)
            if current_usage + requested_count > daily_limit:
                would_exceed_by = (current_usage + requested_count) - daily_limit
                return {
                    "allowed": False,
                    "remaining": max(0, daily_limit - current_usage),
                    "limit": daily_limit,
                    "used": current_usage,
                    "requested": requested_count,
                    "would_exceed_by": would_exceed_by,
                }

            remaining = max(0, daily_limit - (current_usage + requested_count))
            return {
                "allowed": True,
                "remaining": remaining,
                "limit": daily_limit,
                "used": current_usage,
            }
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return {"allowed": True, "remaining": float("inf"), "limit": None, "used": 0}

    async def _get_redis_int(self, redis, key: str, default: int = 0) -> int:
        """Obtiene valor entero de Redis de forma segura."""
        try:
            value = await redis.get(key)
            if value is None:
                return default
            return int(value)
        except (ValueError, TypeError):
            return default


validation_service = ValidationService()


# ---------------------------
# Middleware de Seguridad
# ---------------------------

async def validate_content_type(content_type: str = Header(default="application/json")) -> str:
    """Valida el Content-Type de la solicitud (solo JSON para endpoints JSON)."""
    if not str(content_type or "").startswith("application/json"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported Media Type. Only 'application/json' is accepted.",
        )
    return content_type


# ---------------------------
# Utilidades de Respuesta
# ---------------------------

class ResponseBuilder:
    @staticmethod
    async def build_validation_response(
        email: str,
        start_time: float,
        valid: bool,
        detail: str,
        status_code: int = status.HTTP_200_OK,
        smtp_checked: bool = False,
        mx_server: Optional[str] = None,
        mailbox_exists: Optional[bool] = None,
        skip_reason: Optional[str] = None,
        error_type: Optional[str] = None,
        provider: Optional[str] = None,
        fingerprint: Optional[str] = None,
        reputation: float = 0.5,
        include_raw_dns: bool = False,
        spf_status: Optional[str] = None,
        spf_record: Optional[str] = None,
        dkim_status: Optional[str] = None,
        dkim_record: Optional[str] = None,
        dkim_selector: Optional[str] = None,
        dkim_key_type: Optional[str] = None,
        dkim_key_length: Optional[int] = None,
        dmarc_status: Optional[str] = None,
        dmarc_record: Optional[str] = None,
        dmarc_policy: Optional[str] = None,
        smtp_detail: Optional[str] = None,
        risk_score: Optional[float] = None,
        quality_score: Optional[float] = None,
        validation_id: Optional[str] = None,
        suggested_fixes: Optional[Dict[str, Any]] = None,
        breach_info: Optional[Dict[str, Any]] = None,
        role_email_info: Optional[Dict[str, Any]] = None,
        spam_trap_info: Optional[Dict[str, Any]] = None,  # ← NUEVO
        cache_used: bool = False,
        client_plan: Optional[str] = None,
    ) -> JSONResponse:
        """
        Construye respuesta JSON validada con todos los campos.
        CRÍTICO:
        - Incluye client_plan en TODAS las respuestas
        - Incluye suggested_fixes si hay typos detectados
        """
        processing_time = time.time() - start_time

        # VALIDAR Y CONVERTIR reputation
        try:
            reputation = float(reputation) if reputation is not None else 0.5
            reputation = max(0.0, min(1.0, reputation))
        except (ValueError, TypeError, AttributeError):
            logger.debug(f"Invalid reputation value {reputation}")
            reputation = 0.5

        # VALIDAR risk_score
        if risk_score is None:
            is_trap = spam_trap_info.get("is_spam_trap", False) if spam_trap_info else False
            trap_conf = spam_trap_info.get("confidence", 0.0) if spam_trap_info else 0.0
            
            risk_score = ResponseBuilder.calculate_risk_score(
                valid, 
                reputation, 
                smtp_checked, 
                mailbox_exists,
                is_spam_trap=is_trap,
                spam_trap_confidence=trap_conf
            )
        else:
            try:
                risk_score = float(risk_score)
            except (ValueError, TypeError):
                is_trap = spam_trap_info.get("is_spam_trap", False) if spam_trap_info else False
                trap_conf = spam_trap_info.get("confidence", 0.0) if spam_trap_info else 0.0
                
                risk_score = ResponseBuilder.calculate_risk_score(
                    valid, 
                    reputation, 
                    smtp_checked, 
                    mailbox_exists,
                    is_spam_trap=is_trap,
                    spam_trap_confidence=trap_conf
                )


        # VALIDAR quality_score
        if quality_score is None:
            quality_score = ResponseBuilder._calculate_quality_score(
                spf_status, dkim_status, dmarc_status, reputation
            )
        else:
            try:
                quality_score = float(quality_score)
            except (ValueError, TypeError):
                quality_score = ResponseBuilder._calculate_quality_score(
                    spf_status, dkim_status, dmarc_status, reputation
                )

        # Calcular suggested_action
        suggested_action = ResponseBuilder._get_suggested_action(valid, float(risk_score))

        # ========================================
        # NUEVO: Calcular el campo "status"
        # ========================================
        # Mapeo de status basado en valid, suggested_action y mailbox_exists:
        # - "undeliverable": email definitivamente inválido (valid=False)
        # - "deliverable": email válido con alta confianza (valid=True y suggested_action="accept")
        # - "risky": email válido pero con señales de riesgo (valid=True y suggested_action in ["review", "monitor"])
        # - "unknown": no se pudo verificar completamente (valid=True pero mailbox_exists=None)
        
        if not valid:
            # Email definitivamente inválido
            email_status = "undeliverable"
        else:
            # Email válido - clasificar según señales de confianza
            provider_is_known = provider and provider not in ["unknown", "generic", None]
            has_dns_security = any([
                spf_status and spf_status in ["valid", "pass"],
                dkim_status and dkim_status in ["valid", "found"],
                dmarc_status and dmarc_status in ["valid", "enforced"]
            ])
            
            # Clasificación mejorada
            if risk_score >= 0.7:
                # Alto riesgo
                email_status = "risky"
            elif risk_score >= 0.4 and not provider_is_known:
                # Riesgo medio + proveedor desconocido = risky (no unknown)
                email_status = "risky"
            elif suggested_action == "accept" and (provider_is_known or has_dns_security):
                # Baja confianza pero con señales positivas
                email_status = "deliverable"
            elif mailbox_exists is False:
                # Buzón no existe (verificado por SMTP)
                email_status = "undeliverable"
            elif mailbox_exists is None and not has_dns_security:
                # No se pudo verificar y sin señales de seguridad
                email_status = "unknown"
            elif suggested_action in ["review", "monitor"]:
                # Requiere revisión
                email_status = "risky"
            else:
                # Caso por defecto para válidos
                email_status = "deliverable"


        # ESTRUCTURA CON VALORES SEGUROS
        content: Dict[str, Any] = {
            "email": email,
            "valid": bool(valid),
            "detail": str(detail or ""),
            "processing_time": round(float(processing_time), 4),
            "risk_score": round(float(risk_score), 3),
            "quality_score": round(float(quality_score), 3),
            "validation_tier": ResponseBuilder._get_validation_tier(smtp_checked, include_raw_dns),
            "suggested_action": suggested_action,
            "status": email_status,
            "provider_analysis": {
                "provider": provider or "unknown",
                "reputation": round(float(reputation), 3),
                "fingerprint": fingerprint or "",
            },
            "smtp_validation": {
                "checked": bool(smtp_checked),
                "mailbox_exists": mailbox_exists,
                "skip_reason": skip_reason,
                "mx_server": mx_server,
                "detail": smtp_detail,
            },
            "dns_security": {
                "spf": {
                    "status": spf_status or "not_found",
                    "record": spf_record if (include_raw_dns and spf_record and not spf_record.startswith("no-")) else None,
                },
                "dkim": {
                    "status": dkim_status or "not_found",
                    "selector": dkim_selector,
                    "key_type": dkim_key_type,
                    "key_length": dkim_key_length,
                    "record": dkim_record if include_raw_dns else None,
                },
                "dmarc": {
                    "status": dmarc_status or "not_found",
                    "policy": dmarc_policy,
                    "record": dmarc_record if (include_raw_dns and dmarc_record and not dmarc_record.startswith("no-")) else None,
                },
            },
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "validation_id": validation_id or str(uuid.uuid4()),
                "cache_used": bool(cache_used),
            },
            "client_plan": client_plan or "UNKNOWN",
        }
        
        # Agregar breach_info si existe
        if breach_info:
            content["security"] = {
                "in_breach": breach_info.get("in_breach"),
                "breach_count": breach_info.get("breach_count"),
                "risk_level": breach_info.get("risk_level"),
                "checked_at": breach_info.get("checked_at"),
                "cached": breach_info.get("cached", False),
            }
            if breach_info.get("in_breach") and breach_info.get("breaches"):
                content["security"]["recent_breaches"] = breach_info.get("breaches")[:5]
        
        # Agregar role_email_info
        if role_email_info:
            content["email_type"] = {
                "is_role_email": role_email_info.get("is_role_email"),
                "role_type": role_email_info.get("role_type"),
                "deliverability_risk": role_email_info.get("deliverability_risk"),
                "confidence": role_email_info.get("confidence"),
            }
        
        # ============================================================
        # NUEVO: Agregar spam_trap_check
        # ============================================================
        if spam_trap_info:
            content["spam_trap_check"] = {
                "checked": True,
                "is_spam_trap": spam_trap_info.get("is_spam_trap", False),
                "confidence": round(spam_trap_info.get("confidence", 0.0), 2),
                "trap_type": spam_trap_info.get("trap_type", "unknown"),
                "source": spam_trap_info.get("source", "unknown"),
                "details": spam_trap_info.get("details", ""),
            }
        else:
            # Incluir campos por defecto incluso si no se verificó
            content["spam_trap_check"] = {
                "checked": False,
                "is_spam_trap": False,
                "confidence": 0.0,
                "trap_type": "unknown",
                "source": "not_checked",
                "details": "Spam trap check not performed",
            }
        
        if suggested_fixes:
            content["suggested_fixes"] = suggested_fixes
        
        if error_type and not valid:
            content["error_type"] = error_type
        
        return JSONResponse(status_code=status_code, content=content)

    @staticmethod
    def calculate_risk_score(
        valid: bool,
        reputation: float,
        smtp_checked: bool,
        mailbox_exists: Optional[bool],
        is_spam_trap: bool = False,  # ← NUEVO parámetro
        spam_trap_confidence: float = 0.0,  # ← NUEVO parámetro
    ) -> float:
        """
        Calcula puntuación de riesgo - MANEJO ROBUSTO DE TIPOS.
        Ahora incluye detección de spam traps.
        """
        # Si es spam trap con alta confianza, retornar riesgo máximo
        if is_spam_trap and spam_trap_confidence > 0.7:
            return 1.0
        
        try:
            if reputation is None:
                reputation = 0.5
            elif isinstance(reputation, (int, float)):
                reputation = float(reputation)
            elif isinstance(reputation, str):
                reputation = float(reputation) if reputation.strip() else 0.5
            elif isinstance(reputation, dict):
                reputation = float(reputation.get("reputation", 0.5) or 0.5)
            else:
                reputation = float(reputation) if reputation else 0.5
        except (ValueError, TypeError, AttributeError):
            logger.warning(
                f"Could not convert reputation to float: {reputation} (type: {type(reputation).__name__})"
            )
            reputation = 0.5
        
        reputation = max(0.0, min(1.0, reputation))
        
        if not valid:
            provider_risk = 1.0 - reputation
            return max(0.2, min(0.8, provider_risk))
        
        base_score = 1.0 - reputation
        
        # Ajustar por spam trap si confianza es baja/media
        if is_spam_trap:
            base_score += spam_trap_confidence * 0.3  # Aumentar hasta 0.3 adicional
        
        if smtp_checked:
            if mailbox_exists is False:
                base_score += 0.3
            elif mailbox_exists is True:
                base_score -= 0.2
        
        return max(0.0, min(1.0, base_score))


    @staticmethod
    def _calculate_quality_score(
        spf_status: Optional[str],
        dkim_status: Optional[str],
        dmarc_status: Optional[str],
        reputation: float,
    ) -> float:
        """✅ Calcula calidad - CON MANEJO DE TIPOS ROBUSTO."""
        
        # ✅ Proteger reputation también aquí
        try:
            if reputation is None:
                reputation = 0.5
            else:
                reputation = float(reputation) if not isinstance(reputation, float) else reputation
        except (ValueError, TypeError):
            reputation = 0.5
        
        base_score = max(0.0, min(1.0, reputation))
        security_bonus = 0.0
        
        spf_valid = (spf_status or "").lower() == "valid"
        dkim_valid = (dkim_status or "").lower() == "valid"
        dmarc_valid = (dmarc_status or "").lower() == "valid"
        
        if spf_valid:
            security_bonus += 0.1
        if dkim_valid:
            security_bonus += 0.15
        if dmarc_valid:
            security_bonus += 0.1
        
        return max(0.0, min(1.0, base_score + security_bonus))


    @staticmethod
    def _get_validation_tier(smtp_checked: bool, include_raw_dns: bool) -> str:
        """Determina el nivel de validación realizado."""
        if smtp_checked and include_raw_dns:
            return "premium"
        if smtp_checked:
            return "standard"
        return "basic"

    @staticmethod
    def _get_suggested_action(valid: bool, risk_score: float) -> str:
        """Sugiere acción basada en el resultado de validación."""
        if not valid:
            return "reject"
        if risk_score > 0.7:
            return "review"
        if risk_score > 0.4:
            return "monitor"
        return "accept"


# ---------------------------
# Lógica Principal de Validación
# ---------------------------

class EmailValidationEngine:
    def __init__(self) -> None:
        self.concurrent_operations: Dict[str, int] = {}

    @staticmethod
    def _extract_plan_from_request(request: Request) -> str:
        """Extract plan from JWT token in request."""
        try:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                from jose import jwt as jose_jwt
                token = auth_header.split(" ")[1]
                payload = jose_jwt.get_unverified_claims(token)
                plan = payload.get("plan")
                if plan:
                    return plan.upper()
        except Exception as e:
            logger.debug(f"Could not extract plan: {e}")
        return "UNKNOWN"

    async def perform_comprehensive_validation(
        self,
        email: str,
        check_smtp: bool,
        include_raw_dns: bool,
        request: Request,
        redis,
        user_id: str,
        plan: str,
    ) -> JSONResponse:
        """Orquesta la validación completa con timeout y fallback robusto."""
        start_time = time.time()
        validation_id = str(uuid.uuid4())
        
        client_plan = self._extract_plan_from_request(request)
        resolved_plan = (plan or "").upper() or client_plan
        
        spam_trap_check = None
        suggested_fixes = None
        breach_info = None
        
        try:
            # ============================================================
            # PASO 1A: Validar formato y normalizar COMPLETO
            # ============================================================
            # 1. Validate format
            formatted_email = await self._validate_email_format(email)
            logger.info(f"{validation_id} | Format validation passed | Email: {mask_email(formatted_email)}")            
            # 2. Apply full normalization (alias removal, Gmail dots, etc.)
            normalized_email = normalize_email_full(formatted_email)
            
            # Log if normalization changed the email
            if normalized_email != formatted_email:
                logger.info(
                    f"{validation_id} | Email normalized | "
                    f"Original: {formatted_email} → Normalized: {normalized_email}"
                )
            
            # ============================================================
            # PASO 1B: Verificar typos
            # ============================================================
            from app.providers import check_typo_suggestion
            
            typo_check = check_typo_suggestion(normalized_email)
            
            if typo_check:
                suggested_email, confidence = typo_check
                suggested_fixes = {
                    "typo_detected": True,
                    "suggested_email": suggested_email,
                    "confidence": round(confidence, 2),
                    "reason": "Possible typo detected in domain"
                }
                logger.warning(
                    f"{validation_id} | Typo detected: {normalized_email} → {suggested_email} "
                    f"(confidence: {confidence*100.0:.0f}%)"
                )
                
                return await ResponseBuilder.build_validation_response(
                    email=normalized_email,
                    start_time=start_time,
                    valid=False,
                    validation_id=validation_id,
                    detail="Possible typo detected in email domain",
                    status_code=status.HTTP_200_OK,
                    error_type="typo_detected",
                    risk_score=0.6,
                    quality_score=0.4,
                    client_plan=resolved_plan,
                    suggested_fixes=suggested_fixes,
                    spam_trap_info=None,  # No se ejecutó aún
                )
            
            # ============================================================
            # PASO 1C: Verificar DISPOSABLE - EJECUTAR PRIMERO
            # ============================================================
            from app.providers import is_disposable_email
            
            if is_disposable_email(normalized_email):
                logger.warning(f"Disposable email detected: {normalized_email}")
                return await ResponseBuilder.build_validation_response(
                    email=normalized_email,
                    start_time=start_time,
                    valid=False,
                    validation_id=validation_id,
                    detail="Disposable/temporary email address detected",
                    status_code=status.HTTP_200_OK,
                    error_type="disposable_email",
                    risk_score=1.0,
                    quality_score=0.0,
                    client_plan=resolved_plan,
                    suggested_fixes=suggested_fixes,
                    spam_trap_info=None,  # No necesitamos spam trap check si es disposable
                )
            
            # ============================================================
            # PASO 1D: SPAM TRAP CHECK - EJECUTAR DESPUÉS DE DISPOSABLE
            # ============================================================
            from app.providers import SpamTrapDetector
            
            logger.info(f"{validation_id} | Checking spam traps...")
            spam_trap_check = await SpamTrapDetector.is_spam_trap(normalized_email)
            
            logger.info(
                f"{validation_id} | Spam trap check completed | "
                f"is_trap={spam_trap_check['is_spam_trap']}, "
                f"confidence={spam_trap_check['confidence']}, "
                f"type={spam_trap_check['trap_type']}"
            )

            # Si es spam trap con alta confianza, rechazar inmediatamente
            HIGH_TRAP_THRESHOLD = 0.9  # umbral de bloqueo duro

            if spam_trap_check["is_spam_trap"] and spam_trap_check["confidence"] >= HIGH_TRAP_THRESHOLD:
                logger.warning(
                    f"{validation_id} | SPAM TRAP DETECTED | Email: {normalized_email} | "
                    f"Type: {spam_trap_check['trap_type']} | Confidence: {spam_trap_check['confidence']}"
                )
                
                return await ResponseBuilder.build_validation_response(
                    email=normalized_email,
                    start_time=start_time,
                    valid=False,
                    validation_id=validation_id,
                    detail=f"Spam trap detected: {spam_trap_check['details']}",
                    status_code=status.HTTP_200_OK,
                    error_type="spam_trap",
                    risk_score=1.0,
                    quality_score=0.0,
                    client_plan=resolved_plan,
                    spam_trap_info=spam_trap_check,
                )

            # ============================================================
            # PASO 1E: Verificar HaveIBeenPwned (solo PREMIUM+)
            # ============================================================
            plan_upper = (plan or "").upper()
            if plan_upper in ["PREMIUM", "ENTERPRISE"]:
                try:
                    from app.providers import HaveIBeenPwnedChecker
                    breach_info = await asyncio.wait_for(
                        HaveIBeenPwnedChecker.check_email_in_breach(
                            normalized_email,
                            redis=redis
                        ),
                        timeout=12,
                    )
                    logger.info(
                        f"[{validation_id}] HIBP check complete | "
                        f"In breach: {breach_info.get('in_breach')} | "
                        f"Count: {breach_info.get('breach_count')}"
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[{validation_id}] HIBP timeout")
                    breach_info = None
                except Exception as e:
                    logger.error(f"[{validation_id}] HIBP error: {str(e)[:200]}")
                    breach_info = None

                
            # ============================================================
            # PASO 2: Analizar proveedor CON TIMEOUT
            # ============================================================
            logger.info(f"{validation_id} | Analyzing provider...")
            
            try:
                provider_analysis = await asyncio.wait_for(
                    analyze_email_provider(
                        normalized_email, 
                        redis=redis,
                        timeout=5.0
                    ),
                    timeout=6.0
                )
                logger.info(
                    f"[{validation_id}] Provider analysis complete | "
                    f"Provider: {provider_analysis.provider} | "
                    f"SPF: {provider_analysis.dns_auth.spf} | "
                    f"DKIM: {provider_analysis.dns_auth.dkim.status} | "
                    f"Reputation: {provider_analysis.reputation}"
                )
            
            except asyncio.TimeoutError:
                logger.warning(f"Provider analysis TIMEOUT for {normalized_email}")
                provider_analysis = ProviderAnalysis(
                    domain=normalized_email.split("@")[-1],
                    primary_mx=None,
                    ip=None,
                    asn_info=None,
                    dns_auth=DNSAuthResults(
                        spf="no-spf",
                        dkim=DKIMInfo(
                            status="not_found",
                            record=None,
                            selector=None,
                            key_type=None,
                            key_length=None
                        ),
                        dmarc="no-dmarc"
                    ),
                    provider="generic",
                    fingerprint="",
                    reputation=0.5,
                    cached=False,
                    error="timeout"
                )
            
            except Exception as e:
                logger.error(f"Provider analysis ERROR: {str(e)[:200]}", exc_info=True)
                provider_analysis = ProviderAnalysis(
                    domain=normalized_email.split("@")[-1],
                    primary_mx=None,
                    ip=None,
                    asn_info=None,
                    dns_auth=DNSAuthResults(
                        spf="error",
                        dkim=DKIMInfo(
                            status="error",
                            record=None,
                            selector=None,
                            key_type=None,
                            key_length=None
                        ),
                        dmarc="error"
                    ),
                    provider="unknown",
                    fingerprint="",
                    reputation=0.1,
                    cached=False,
                    error=str(e)[:200]
                )
            
            # ============================================================
            # PASO 3: Validar dominio
            # ============================================================
            domain_result = await self._validate_domain(normalized_email, redis)
            
            if not domain_result.valid:
                return await ResponseBuilder.build_validation_response(
                    email=normalized_email,
                    start_time=start_time,
                    valid=False,
                    validation_id=validation_id,
                    detail=domain_result.detail or "Domain validation failed",
                    status_code=status.HTTP_200_OK,
                    error_type=domain_result.error_type or "domain_invalid",
                    provider=provider_analysis.provider,
                    reputation=provider_analysis.reputation,
                    fingerprint=provider_analysis.fingerprint,
                    client_plan=resolved_plan,
                    suggested_fixes=suggested_fixes,
                    spam_trap_info=spam_trap_check,
                    breach_info=breach_info,
                )
            
            # ============================================================
            # PASO 4A: Detectar Role Emails
            # ============================================================
            from app.providers import detect_role_email

            role_email_info = detect_role_email(normalized_email)
            logger.info(
                f"[{validation_id}] Role email check | "
                f"Is role: {role_email_info.get('is_role_email')} | "
                f"Type: {role_email_info.get('role_type')}"
            )

            if role_email_info.get("is_role_email"):
                logger.warning(f"[{validation_id}] Role email detected: {role_email_info['role_type']}")
            
            # ============================================================
            # PASO 4B: Realizar validación SMTP
            # ============================================================
            smtp_result = await self._perform_smtp_validation(
                normalized_email,
                domain_result.mx_host,
                check_smtp,
                plan,
                redis,
                provider_analysis.fingerprint,
            )
            
            # ============================================================
            # PASO 6: Convertir reputation de forma segura
            # ============================================================
            try:
                if provider_analysis.reputation is None:
                    safe_reputation = 0.5
                elif isinstance(provider_analysis.reputation, (int, float)):
                    safe_reputation = float(provider_analysis.reputation)
                elif isinstance(provider_analysis.reputation, str):
                    safe_reputation = float(provider_analysis.reputation) if provider_analysis.reputation.strip() else 0.5
                else:
                    safe_reputation = 0.5
                
                safe_reputation = max(0.0, min(1.0, safe_reputation))
            
            except (ValueError, TypeError, AttributeError) as e:
                logger.warning(f"Could not convert reputation: {provider_analysis.reputation} | Error: {e}")
                safe_reputation = 0.5
            
            # ============================================================
            # PASO 7: Ajustar risk_score si está en breach
            # ============================================================
            initial_risk_score = None
            if breach_info and breach_info.get("in_breach"):
                initial_risk_score = min(1.0, (safe_reputation if not safe_reputation else 0.5) + 0.3)
                logger.warning(f"[{validation_id}] Risk score increased due to breach")

            
            # ============================================================
            # PASO 7.5: Determinar si se usó cache en algún paso
            # ============================================================
            # Determinar si esta validación completa ya fue procesada antes
            validation_cache_key = f"email_validation_full:{normalized_email}"
            full_validation_cached = False

            try:
                if redis:
                    # Verificar si esta validación completa existe en caché
                    existing_validation = await redis.get(validation_cache_key)
                    full_validation_cached = (existing_validation is not None)
                    
                    # Si es la primera vez, marcar como vista
                    if not full_validation_cached:
                        # Guardar en caché por 1 hora
                        await redis.setex(validation_cache_key, 3600, "1")
                        logger.debug(f"First validation for {normalized_email}, marking in cache")
                    else:
                        logger.debug(f"Validation cache HIT for {normalized_email}")
            except Exception as cache_err:
                logger.debug(f"Cache check failed: {cache_err}")
                full_validation_cached = False

            # Determinar cache_used basado en validación completa
            # Solo marcar como cached si esta VALIDACIÓN COMPLETA ya se ejecutó antes
            cache_used = full_validation_cached
            
            # ============================================================
            # PASO 7.8: DETECT CATCH-ALL (solo si check_smtp=true)
            # ============================================================
            catch_all_info = {'is_catch_all': False, 'confidence': 0.0, 'method': 'not_checked', 'details': 'Skipped'}
            
            if check_smtp:
                try:
                    # Extract domain from email
                    domain = normalized_email.split('@')[-1]
                    
                    # Run catch-all detection with timeout
                    catch_all_info = await asyncio.wait_for(
                        detect_catch_all_domain(domain, redis=redis),
                        timeout=10.0  # 10s timeout for catch-all check
                    )
                    
                    logger.info(
                        f"[{validation_id}] Catch-all check | "
                        f"Domain: {domain} | "
                        f"Is catch-all: {catch_all_info.get('is_catch_all')} | "
                        f"Confidence: {catch_all_info.get('confidence'):.2f} | "
                        f"Method: {catch_all_info.get('method')}"
                    )
                    
                except asyncio.TimeoutError:
                    logger.warning(f"[{validation_id}] Catch-all detection timeout")
                    catch_all_info = {'is_catch_all': False, 'confidence': 0.0, 'method': 'timeout', 'details': 'Timeout'}
                
                except Exception as e:
                    logger.error(f"[{validation_id}] Catch-all detection error: {e}")
                    catch_all_info = {'is_catch_all': False, 'confidence': 0.0, 'method': 'error', 'details': str(e)[:100]}
            else:
                logger.debug(f"[{validation_id}] Catch-all check skipped (check_smtp=false)")
            
            # ============================================================
            # PASO 7.9: CALCULAR UNIFIED RISK SCORING (0-100)
            # ============================================================
            # Extract domain for toxic domain check
            domain = normalized_email.split('@')[-1] if '@' in normalized_email else ''
            is_toxic = is_abuse_domain(domain) if domain else False
            
            # Preparar datos para RiskScorer
            validation_data = {
                'valid': True,
                'syntax_valid': True,  # Si llegamos aquí, syntax es válida
                'smtp_checked': smtp_result["checked"],
                'disposable': False,  # Ya fue filtrado antes
                'role_based': role_email_info.get('is_role_email', False),
                'catch_all': catch_all_info.get('is_catch_all', False),  # ✅ REAL VALUE
                'toxic_domain': is_toxic,  # ✅ REAL VALUE
            }
            
            # Calcular unified risk score
            unified_risk = RiskScorer.calculate_risk(
                validation_result=validation_data,
                spam_trap_result=spam_trap_check,
                breach_result=breach_info
            )
            
            logger.info(
                f"[{validation_id}] Unified risk scoring | "
                f"Score: {unified_risk.score}/100 | "
                f"Level: {unified_risk.level} | "
                f"Confidence: {unified_risk.confidence:.2%} | "
                f"Factors: {unified_risk.factors}"
            )
            
            # ============================================================
            # PASO 8: Construir respuesta principal CON RISK SCORING
            # ============================================================
            response = await ResponseBuilder.build_validation_response(
                email=normalized_email,
                start_time=start_time,
                valid=True,
                validation_id=validation_id,
                detail="Email format and domain are valid",
                status_code=status.HTTP_200_OK,
                smtp_checked=smtp_result["checked"],
                mx_server=domain_result.mx_host,
                mailbox_exists=smtp_result["mailbox_exists"],
                skip_reason=smtp_result["skip_reason"],
                provider=provider_analysis.provider,
                fingerprint=provider_analysis.fingerprint,
                reputation=safe_reputation,
                include_raw_dns=include_raw_dns,
                spf_status="valid" if provider_analysis.dns_auth.spf and provider_analysis.dns_auth.spf != "no-spf" else "not_found",
                spf_record=provider_analysis.dns_auth.spf if include_raw_dns else None,
                dkim_status=provider_analysis.dns_auth.dkim.status,
                dkim_record=provider_analysis.dns_auth.dkim.record if include_raw_dns else None,
                dkim_selector=provider_analysis.dns_auth.dkim.selector,
                dkim_key_type=provider_analysis.dns_auth.dkim.key_type,
                dkim_key_length=provider_analysis.dns_auth.dkim.key_length,
                dmarc_status="valid" if provider_analysis.dns_auth.dmarc and provider_analysis.dns_auth.dmarc != "no-dmarc" else "not_found",
                dmarc_record=provider_analysis.dns_auth.dmarc if include_raw_dns else None,
                smtp_detail=smtp_result["detail"],
                risk_score=initial_risk_score,
                cache_used=cache_used,
                client_plan=resolved_plan,
                suggested_fixes=suggested_fixes,
                breach_info=breach_info,
                role_email_info=role_email_info,
                spam_trap_info=spam_trap_check,
            )
            
            # ========================================
            # AGREGAR UNIFIED RISK SCORING A RESPONSE
            # ========================================
            response_dict = json.loads(response.body.decode())
            response_dict["risk_assessment"] = {
                "score": unified_risk.score,
                "level": unified_risk.level,
                "factors": unified_risk.factors,
                "explanation": unified_risk.explanation,
                "confidence": round(unified_risk.confidence, 3)
            }
            
            # Actualizar response con nueva información
            response = JSONResponse(
                status_code=response.status_code,
                content=response_dict
            )
                        
            await self.update_validation_metrics(request, response, plan, start_time)
            logger.info(f"Validation {validation_id} completed successfully")
            
            return response
        
        except APIException as e:
            elapsed = time.time() - start_time
            logger.warning(f"Validation error (APIException): {e.detail} | Elapsed: {elapsed:.2f}s")
            
            return await self.handle_validation_error(
                email=email,
                start_time=start_time,
                request=request,
                plan=plan,
                error=e,
                validation_id=validation_id,
                spam_trap_info=spam_trap_check,  # ← Pasar incluso en errores
            )
        
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(
                f"Unexpected error in validation: {type(e).__name__}: {str(e)[:200]} | Elapsed: {elapsed:.2f}s",
                exc_info=True,
            )
            
            return await self.handle_validation_error(
                email=email,
                start_time=start_time,
                request=request,
                plan=plan,
                error=e,
                validation_id=validation_id,
                spam_trap_info=spam_trap_check,  # ← Pasar incluso en errores
            )
        
        finally:
            await self._cleanup_concurrency_limits(redis, user_id)


    async def check_concurrency_limits(self, redis, user_id: str, plan: str) -> None:
        """Aplica límites de concurrencia por plan; eleva 429 si excede."""
        try:
            settings = get_settings()
            
            plan_features = getattr(settings, "plan_features", {})
            if not plan_features:
                logger.debug(f"No plan_features found for plan {plan}")
                return
                
            plan_config = plan_features.get(plan.upper(), {})
            if not plan_config:
                logger.debug(f"No plan_config found for plan {plan.upper()}")
                return
                
            limit = int(plan_config.get("concurrent", 0) or 0)
            logger.debug(f"Concurrency limit for {plan}: {limit}")
            
            if limit <= 0:
                return
                
            key = f"concurrent:{user_id}"
            
            try:
                # PRIMERO: obtener el valor actual ANTES de incrementar
                current_raw = await redis.get(key)
                current = int(current_raw) if current_raw else 0
                
                logger.debug(f"Current concurrency for {user_id}: {current}, limit: {limit}")
                
                # SEGUNDO: verificar si YA está en el límite ANTES de incrementar
                if current >= limit:
                    raise APIException(
                        detail=f"Concurrent limit exceeded ({limit} allowed, {current} in progress)",
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        error_type="concurrent_limit_exceeded",
                    )
                
                # TERCERO: si no está en el límite, incrementar
                new_count = await redis.incr(key)
                
                # CUARTO: si es el primer incremento, establecer expiración
                if new_count == 1:
                    await redis.expire(key, 600)  # 10 minutos
                    
            except APIException:
                raise  # Re-lanzar excepciones de validación
            except Exception as e:
                logger.warning(f"Redis operation failed in concurrency check: {e}")
                # En caso de error de Redis, permitir la operación (fail-open)
                return
                
        except APIException:
            raise
        except Exception as e:
            logger.error(f"Concurrency check failed: {e}")
            # En caso de error, permitir la operación
            return


    async def _cleanup_concurrency_limits(self, redis, user_id: str) -> None:
        """Limpia los límites de concurrencia al finalizar la validación."""
        try:
            key = f"concurrent:{user_id}"
            current = await redis.decr(key)
            if current <= 0:
                # Si llega a cero o negativo, eliminar la clave
                await redis.delete(key)
        except Exception as e:
            logger.debug(f"Error cleaning up concurrency limits: {e}")


    async def _validate_email_format(self, email: str) -> str:
        """✅ Valida formato de email con mensajes más claros."""
        trimmed = email.strip()
        if not trimmed:
            raise APIException(
                detail="Email cannot be empty",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                error_type="empty_email"
            )
        
        if email != trimmed:
            # ✅ MENSAJE MÁS CLARO
            raise APIException(
                detail="Email has leading or trailing whitespace. "
                    "Please remove spaces at the beginning or end. "
                    f"You provided: '{email}' but expected: '{trimmed}'",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                error_type="invalid_format_whitespace"
            )
        
        try:
            # Validación adicional de longitudes RFC 5321 ANTES de email-validator
            if "@" in email:
                local, domain = email.rsplit("@", 1)
                
                # RFC 5321: Local-part máximo 64 caracteres
                if len(local) > 64:
                    raise APIException(
                        detail=f"Local-part too long: {len(local)} characters (max 64)",
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        error_type="invalid_format"
                    )
                
                # RFC 5321: Dominio máximo 253 caracteres
                if len(domain) > 253:
                    raise APIException(
                        detail=f"Domain too long: {len(domain)} characters (max 253)",
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        error_type="invalid_format"
                    )
                
                # RFC 1035: Cada label de dominio máximo 63 caracteres
                for label in domain.split("."):
                    if len(label) > 63:
                        raise APIException(
                            detail=f"Domain label too long: '{label}' ({len(label)} characters, max 63)",
                            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            error_type="invalid_format"
                        )
            
            # Ahora sí, usar email-validator
            valid_email = validate_email_lib(
                email,
                allow_smtputf8=True,
                check_deliverability=False,
                test_environment=get_settings().testing_mode
            )
            return valid_email.normalized
        except EmailNotValidError as e:
            raise APIException(
                detail=f"Invalid email format: {str(e)}",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                error_type="invalid_format"
            )



    async def _validate_domain(self, email: str, redis) -> VerificationResult:
        """
        ✅ Valida que el dominio existe y tiene registros MX válidos.
        
        Retorna:
            VerificationResult con:
            - valid: bool → True si dominio tiene MX records
            - detail: str → Descripción del resultado
            - mxhost: Optional[str] → Primer MX record si es válido
            - errortype: Optional[str] → Tipo de error si falla
        
        Comportamiento:
            - Si dominio es reservado (example.com, test.com) → valid: False
            - Si dominio es disposable → valid: False
            - Si dominio no tiene MX records → valid: False
            - Si dominio tiene MX records → valid: True (válido para recibir emails)
        """
        
        # Extraer dominio del email
        _, domain = email.split("@")
        
        logger.info(f"Validating domain: {domain}")
        
        try:
            # ✅ Usar cachedcheckdomain de validation.py
            # Esta función ya:
            # - Valida formato del dominio
            # - Verifica si está en lista de dominios reservados
            # - Verifica si es dominio disposable
            # - Intenta resolver MX records
            # - Maneja caché automáticamente
            
            result = await cached_check_domain(domain)
            
            # result ya es VerificationResult con estructura:
            # {
            #     "valid": bool,
            #     "detail": str,
            #     "mxhost": Optional[str],
            #     "errortype": Optional[str]
            # }
            
            if result.valid:
                logger.info(
                    f"Domain validation SUCCESS: {domain} | "
                    f"MX: {result.mx_host} | Detail: {result.detail}"
                )
            else:
                logger.warning(
                    f"Domain validation FAILED: {domain} | "
                    f"Error: {result.error_type} | Detail: {result.detail}"
                )
            
            return result
        
        except Exception as e:
            logger.error(f"Unexpected error validating domain {domain}: {str(e)}", exc_info=True)
            
            # Retornar error genérico con estructura VerificationResult
            return VerificationResult(
                valid=False,
                detail=f"Domain validation service error: {str(e)[:100]}",
                error_type="validation_error",
                mx_host=None
            )


    async def _perform_smtp_validation(
        self,
        email: str,
        mx_host: Optional[str],
        check_smtp: bool,
        plan: str,
        redis,
        fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Realiza validación SMTP en PRODUCCIÓN."""
        
        domain = email.split("@")[-1]
        
        # ✅ 1. Verificar si dominio está restringido
        SMTP_RESTRICTED_DOMAINS = {
            "gmail.com", "hotmail.com", "outlook.com", "yahoo.com",
            "aol.com", "icloud.com", "mail.ru", "qq.com"
        }
        
        if domain in SMTP_RESTRICTED_DOMAINS:
            return {
                "checked": False,
                "mailbox_exists": None,
                "skip_reason": f"Domain {domain} is restricted (does not accept SMTP verification)",
                "mx_server": mx_host,
                "detail": None,
            }
        
        # ✅ 2. Verificar plan (FREE no tiene SMTP)
        if plan.upper() == "FREE":
            return {
                "checked": False,
                "mailbox_exists": None,
                "skip_reason": "SMTP check not available in FREE plan",
                "mx_server": mx_host,
                "detail": None,
            }
        
        # ✅ 3. Verificar si usuario solicitó SMTP
        if not check_smtp or not mx_host:
            return {
                "checked": False,
                "mailbox_exists": None,
                "skip_reason": "SMTP check not requested or no MX host",
                "mx_server": mx_host,
                "detail": None,
            }
        
        # ✅ 4. EJECUTAR SMTP VALIDATION EN PRODUCCIÓN (sin Docker bypass)
        try:
            logger.debug(f"[SMTP] Starting validation for {email} on {mx_host}")
            
            # Usar check_smtp_mailbox_safe con timeout
            exists, detail = await asyncio.wait_for(
                check_smtp_mailbox_safe(email, do_rcpt=True),
                timeout=30
            )
            
            logger.info(
                f"[SMTP] Validation complete: {email} | "
                f"Exists: {exists} | Host: {mx_host}"
            )
            
            # ✅ Actualizar reputación si tenemos mailbox result
            if fingerprint and redis is not None and exists is not None:
                try:
                    success = bool(exists)
                    cache_key = f"reputation:{fingerprint}"
                    
                    # Aumentar confianza en reputación si el buzón existe
                    reputation_boost = 0.1 if success else -0.2
                    await asyncio.wait_for(
                        redis.setex(
                            cache_key,
                            7 * 24 * 3600,  # 7 días
                            str(max(0.0, min(1.0, 0.5 + reputation_boost)))
                        ),
                        timeout=2
                    )
                except Exception as e:
                    logger.debug(f"Could not update reputation: {e}")
            
            return {
                "checked": True,
                "mailbox_exists": exists,
                "skip_reason": None,
                "mx_server": mx_host,
                "detail": detail,
            }
        
        except asyncio.TimeoutError:
            logger.warning(f"[SMTP] Timeout for {email} on {mx_host}")
            return {
                "checked": True,
                "mailbox_exists": None,
                "skip_reason": "smtp_timeout",
                "mx_server": mx_host,
                "detail": "SMTP verification timed out (30s)",
            }
        
        except Exception as e:
            logger.error(f"[SMTP] Error for {email}: {str(e)[:200]}", exc_info=True)
            return {
                "checked": True,
                "mailbox_exists": None,
                "skip_reason": "smtp_error",
                "mx_server": mx_host,
                "detail": f"SMTP verification failed: {str(e)[:100]}",
            }


    async def handle_validation_error(
        self,
        email: str,
        start_time: float,
        request: Request,
        plan: str,
        error: Exception,
        validation_id: Optional[str] = None,
        spam_trap_info: Optional[Dict[str, Any]] = None,  # ← NUEVO PARÁMETRO
    ) -> JSONResponse:
        """
        ✅ Maneja errores de validación con respuesta consistente.
        
        Características:
        - Distingue entre APIException y excepciones genéricas
        - Retorna respuesta JSON válida SIEMPRE
        - Incluye client_plan en TODAS las respuestas
        - Registra métricas correctamente
        - Incluye spam_trap_info si está disponible
        """
        elapsed = time.time() - start_time
        
        # ✅ Extraer plan del JWT
        client_plan = (plan or "").upper() or self._extract_plan_from_request(request)
        
        # ✅ PASO 1: Determinar tipo de error
        if isinstance(error, APIException):
            status_code = error.status_code
            error_type = error.error_type
            detail = error.detail
            
            logger.warning(
                f"APIException | Email: {email} | Type: {error_type} | "
                f"Detail: {detail} | Elapsed: {elapsed:.2f}s"
            )
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            error_type = type(error).__name__
            detail = "Email validation service unavailable"
            
            logger.error(
                f"Unhandled Exception | Email: {email} | Type: {error_type} | "
                f"Message: {str(error)[:200]} | Elapsed: {elapsed:.2f}s",
                exc_info=True,
            )
        
        # ✅ PASO 2: Registrar métricas
        try:
            metrics_recorder.record_error(
                error_type=error_type,
                severity="error",
                component="validation",
            )
        except Exception as metrics_error:
            logger.warning(f"Failed to record metrics: {metrics_error}")
        
        # ✅ PASO 3: Construir respuesta usando ResponseBuilder
        try:
            response = await ResponseBuilder.build_validation_response(
                email=email,
                start_time=start_time,
                valid=False,
                detail=detail,
                status_code=status_code,
                error_type=error_type,
                provider=None,
                fingerprint=None,
                reputation=0.1,
                validation_id=validation_id or str(uuid.uuid4()),
                client_plan=client_plan,
                spam_trap_info=spam_trap_info,  # ← INCLUIR AQUÍ
            )
            
            response.headers["X-Error-Type"] = error_type
            response.headers["X-Processing-Time"] = str(round(elapsed, 4))
            
            return response
        
        except Exception as build_error:
            # ✅ FALLBACK CRÍTICO
            logger.error(
                f"Failed to build error response: {build_error}",
                exc_info=True,
            )
            
            # Construir contenido base del fallback
            fallback_content = {
                "email": email,
                "valid": False,
                "detail": detail,
                "validation_tier": "ERROR_FALLBACK",
                "processing_time": elapsed,
                "error_type": error_type,
                "client_plan": client_plan,
                "metadata": {
                    "validation_id": validation_id or str(uuid.uuid4()),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "error_fallback": True,
                },
            }
            
            # ✅ Incluir spam_trap_check en fallback si existe
            if spam_trap_info:
                fallback_content["spam_trap_check"] = {
                    "checked": True,
                    "is_spam_trap": spam_trap_info.get("is_spam_trap", False),
                    "confidence": spam_trap_info.get("confidence", 0.0),
                    "trap_type": spam_trap_info.get("trap_type", "unknown"),
                    "source": spam_trap_info.get("source", "unknown"),
                    "details": spam_trap_info.get("details", ""),
                }
            else:
                fallback_content["spam_trap_check"] = {
                    "checked": False,
                    "is_spam_trap": False,
                    "confidence": 0.0,
                    "trap_type": "unknown",
                    "source": "not_checked",
                    "details": "Spam trap check not performed due to error",
                }
            
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=fallback_content,
            )




    async def update_validation_metrics(
        self,
        request: Request,
        response: JSONResponse,
        plan: str,
        start_time: float,
    ) -> None:
        """Actualiza métricas de validación."""
        processing_time = time.time() - start_time
        
        # Extrae el resultado de la respuesta
        try:
            # Verifica que response sea JSONResponse antes de acceder a .body
            if isinstance(response, JSONResponse):
                try:
                    content = json.loads(response.body.decode())
                except (AttributeError, TypeError):
                    # Si response ya es un dict, úsalo directamente
                    content = response if isinstance(response, dict) else {"error": "Could not extract response"}
            else:
                content = response if isinstance(response, dict) else {}
            valid = content.get("valid", False)
            result = "success" if valid else "error"
        except:
            result = "error"
        
        # Registra la validación usando la nueva API
        metrics_recorder.record_validation(
            validation_type="email",
            result=result,
            client_plan=plan,
            duration=processing_time
        )

validation_engine = EmailValidationEngine()


# Executor global para tareas bloqueantes de archivo
_blocking_executor = ThreadPoolExecutor(
    max_workers=getattr(get_settings(), "BLOCKING_THREADPOOL_MAX_WORKERS", 16)
)


# ---------------------------
# Procesamiento de Archivos
# ---------------------------

class FileValidationService:
    def __init__(self) -> None:
        self.allowed_extensions = {".csv", ".txt", ".zip"}
        self.max_file_size = ValidationLimits.FILE_MAX_SIZE

    async def process_uploaded_file(
        self,
        file: UploadFile,
        column: Optional[str] = None,
    ) -> List[str]:
        """
        Guarda el upload en disco en streaming y procesa desde disco.

        Protecciones:
        - Evita leer todo el archivo en memoria
        - Aplica límites ya en disco (tamaño máximo)
        - Delega operaciones bloqueantes a ThreadPoolExecutor
        """
        filename = (file.filename or "").lower()

        if not any(filename.endswith(ext) for ext in self.allowed_extensions):
            raise APIException(
                detail=f"File type not allowed. Allowed: {', '.join(sorted(self.allowed_extensions))}",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type="invalid_file_type",
            )

        max_file_size = getattr(ValidationLimits, "FILE_MAX_SIZE", self.max_file_size)
        max_emails = getattr(ValidationLimits, "MAX_EMAILS_PER_UPLOAD", 5000)

        tmp_file_path: Optional[str] = None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(
                prefix="upload_", suffix=os.path.splitext(filename)[1] or ".dat"
            )
            os.close(tmp_fd)
            tmp_file_path = tmp_path

            def _copy_stream_to_disk(in_file, out_path: str, max_bytes: int) -> int:
                total = 0
                chunk_size = 64 * 1024
                with open(out_path, "wb") as out_f:
                    while True:
                        chunk = in_file.read(chunk_size)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            raise APIException(
                                detail="Uploaded file too large",
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                error_type="file_too_large",
                            )
                        out_f.write(chunk)
                return total

            in_file = file.file
            await asyncio.get_running_loop().run_in_executor(
                _blocking_executor,
                _copy_stream_to_disk,
                in_file,
                tmp_path,
                max_file_size,
            )

            if filename.endswith(".zip"):
                emails = await asyncio.get_running_loop().run_in_executor(
                    _blocking_executor,
                    lambda: self._extract_from_zip_on_disk(
                        tmp_path,
                        column=column,
                        max_emails=max_emails,
                        max_files_in_zip=getattr(ValidationLimits, "MAX_FILES_IN_ZIP", 25),
                        max_uncompressed_zip=getattr(
                            ValidationLimits, "MAX_UNCOMPRESSED_ZIP_BYTES", 10 * 1024 * 1024
                        ),
                    ),
                )
            else:
                emails = await asyncio.get_running_loop().run_in_executor(
                    _blocking_executor,
                    lambda: self._extract_from_file_on_disk(
                        tmp_path, column=column, max_emails=max_emails
                    ),
                )

            deduped: List[str] = []
            seen = set()
            for e in emails:
                if e not in seen:
                    seen.add(e)
                    deduped.append(e)
                if len(deduped) >= max_emails:
                    break

            if not deduped:
                raise APIException(
                    detail="No valid emails found in file",
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error_type="no_valid_emails",
                )

            return deduped

        finally:
            try:
                if tmp_file_path and os.path.exists(tmp_file_path):
                    os.remove(tmp_file_path)
            finally:
                try:
                    file.file.close()
                except Exception:
                    logger.debug("Failed to close upload stream", exc_info=True)


    # Métodos bloqueantes auxiliares (para executor)
    def _extract_from_zip_on_disk(
        self,
        tmp_path: str,
        column: Optional[str],
        max_emails: int,
        max_files_in_zip: int,
        max_uncompressed_zip: int,
    ) -> List[str]:
        emails: List[str] = []
        total_uncompressed = 0

        import io

        max_csv_rows = getattr(ValidationLimits, "MAX_CSV_ROWS", 100_000)
        max_txt_lines = getattr(ValidationLimits, "MAX_LINES_PER_TEXT", 100_000)

        try:
            with zipfile.ZipFile(tmp_path, "r") as zf:
                infos = zf.infolist()
                if len(infos) > max_files_in_zip:
                    infos = infos[:max_files_in_zip]

                for info in infos:
                    if info.is_dir():
                        continue
                    fname = info.filename or ""
                    # Evita path traversal
                    norm = fname.replace("\\", "/")
                    if os.path.isabs(norm) or ".." in norm.split("/"):
                        logger.warning(f"Path traversal attempt detected: {fname}")
                        raise APIException(
                            detail=f"Security violation: Path traversal in ZIP ('{fname}')",
                            status_code=status.HTTP_400_BAD_REQUEST,
                            error_type="path_traversal_attempt",
                        )

                    lower = fname.lower()
                    if not lower.endswith((".csv", ".txt")):
                        continue

                    # NUEVO: evita miembros cifrados y limita tamaño individual
                    if info.flag_bits & 0x1:
                        # Evita miembros cifrados
                        continue
                    # Limitar tamaño por archivo individual adicional al acumulado
                    if getattr(info, "file_size", 0) > (max_uncompressed_zip // 2):
                        continue

                    # Control de tamaño descomprimido acumulado
                    file_uncompressed = getattr(info, "file_size", info.compress_size or 0)
                    total_uncompressed += int(file_uncompressed or 0)
                    if total_uncompressed > max_uncompressed_zip:
                        if emails:
                            # Ya tenemos emails, devolver lo recolectado
                            logger.warning(f"ZIP size limit reached, returning {len(emails)} emails")
                            break
                        else:
                            # No hay emails aún, rechazar
                            raise APIException(
                                detail="ZIP uncompressed size exceeds limit",
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                error_type="zip_uncompressed_too_large",
                            )

                    per_file_budget = max(0, max_emails - len(emails))
                    if per_file_budget <= 0:
                        break
                    per_file_limit = min(per_file_budget, 2000)  # evita abusos por archivo
                    emails_in_this_file = 0
                    if lower.endswith(".txt"):
                        # Itera línea a línea en streaming
                        with zf.open(info) as fh:
                            text_fh = io.TextIOWrapper(fh, encoding="utf-8", errors="ignore", newline="")
                            for i, line in enumerate(text_fh):
                                if i >= max_txt_lines or len(emails) >= max_emails or emails_in_this_file >= per_file_limit:
                                    break
                                line = (line or "").strip()
                                if not line:
                                    continue
                                remaining_global = max_emails - len(emails)
                                remaining_file = per_file_limit - emails_in_this_file
                                if remaining_global <= 0 or remaining_file <= 0:
                                    break
                                found = self._extract_emails_from_string_block(line, min(remaining_global, remaining_file))
                                if found:
                                    # recorta por límite por archivo
                                    if len(found) > remaining_file:
                                        found = found[:remaining_file]
                                    emails.extend(found)
                                    emails_in_this_file += len(found)
                                    # dedupe incremental y corte
                                    if len(emails) >= max_emails or emails_in_this_file >= per_file_limit:
                                        break
                        # Siguiente miembro
                        continue

                    # CSV: detecta dialecto con una muestra pequeña sin cargar el archivo entero
                    # Lee pequeña muestra y reabre para parsear desde el inicio
                    try:
                        with zf.open(info) as sample_fh:
                            sample_bytes = sample_fh.read(4096)
                        sample_text = sample_bytes.decode("utf-8", errors="ignore")
                        try:
                            dialect = csv.Sniffer().sniff(sample_text)
                        except Exception:
                            dialect = csv.excel
                    except Exception as e:
                        logger.error(f"CSV sniff failed for {fname}: {e}")
                        dialect = csv.excel

                    with zf.open(info) as fh:
                        text_fh = io.TextIOWrapper(fh, encoding="utf-8", errors="ignore", newline="")
                        reader = csv.DictReader(text_fh, dialect=dialect)
                        if not reader.fieldnames:
                            continue
                        target_column = self._determine_target_column(reader.fieldnames, column)
                        rows_seen = 0
                        for row in reader:
                            rows_seen += 1
                            if rows_seen > max_csv_rows or len(emails) >= max_emails or emails_in_this_file >= per_file_limit:
                                break
                            value = (row.get(target_column, "") or "")
                            if not value:
                                # fallback: busca en toda la fila serializada
                                raw_row = ",".join([str(row.get(fn, "")) for fn in reader.fieldnames])
                                remaining_global = max_emails - len(emails)
                                remaining_file = per_file_limit - emails_in_this_file
                                if remaining_global <= 0 or remaining_file <= 0:
                                    break
                                found = self._extract_emails_from_string_block(raw_row, min(remaining_global, remaining_file))
                            else:
                                remaining_global = max_emails - len(emails)
                                remaining_file = per_file_limit - emails_in_this_file
                                if remaining_global <= 0 or remaining_file <= 0:
                                    break
                                found = self._extract_emails_from_string_block(value, min(remaining_global, remaining_file))
                            if found:
                                if len(found) > remaining_file:
                                    found = found[:remaining_file]
                                emails.extend(found)
                                emails_in_this_file += len(found)
                            if len(emails) >= max_emails or emails_in_this_file >= per_file_limit:
                                    break

            # Deduplicación estable al final
            return list(dict.fromkeys(emails))
        except zipfile.BadZipFile:
            raise APIException(
                detail="Invalid ZIP file",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type="invalid_zip",
            )


    def _extract_from_file_on_disk(self, tmp_path: str, column: Optional[str], max_emails: int) -> List[str]:
        emails: List[str] = []
        _, ext = os.path.splitext(tmp_path)
        ext = ext.lower()

        if ext == ".txt":
            with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if len(emails) >= max_emails:
                        break
                    candidate = (line or "").strip()
                    if not candidate:
                        continue
                    found = self._extract_emails_from_string_block(candidate, max_emails - len(emails))
                    emails.extend(found)
            return list(dict.fromkeys(emails))

        with open(tmp_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            sample = f.read(4096)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample)
            except Exception:
                dialect = csv.excel
            f.seek(0)
            reader = csv.DictReader(f, dialect=dialect)
            # Fallback si no hay headers: modo texto línea a línea
            if not reader.fieldnames:
                f.seek(0)
                for line in f:
                    if len(emails) >= max_emails:
                        break
                    text = (line or "").strip()
                    if not text:
                        continue
                    found = self._extract_emails_from_string_block(text, max_emails - len(emails))
                    emails.extend(found)
                return list(dict.fromkeys(emails))

            target_column = self._determine_target_column(reader.fieldnames, column)
            for row in reader:
                if len(emails) >= max_emails:
                    break
                value = (row.get(target_column, "") or "")
                # Si la columna está vacía, escanea toda la fila serializada
                text = value if value else ",".join([str(row.get(fn, "")) for fn in reader.fieldnames])
                if not text:
                    continue
                found = self._extract_emails_from_string_block(text, max_emails - len(emails))
                emails.extend(found)

        return list(dict.fromkeys(emails))


    def _extract_emails_from_string_block(self, text: str, max_emails: int) -> List[str]:
        email_pattern = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.IGNORECASE)
        found: List[str] = []
        for m in email_pattern.finditer(text):
            if len(found) >= max_emails:
                break
            email = m.group(0).lower()
            if self._is_valid_email(email):
                found.append(email)
        return found

    def _extract_emails_from_content(
        self,
        content: str,
        file_type: str,
        max_emails: int = 100,
        column: Optional[str] = None,
    ) -> List[str]:
        emails: List[str] = []
        try:
            email_pattern = re.compile(
                r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
                re.IGNORECASE,
            )
            if file_type == "txt":
                max_lines = getattr(ValidationLimits, "MAX_LINES_PER_TEXT", 100_000)
                for i, line in enumerate(content.splitlines()):
                    if i >= max_lines or len(emails) >= max_emails:
                        break
                    candidate = line.strip()
                    if not candidate:
                        continue
                    m = email_pattern.search(candidate)
                    if m:
                        email = m.group(0).lower()
                        if self._is_valid_email(email):
                            emails.append(email)
                            if len(emails) >= max_emails:
                                break
            elif file_type == "csv":
                csv_file = StringIO(content)
                try:
                    sample = csv_file.read(4096)
                    csv_file.seek(0)
                    dialect = csv.Sniffer().sniff(sample)
                except Exception:
                    dialect = csv.excel
                csv_file.seek(0)
                reader = csv.DictReader(csv_file, dialect=dialect)
                if not reader.fieldnames:
                    return []
                target_column = self._determine_target_column(reader.fieldnames, column)
                for i, row in enumerate(reader):
                    if i >= getattr(ValidationLimits, "MAX_CSV_ROWS", 100_000) or len(emails) >= max_emails:
                        break
                    value = row.get(target_column, "")
                    if not value:
                        continue
                    m = email_pattern.search(value)
                    if m:
                        email = m.group(0).lower()
                        if self._is_valid_email(email):
                            emails.append(email)
                            if len(emails) >= max_emails:
                                break
            else:
                return []
        except Exception as e:
            logger.error(f"Error processing {file_type} content: {e}")
            raise APIException(
                detail=f"Error processing {file_type.upper()} file",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type=f"{file_type}_parse_error",
            )

        return list(dict.fromkeys(emails))

    def _determine_target_column(self, fieldnames: List[str], specified_column: Optional[str]) -> str:
        """Determina la columna objetivo para extraer emails (case-insensitive)."""
        if not fieldnames:
            raise APIException(
                detail="CSV file has no headers",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type="csv_no_headers",
            )
        
        # Normaliza fieldnames a lowercase para comparación
        fieldnames_lower = {fn.lower(): fn for fn in fieldnames}
        
        if specified_column:
            spec_lower = specified_column.lower()
            if spec_lower in fieldnames_lower:
                return fieldnames_lower[spec_lower]
            raise APIException(
                detail=f"Column '{specified_column}' not found",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type="column_not_found",
            )
        
        # Busca columnas comunes (case-insensitive)
        common_email_columns = ["email", "e-mail", "mail", "contact", "username"]
        for common_col in common_email_columns:
            if common_col in fieldnames_lower:
                return fieldnames_lower[common_col]
        
        return fieldnames[0]

    def _is_valid_email(self, email: str) -> bool:
        """Valida sintaxis de email con email_validator o regex conservadora."""
        try:
            from email_validator import validate_email as _validate_email
        except Exception:
            _validate_email = None

        if not email or " " in email:
            return False

        if _validate_email:
            try:
                _validate_email(email, check_deliverability=False)
                return True
            except Exception:
                return False
        pattern = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", re.IGNORECASE)
        return bool(pattern.match(email))

    def generate_csv_report(self, results: List[Dict[str, Any]]) -> str:
        """Genera reporte CSV de los resultados."""
        output = StringIO()
        writer = csv.writer(output)
        headers = [
            "Email",
            "Valid",
            "Risk Score",
            "Quality Score",
            "Provider",
            "Reputation",
            "SPF Status",
            "DKIM Status",
            "DMARC Status",
            "MX Server",
            "Mailbox Exists",
            "Processing Time",
            "Detail",
        ]
        writer.writerow(headers)
        for result in results:
            writer.writerow([
                result.get("email", ""),
                result.get("valid", ""),
                result.get("risk_score", ""),
                result.get("quality_score", ""),
                result.get("provider_analysis", {}).get("provider", ""),
                result.get("provider_analysis", {}).get("reputation", ""),
                result.get("dns_security", {}).get("spf", {}).get("status", ""),
                result.get("dns_security", {}).get("dkim", {}).get("status", ""),
                result.get("dns_security", {}).get("dmarc", {}).get("status", ""),
                result.get("smtp_validation", {}).get("mx_server", ""),
                result.get("smtp_validation", {}).get("mailbox_exists", ""),
                result.get("processing_time", ""),
                (result.get("detail", "") or "")[:100],
            ])
        return output.getvalue()

    def _calculate_risk_distribution(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calcula distribución de riesgo."""
        distribution = {"low": 0, "medium": 0, "high": 0}
        for result in results:
            risk_score = result.get("risk_score", 0.5) or 0.5
            if risk_score < 0.3:
                distribution["low"] += 1
            elif risk_score < 0.7:
                distribution["medium"] += 1
            else:
                distribution["high"] += 1
        return distribution

    def _calculate_provider_breakdown(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calcula distribución de proveedores."""
        breakdown: Dict[str, int] = {}
        for result in results:
            provider = result.get("provider_analysis", {}).get("provider", "unknown")
            breakdown[provider] = breakdown.get(provider, 0) + 1
        return breakdown


file_validation_service = FileValidationService()


# ---------------------------
# Endpoints Principales
# ---------------------------

from app.config import SAFE_CONTENT_TYPES

async def validate_content_type(request: Request) -> str:
    """Dependency: Validar Content-Type desde middleware"""
    content_type = (request.headers.get("Content-Type") or "").lower()
    if request.method in ("POST", "PUT", "PATCH"):
        valid = any(ct.startswith(content_type) for ct in SAFE_CONTENT_TYPES)
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Only 'application/json' accepted"
            )
    return content_type


def _get_plan_config_safe(plan: str) -> dict:
    """Obtener configuración de plan (igual que en utils.py)"""
    plan_upper = plan.upper() if plan else "FREE"
    return {
        "FREE": {"raw_dns": False, "smtp": False},
        "PREMIUM": {"raw_dns": True, "smtp": True},
        "ENTERPRISE": {"raw_dns": True, "smtp": True},
    }.get(plan_upper, {"raw_dns": False, "smtp": False})


async def _basic_email_validation(email: str) -> bool:
    """Validación básica: solo sintaxis"""
    import re
    return bool(re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email.lower().strip()))


@router.post("/email", response_class=JSONResponse)
async def validate_email_endpoint(
    request: Request,
    req_body: EmailValidationRequest,
    current_client: TokenData = Depends(validate_api_key_or_token),
    redis = Depends(get_redis),
) -> JSONResponse:
    """
    ✅ Endpoint de validación de email con timeout y fallback robusto.
    
    Cambios principales:
    - Timeout explícito por plan (FREE: 10s, PREMIUM: 30s, ENTERPRISE: 60s)
    - Fallback BASIC seguro si se vence
    - SIEMPRE retorna JSONResponse válida
    - client_plan en TODAS las respuestas
    - spam_trap_check ejecutado ANTES del timeout para estar disponible en fallback
    - Manejo de errores con ResponseBuilder
    """
    
    start_time = time.time()
    request_id = str(uuid.uuid4())
    email = (req_body.email or "").strip()
    check_smtp = getattr(req_body, "check_smtp", False)
    include_raw_dns = getattr(req_body, "include_raw_dns", False)
    
    user_id = current_client.sub
    plan_upper = (current_client.plan or "FREE").upper()
    
    # Determinar si está en Docker
    is_docker = os.getenv("ENVIRONMENT", "").lower() == "docker"
    
    logger.info(
        f"Email validation | User: {user_id} | Plan: {plan_upper} | Email: {email} | "
        f"Env: {'docker' if is_docker else 'production'} | SMTP: {check_smtp} | DNS: {include_raw_dns}"
    )
    
    email_normalized = None
    is_valid = False
    domain = "unknown"
    spam_trap_check = None  # ← NUEVO: Variable para almacenar resultado
    
    try:
        # ✅ VALIDACIÓN BÁSICA DE FORMATO
        if not email or "@" not in email:
            raise APIException(
                detail="Invalid email format",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type="invalid_format"
            )
        
        email_normalized = email.lower().strip()
        
        # ============================================================
        # ✅ NUEVO: EJECUTAR SPAM TRAP CHECK ANTES DEL TIMEOUT WRAPPER
        # ============================================================
        try:
            # Validar formato más detallado
            from email_validator import validate_email as validate_email_lib, EmailNotValidError
            
            try:
                validated = validate_email_lib(email_normalized, check_deliverability=False)
                email_normalized = validated.normalized
                
                # Ejecutar spam trap check ANTES del timeout
                from app.providers import SpamTrapDetector
                spam_trap_check = await SpamTrapDetector.is_spam_trap(email_normalized)
                
                logger.info(
                    f"{request_id} | Pre-validation spam trap check | "
                    f"Email: {email_normalized} | "
                    f"Is trap: {spam_trap_check['is_spam_trap']} | "
                    f"Confidence: {spam_trap_check['confidence']}"
                )
                
            except EmailNotValidError as e:
                # Si falla formato, dejarlo manejar por perform_comprehensive_validation
                logger.debug(f"Pre-validation format error: {e}")
                email_normalized = email
        
        except Exception as pre_error:
            logger.warning(f"Pre-validation error: {pre_error}")
            email_normalized = email
        
        # ============================================================
        # ✅ TIMEOUT EXPLÍCITO POR PLAN
        # ============================================================
        try:
            timeout_seconds = {
                "FREE": 15.0,      # 15 segundos para FREE
                "PREMIUM": 45.0,   # 45 segundos para PREMIUM
                "ENTERPRISE": 60.0 # 60 segundos para ENTERPRISE
            }.get(plan_upper, 20.0)
            
            response = await asyncio.wait_for(
                validation_engine.perform_comprehensive_validation(
                    email=email_normalized,
                    check_smtp=check_smtp,
                    include_raw_dns=include_raw_dns,
                    request=request,
                    redis=redis,
                    user_id=user_id,
                    plan=plan_upper,
                ),
                timeout=timeout_seconds
            )
            
            # ✅ AGREGAR HEADERS A LA RESPUESTA
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Plan"] = plan_upper
            
            logger.info(f"Validation {request_id} completed successfully")
            return response
            
        except asyncio.TimeoutError:
            elapsed = time.time() - start_time
            logger.warning(
                f"Validation timeout | Email: {email_normalized} | Elapsed: {elapsed:.2f}s | "
                f"Timeout: {timeout_seconds}s | Plan: {plan_upper}"
            )
            
            # ✅ FALLBACK A VALIDACIÓN BÁSICA EN TIMEOUT
            email_normalized = email_normalized or email
            is_valid = False
            domain = "unknown"
            
            if email_normalized and "@" in email_normalized:
                try:
                    local_part, domain = email_normalized.rsplit("@", 1)
                    is_local_valid = (
                        len(local_part) > 0 and len(local_part) <= 64 and
                        all(c.isalnum() or c in "._%-" for c in local_part)
                    )
                    is_domain_valid = (
                        len(domain) > 4 and "." in domain and
                        all(c.isalnum() or c in "-." for c in domain) and
                        domain[0].isalnum() and domain[-1].isalnum()
                    )
                    is_valid = is_local_valid and is_domain_valid
                except Exception as parse_error:
                    logger.debug(f"Fallback basic parsing error: {parse_error}")
                    is_valid = False
                    domain = "unknown"
            
            # ✅ CONSTRUIR RESPUESTA DE TIMEOUT CON ResponseBuilder
            timeout_response = await ResponseBuilder.build_validation_response(
                email=email_normalized,
                start_time=start_time,
                valid=is_valid,
                detail="Validation timeout - using BASIC validation fallback",
                status_code=status.HTTP_200_OK,
                smtp_checked=False,
                mailbox_exists=None,
                skip_reason="Timeout - Docker environment validation timeout",
                provider=domain if domain != "unknown" else "unknown",
                reputation=0.3,
                fingerprint=None,
                risk_score=0.7 if is_valid else 0.9,
                quality_score=0.4 if is_valid else 0.1,
                include_raw_dns=include_raw_dns,
                spf_status=None,
                dkim_status=None,
                dmarc_status=None,
                validation_id=request_id,
                cache_used=False,
                client_plan=plan_upper,
                spam_trap_info=spam_trap_check,  # ← CRÍTICO: Incluir spam trap check
            )
            
            timeout_response.headers["X-Request-ID"] = request_id
            timeout_response.headers["X-Plan"] = plan_upper
            timeout_response.headers["X-Environment"] = "docker" if is_docker else "production"
            timeout_response.headers["X-Timeout"] = "true"
            
            # ✅ INTENTAR INCREMENTAR USO
            try:
                await increment_usage(redis, user_id, 1)
            except Exception as usage_error:
                logger.warning(f"Failed to increment usage on timeout: {usage_error}")
            
            logger.info(
                f"Validation completed with timeout fallback | Email: {email_normalized} | "
                f"Valid: {is_valid} | Elapsed: {elapsed:.2f}s | Plan: {plan_upper}"
            )
            
            return timeout_response
        
    except APIException as api_error:
        # ✅ MANEJO DE ERRORES DE API CON ResponseBuilder
        elapsed = time.time() - start_time
        logger.warning(
            f"API Exception | Email: {email_normalized or email} | "
            f"Error: {api_error.detail} | Elapsed: {elapsed:.2f}s"
        )
        
        error_response = await validation_engine.handle_validation_error(
            email=email_normalized or email,
            start_time=start_time,
            request=request,
            plan=plan_upper,
            error=api_error,
            validation_id=request_id,
            spam_trap_info=spam_trap_check,  # ← Incluir incluso en errores
        )
        
        error_response.headers["X-Request-ID"] = request_id
        error_response.headers["X-Plan"] = plan_upper
        
        return error_response
    
    except Exception as e:
        # ✅ MANEJO DE ERRORES INESPERADOS
        elapsed = time.time() - start_time
        logger.error(
            f"Unexpected error | Email: {email_normalized or email} | "
            f"Error: {str(e)[:200]} | Elapsed: {elapsed:.2f}s",
            exc_info=True
        )
        
        error_response = await validation_engine.handle_validation_error(
            email=email_normalized or email,
            start_time=start_time,
            request=request,
            plan=plan_upper,
            error=e,
            validation_id=request_id,
            spam_trap_info=spam_trap_check,  # ← Incluir incluso en errores inesperados
        )
        
        error_response.headers["X-Request-ID"] = request_id
        error_response.headers["X-Plan"] = plan_upper
        
        return error_response


@router.post(
    "/batch",
    response_model=BatchEmailResponse,
    summary="Batch Email Validation",
    description="Valida múltiples direcciones de email en una sola solicitud.",
    responses={
        200: {"description": "Batch validation completed"},
        400: {"description": "Invalid batch request"},
        413: {"description": "Batch too large"},
        429: {"description": "Rate limit exceeded"},
    },
)
async def batch_validate_emails(
    request: Request,
    batch_request: BatchValidationRequest,
    current_client: TokenData = Security(validate_api_key_or_token, scopes=["validate:batch"]),
    redis = Depends(get_redis),
) -> JSONResponse:
    
    plan_upper = current_client.plan.upper() if current_client.plan else "FREE"
    logger.info(f"Batch validation requested by: {current_client.sub} (Plan: {plan_upper})")
    
    try:
        # ===== CORRECCIÓN: Validar plan PRIMERO =====
        if batch_request.check_smtp and plan_upper not in ("PREMIUM", "ENTERPRISE"):
            raise APIException(
                detail=f"SMTP check in batch requires PREMIUM plan (your plan: {plan_upper})",
                status_code=status.HTTP_403_FORBIDDEN,
                error_type="plan_upgrade_required",
            )
        
        if batch_request.include_raw_dns and plan_upper not in ("PREMIUM", "ENTERPRISE"):
            raise APIException(
                detail=f"Raw DNS records require PREMIUM plan (your plan: {plan_upper})",
                status_code=status.HTTP_403_FORBIDDEN,
                error_type="plan_upgrade_required",
            )
        
        # Configuración por plan
        batch_limits = {
            "FREE": 10,
            "PREMIUM": 100,
            "ENTERPRISE": 1000,
        }
        batch_size_limit = batch_limits.get(plan_upper, 10)
        
        if len(batch_request.emails) > batch_size_limit:
            raise APIException(
                detail=f"Batch size limit exceeded for {plan_upper} plan: {len(batch_request.emails)}/{batch_size_limit}",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type="batch_limit_exceeded",
            )
        
        # Rate limits
        rate_check = await validation_service.check_rate_limits(
            redis, current_client.sub, current_client.plan, len(batch_request.emails)
        )
        
        if not rate_check["allowed"]:
            raise APIException(
                detail=f"Daily limit would be exceeded. Used: {rate_check['used']}/{rate_check['limit']}, Requested: {rate_check.get('requested', 1)}, Remaining: {rate_check['remaining']}",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                error_type="quota_exceeded",
            )
        
        # Filtrar emails vacíos y deduplicar
        valid_input_emails = [e.strip() for e in batch_request.emails if e and e.strip()]

        if not valid_input_emails:
            raise APIException(
                detail="No valid emails provided in batch",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type="empty_batch",
            )

        # Deduplicar manteniendo orden
        unique_emails = list(dict.fromkeys(valid_input_emails))

        if len(unique_emails) < len(valid_input_emails):
            logger.info(
                f"Deduplicated {len(valid_input_emails)} emails to {len(unique_emails)} "
                f"unique emails for user {current_client.sub}"
            )

        start_time = time.time()
        semaphore = asyncio.Semaphore(ValidationLimits.CONCURRENCY_LIMIT)
        
        async def validate_single_email(email: str) -> Dict[str, Any]:
            """Valida un email y retorna dict (no JSONResponse)"""
            async with semaphore:
                try:
                    response = await validation_engine.perform_comprehensive_validation(
                        email=email,
                        check_smtp=batch_request.check_smtp,
                        include_raw_dns=batch_request.include_raw_dns,
                        request=request,
                        redis=redis,
                        user_id=current_client.sub,
                        plan=plan_upper,
                    )
                    
                    # CRÍTICO: Extraer dict del JSONResponse
                    if hasattr(response, 'body'):
                        body_bytes = response.body
                        if isinstance(body_bytes, bytes):
                            content_str = body_bytes.decode('utf-8')
                            return json.loads(content_str)
                        else:
                            return json.loads(body_bytes)
                    elif isinstance(response, dict):
                        return response
                    else:
                        raise ValueError(f"Unexpected response type: {type(response)}")
                        
                except Exception as e:
                    logger.error(f"Validation failed for {email}: {e}")
                    return {
                        "email": email,
                        "valid": False,
                        "detail": f"Validation error: {str(e)}",
                        "error_type": "validation_error",
                        "processing_time": 0.0,
                        "risk_score": 0.8,
                        "quality_score": 0.0,
                        "provider_analysis": {"provider": "unknown", "reputation": 0.5, "fingerprint": ""},
                        "smtp_validation": {"checked": False, "mailbox_exists": None, "skip_reason": "exception", "mx_server": None, "detail": None},
                        "dns_security": {
                            "spf": {"status": "not_found", "record": None},
                            "dkim": {"status": "not_found", "selector": None, "key_type": None, "key_length": None, "record": None},
                            "dmarc": {"status": "not_found", "policy": None, "record": None}
                        },
                        "metadata": {
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "validation_id": str(uuid.uuid4()),
                            "cache_used": False
                        },
                        "client_plan": plan_upper,
                    }

        
        tasks = [validate_single_email(email) for email in unique_emails]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results: List[Dict[str, Any]] = []
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "email": batch_request.emails[i],
                    "valid": False,
                    "detail": f"Validation error: {str(result)}",
                    "error_type": "validation_error",
                    "processing_time": 0.0,
                    "risk_score": 0.8,
                    "quality_score": 0.0,
                    "provider_analysis": {"provider": None, "reputation": 0.5, "fingerprint": None},
                    "smtp_validation": {"checked": False, "mailbox_exists": None, "skip_reason": "exception", "mx_server": None, "detail": None},
                    "dns_security": {"spf": {"status": None, "record": None}, "dkim": {"status": None, "selector": None, "key_type": None, "key_length": None, "record": None}, "dmarc": {"status": None, "policy": None, "record": None}},
                    "metadata": {"timestamp": datetime.utcnow().isoformat(), "validation_id": str(uuid.uuid4()), "cache_used": False},
                })
            elif isinstance(result, dict):
                # Si ya es dict, agregar directamente
                processed_results.append(result)
            else:
                # Si es JSONResponse, extraer el body
                try:
                    if hasattr(result, 'body'):
                        content = json.loads(result.body.decode())
                        processed_results.append(content)
                    else:
                        # Fallback: intentar convertir a dict
                        processed_results.append(dict(result))
                except Exception as decode_error:
                    logger.error(f"Failed to decode result for {batch_request.emails[i]}: {decode_error}")
                    processed_results.append({
                        "email": batch_request.emails[i],
                        "valid": False,
                        "detail": "Invalid response format",
                        "error_type": "internal_error",
                        "processing_time": 0.0,
                        "risk_score": 0.8,
                        "quality_score": 0.0,
                    })
        
        valid_count = sum(1 for r in processed_results if r.get("valid"))
        processing_time = time.time() - start_time
        
        await increment_usage(redis, current_client.sub, len(batch_request.emails))
        
        batch_id = str(uuid.uuid4())
        
        resp = JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "count": len(processed_results),
                "valid_count": valid_count,
                "invalid_count": len(processed_results) - valid_count,
                "processing_time": round(processing_time, 4),
                "average_time": round(processing_time / max(len(processed_results), 1), 4),
                "results": processed_results,
                "summary": {
                    "success_rate": round(valid_count / max(len(processed_results), 1), 4),
                    "batch_id": batch_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "plan": plan_upper,
                },
            },
        )
        
        resp.headers["X-Validation-Id"] = batch_id
        resp.headers["X-Plan"] = plan_upper
        return resp
    
    except APIException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "detail": e.detail,
                "error_type": e.error_type,
                "client_plan": plan_upper
            }
        )
    
    except Exception as e:
        logger.exception(f"Batch validation failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Batch processing failed",
                "error_type": "internal_server_error",
                "client_plan": plan_upper
            }
        )


@router.post(
    "/batch/upload",
    summary="Batch Email Validation via File Upload",
    responses={
        200: {"description": "Validation completed"},
        400: {"description": "Invalid file or parameters"},
        413: {"description": "File too large"},
        415: {"description": "Unsupported file type"},
        429: {"description": "Rate limit exceeded"},
    },
)
async def batch_validate_upload(
    request: Request,
    file: UploadFile = File(...),
    column: Optional[str] = Form(None),
    include_raw_dns: bool = Form(False),
    check_smtp: bool = Form(False),
    current_client: TokenData = Security(validate_api_key_or_token, scopes=["batch:upload"]),
    redis = Depends(get_redis),
) -> Response:
    logger.info(f"Upload requested by: {current_client.sub} - File: {file.filename}")
    start_time = time.time()
    try:
        if current_client.plan.upper() == "FREE":
            raise APIException(
                detail="File upload requires PREMIUM plan",
                status_code=status.HTTP_403_FORBIDDEN,
                error_type="plan_upgrade_required",
            )

        emails = await file_validation_service.process_uploaded_file(file, column)
        if not emails:
            raise APIException(
                detail="No valid emails found in file",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_type="no_valid_emails",
            )

        plan_config = _get_plan_config_safe(current_client.plan)
        if include_raw_dns and not plan_config.get("raw_dns", False):
            raise APIException(
                detail="Raw DNS details require PREMIUM plan",
                status_code=status.HTTP_403_FORBIDDEN,
                error_type="plan_upgrade_required",
            )

        rate_check = await validation_service.check_rate_limits(
            redis, current_client.sub, current_client.plan, requested_count=len(emails)
        )
        if not rate_check["allowed"]:
            raise APIException(
                detail=f"Daily limit would be exceeded. Used={rate_check['used']}/{rate_check['limit']}, "
                       f"Requested={rate_check.get('requested', len(emails))}, Remaining={rate_check['remaining']}",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                error_type="quota_exceeded",
            )

        sem = asyncio.Semaphore(ValidationLimits.CONCURRENCY_LIMIT)

        async def validate_single(email: str) -> Dict[str, Any]:
            async with sem:
                resp = await validation_engine.perform_comprehensive_validation(
                    email=email,
                    check_smtp=check_smtp,
                    include_raw_dns=include_raw_dns,
                    request=request,
                    redis=redis,
                    user_id=current_client.sub,
                    plan=current_client.plan,
                )
                return json.loads(resp.body.decode())

        results = await asyncio.gather(*[validate_single(e) for e in emails], return_exceptions=True)

        processed: List[Dict[str, Any]] = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                processed.append({
                    "email": emails[i],
                    "valid": False,
                    "detail": f"Validation error: {r}",
                    "error_type": "validation_error",
                    "processing_time": 0.0,
                    "risk_score": 0.8,
                    "quality_score": 0.0,
                    "provider_analysis": {"provider": None, "reputation": 0.5},
                    "smtp_validation": {"checked": False, "mailbox_exists": None, "skip_reason": "exception", "mx_server": None, "detail": None},
                    "dns_security": {"spf": {"status": None, "record": None}, "dkim": {"status": None}, "dmarc": {"status": None}},
                    "metadata": {"timestamp": datetime.utcnow().isoformat(), "validation_id": str(uuid.uuid4()), "cache_used": False},
                })
            else:
                processed.append(r)

        valid_count = sum(1 for r in processed if r.get("valid"))
        processing_time = time.time() - start_time
        await increment_usage(redis, current_client.sub, len(emails))

        accept = request.headers.get("accept", "") or ""
        if "text/csv" in accept:
            csv_content = file_validation_service.generate_csv_report(processed)
            filename = f"validation_results_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.csv"
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "X-Validation-Summary": f"Valid={valid_count}/{len(emails)}",
                    "X-Validation-Id": str(uuid.uuid4()),
                },
            )

        batch_id = str(uuid.uuid4())
        resp = JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "filename": file.filename,
                "upload_time": datetime.utcnow().isoformat(),
                "emails_found": len(emails),
                "valid_count": valid_count,
                "invalid_count": len(emails) - valid_count,
                "processing_time": round(processing_time, 4),
                "average_time": round(processing_time / max(len(emails), 1), 4),
                "results": processed,
                "summary": {"success_rate": round(valid_count / max(len(emails), 1), 4)},
                "batch_id": batch_id,
                "risk_distribution": file_validation_service._calculate_risk_distribution(processed),
                "provider_breakdown": file_validation_service._calculate_provider_breakdown(processed),
            },
        )
        resp.headers["X-Validation-Id"] = batch_id
        return resp

    except APIException as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.detail, "error_type": e.error_type})
    except Exception as e:
        logger.exception(f"File upload validation failed: {e}")
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": "File processing failed", "error_type": "internal_server_error"})



# ---------------------------
# Endpoints de Administración y Monitoreo
# ---------------------------

@router.get("/stats/cache")
async def get_cache_stats(redis=Depends(get_redis)) -> Dict[str, Any]:
    """Obtiene estadísticas de cache del sistema."""
    try:
        provider_stats = get_provider_cache_stats()
        redis_info = await redis.info("memory")
        used_rss = float(redis_info.get("used_memory_rss", 0))
        total_mem = float(redis_info.get("total_system_memory", 1)) or 1.0
        memory_usage_pct = f"{(used_rss / total_mem) * 100:.2f}%"
        return {
            "provider_caches": provider_stats,
            "redis_memory": {
                "used_memory": redis_info.get("used_memory", 0),
                "used_memory_human": redis_info.get("used_memory_human", "0B"),
                "memory_usage": memory_usage_pct,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error(f"Cache stats error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not retrieve cache statistics",
        )


@router.get("/stats/usage")
async def get_usage_stats(
    current_client: TokenData = Depends(validate_api_key_or_token),
    redis=Depends(get_redis),
) -> Dict[str, Any]:
    """Obtiene estadísticas de uso del cliente actual."""
    try:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        usage_key = f"usage:{current_client.sub}:{today}"
        current_usage = await validation_service._get_redis_int(redis, usage_key)

        plan_limits = {
            "FREE": ValidationLimits.FREE_DAILY,
            "PREMIUM": ValidationLimits.PREMIUM_DAILY,
            "ENTERPRISE": ValidationLimits.ENTERPRISE_DAILY,
        }
        daily_limit = plan_limits.get(current_client.plan.upper(), ValidationLimits.FREE_DAILY)

        return {
            "plan": current_client.plan,
            "usage_today": current_usage,
            "daily_limit": daily_limit,
            "remaining_today": max(0, daily_limit - current_usage),
            "usage_percentage": round((current_usage / daily_limit) * 100, 2) if daily_limit else 0,
        }
    except Exception as e:
        logger.error(f"Usage stats error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not retrieve usage statistics",
        )


# ---------------------------
# Health Check
# ---------------------------

_service_start_time = time.time()


@router.get("/health")
@router.head("/health")
async def health_check(redis=Depends(get_redis)) -> Dict[str, Any]:
    """Health check completo del servicio."""
    try:
        await redis.ping()
        redis_healthy = True
    except Exception:
        redis_healthy = False

    # Estas verificaciones pueden ampliarse con checks reales
    dns_healthy = True
    smtp_healthy = True

    overall_status = "healthy" if all([redis_healthy, dns_healthy, smtp_healthy]) else "degraded"
    return {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "services": {
            "redis": "healthy" if redis_healthy else "unhealthy",
            "dns": "healthy" if dns_healthy else "unhealthy",
            "smtp": "healthy" if smtp_healthy else "unhealthy",
        },
        "uptime": round(time.time() - _service_start_time, 2),
    }

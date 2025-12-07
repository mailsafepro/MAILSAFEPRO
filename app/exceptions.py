"""
exceptions.py - Enterprise exception handling system

Provides:
- RFC 7807 Problem Details for HTTP APIs
- Structured error responses
- Automatic metrics recording
- Comprehensive error logging
- Correlation ID tracking
- Client plan detection
"""

from __future__ import annotations

import traceback
import json
from typing import Optional, Dict, Any

from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field

from app.config import settings
from app.logger import logger
from app.metrics import metrics_recorder
from app.utils import get_user_plan_safe


# =============================================================================
# EXCEPTION MODELS (RFC 7807 Problem Details)
# =============================================================================

class ProblemDetail(BaseModel):
    """
    RFC 7807 Problem Details for HTTP APIs.
    
    Provides machine-readable error information in a standardized format.
    """
    type: str = Field(..., description="URI reference identifying the problem type")
    title: str = Field(..., description="Short, human-readable summary")
    status: int = Field(..., description="HTTP status code")
    detail: str = Field(..., description="Human-readable explanation")
    instance: str = Field(..., description="URI reference identifying specific occurrence")
    trace_id: Optional[str] = Field(None, description="Correlation ID for request tracking")
    timestamp: Optional[str] = Field(None, description="Error timestamp")
    
    # Extensions (optional)
    errors: Optional[list] = Field(None, description="Validation error details")
    client_plan: Optional[str] = Field(None, description="Client subscription plan")


# Alias for backward compatibility
APIError = ProblemDetail


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class APIException(Exception):
    """
    Base exception for all API errors.
    
    Features:
    - Structured error information
    - HTTP status code mapping
    - Custom headers support
    - Automatic metrics tracking
    """
    
    def __init__(
        self,
        *,
        error_type: str = "about:blank",
        title: str = "API Error",
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        headers: Optional[Dict[str, str]] = None,
        extensions: Optional[Dict[str, Any]] = None
    ):
        self.error_type = error_type
        self.title = title
        self.detail = detail
        self.status_code = status_code
        self.headers = headers or {}
        self.extensions = extensions or {}
        
        super().__init__(detail)
    
    def to_problem_detail(
        self,
        instance: str,
        trace_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        **kwargs
    ) -> ProblemDetail:
        """Convert exception to RFC 7807 Problem Detail."""
        return ProblemDetail(
            type=self.error_type,
            title=self.title,
            status=self.status_code,
            detail=self.detail,
            instance=instance,
            trace_id=trace_id,
            timestamp=timestamp,
            **self.extensions,
            **kwargs
        )


class ValidationException(APIException):
    """Raised when request validation fails."""
    
    def __init__(self, detail: str, errors: Optional[list] = None):
        super().__init__(
            error_type="validation_error",
            title="Request Validation Failed",
            detail=detail,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            extensions={"errors": errors} if errors else {}
        )


class AuthenticationException(APIException):
    """Raised when authentication fails."""
    
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(
            error_type="authentication_error",
            title="Authentication Failed",
            detail=detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"}
        )


class AuthorizationException(APIException):
    """Raised when authorization fails."""
    
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            error_type="authorization_error",
            title="Authorization Failed",
            detail=detail,
            status_code=status.HTTP_403_FORBIDDEN
        )


class RateLimitException(APIException):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, detail: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        super().__init__(
            error_type="rate_limit_exceeded",
            title="Rate Limit Exceeded",
            detail=detail,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers=headers
        )


class ServiceUnavailableException(APIException):
    """Raised when a service is unavailable."""
    
    def __init__(self, detail: str = "Service temporarily unavailable", service: Optional[str] = None):
        super().__init__(
            error_type="service_unavailable",
            title="Service Unavailable",
            detail=detail,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            extensions={"service": service} if service else {}
        )


# Backward compatibility
ServiceUnavailableError = ServiceUnavailableException


# =============================================================================
# EXCEPTION HANDLERS
# =============================================================================

# EN exceptions.py - LOS DOS HANDLERS FINALES

async def api_exception_handler(
    request: Request, 
    exc: APIException
) -> JSONResponse:
    """Handle APIException with structured response and metrics."""
    trace_id = getattr(request.state, "correlation_id", None)
    
    # ✅ Extrae plan del JWT
    client_plan = _extract_plan_from_jwt(request)
    
    _record_error_metrics(
        error_type=exc.error_type,
        status_code=exc.status_code,
        component="api_exception_handler"
    )
    
    problem = exc.to_problem_detail(
        instance=str(request.url),
        trace_id=trace_id,
        client_plan=client_plan
    )
    
    logger.error(
        "API Exception | Type: %s | Status: %d | Detail: %s | "
        "Trace: %s | Plan: %s | Path: %s",
        exc.error_type,
        exc.status_code,
        exc.detail,
        trace_id,
        client_plan,
        request.url.path
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=problem.model_dump(exclude_none=True),
        headers=exc.headers
    )


async def general_exception_handler(
    request: Request, 
    exc: Exception
) -> JSONResponse:
    """Handle unexpected exceptions with safe error reporting."""
    trace_id = getattr(request.state, "correlation_id", None)
    
    # ✅ Extrae plan del JWT
    client_plan = _extract_plan_from_jwt(request)
    
    _record_error_metrics(
        error_type="internal_server_error",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        component="general_exception_handler"
    )
    
    # Diferentes mensajes según environment
    if settings.environment == "PRODUCTION":
        detail = "An unexpected error occurred. Please contact support if the problem persists."
        error_info = None
    else:
        detail = f"{type(exc).__name__}: {str(exc)}"
        error_info = traceback.format_exc()
    
    problem = ProblemDetail(
        type="internal_server_error",
        title="Internal Server Error",
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=detail,
        instance=str(request.url),
        trace_id=trace_id,
        client_plan=client_plan  # ✅ Plan correcto aquí también
    )
    
    logger.critical(
        "Unhandled Exception | Type: %s | Detail: %s | "
        "Trace: %s | Plan: %s | Path: %s\n%s",
        type(exc).__name__,
        str(exc),
        trace_id,
        client_plan,
        request.url.path,
        error_info or "",
        exc_info=True
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=problem.model_dump(exclude_none=True)
    )


# ✅ HELPER FUNCTION: Centraliza la extracción del plan (DRY)
def _extract_plan_from_jwt(request: Request) -> str:
    """Extract plan from JWT token in Authorization header."""
    try:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            import jwt as pyjwt
            token = auth_header.split(" ")[1]
            payload = pyjwt.decode(token, options={"verify_signature": False})
            plan = payload.get("plan")
            if plan:
                return plan.upper()
    except Exception as e:
        logger.debug(f"Could not extract plan from JWT: {type(e).__name__}: {e}")
    
    return "UNKNOWN"


from app.pii_mask import sanitize_request_body

async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic validation errors with detailed feedback."""
    
    trace_id = getattr(request.state, "correlation_id", None)
    
    # ✅ CORRECTO: Extrae el plan del JWT directamente usando jose
    client_plan = "UNKNOWN"  # Default
    try:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            import jwt as pyjwt
            token = auth_header.split(" ")[1]
            
            # ✅ MÉTODO CORRECTO: decode con verify_signature=False
            payload = pyjwt.decode(token, options={"verify_signature": False})
            plan = payload.get("plan")
            
            if plan:
                client_plan = plan.upper()
                logger.debug(f"Extracted plan from JWT: {client_plan}")
            else:
                logger.debug("No plan found in JWT payload")
        else:
            logger.debug("No Bearer token in Authorization header")
            
    except Exception as e:
        logger.debug(f"Could not extract plan from token: {type(e).__name__}: {e}")
        client_plan = "UNKNOWN"
    
    _record_error_metrics(
        error_type="validation_error",
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        component="validation_exception_handler"
    )
    
    formatted_errors = _format_validation_errors(exc.errors())
    
    problem = ProblemDetail(
        type="validation_error",
        title="Request Validation Failed",
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="One or more fields failed validation",
        instance=str(request.url),
        trace_id=trace_id,
        client_plan=client_plan,  # ← Ahora será PREMIUM ✅
        errors=formatted_errors
    )
    
    # ✅ NUEVO: Sanitizar errores antes de loguear
    error_details_raw = json.dumps(formatted_errors, default=str, ensure_ascii=False)[:1000]
    error_details_safe = sanitize_request_body(error_details_raw)  # ← SANITIZAR
    
    logger.warning(
        f"Validation Error | Count: {len(formatted_errors)} | "
        f"Details: {error_details_safe} | "  # ← USAR VERSION SANITIZADA
        f"Trace: {trace_id} | "
        f"Plan: {client_plan} | "
        f"Path: {request.url.path}"
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem.model_dump(exclude_none=True)
    )


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

async def _get_client_plan_safe(request: Request) -> str:
    """Safely retrieve client plan from request or JWT token."""
    try:
        # 1. Intenta desde request.state (si se guardó previamente)
        if hasattr(request.state, "client_plan"):
            plan = request.state.client_plan
            if plan:
                return plan.upper()
        
        # 2. ✅ NUEVO: Lee directamente del JWT en Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                import jwt as pyjwt
                token = auth_header.split(" ")[1]
                
                # Decodifica sin verificar (porque ya fue verificado en middleware)
                payload = pyjwt.decode(token, options={"verify_signature": False})
                plan = payload.get("plan")
                if plan:
                    return plan.upper()
            except Exception as jwt_error:
                logger.debug(f"Could not decode JWT for plan: {jwt_error}")
        
        # 3. Fallback: Intenta desde Redis
        redis = getattr(request.app.state, "redis", None)
        if redis:
            plan = await get_user_plan_safe(request, redis)
            if plan:
                return plan.upper()
    
    except Exception as e:
        logger.debug(f"Failed to get client plan: {e}")
    
    # 4. Default: Retorna UNKNOWN (no FREE)
    return "UNKNOWN"


def _record_error_metrics(error_type: str, status_code: int, component: str) -> None:
    """Record error metrics safely."""
    try:
        if status_code >= 500:
            severity = "critical"
        elif status_code >= 400:
            severity = "error"
        else:
            severity = "warning"
        
        metrics_recorder.record_error(
            error_type=error_type,
            severity=severity,
            component=component
        )
    except Exception as e:
        logger.debug(f"Failed to record error metrics: {e}")


def _format_validation_errors(errors: list) -> list:
    """Format Pydantic validation errors for user-friendly display."""
    formatted = []
    
    for error in errors:
        input_value = error.get("input") if "input" in error else None
        
        # Handle bytes input (e.g. from non-JSON bodies)
        if isinstance(input_value, bytes):
            try:
                input_value = input_value.decode("utf-8", errors="replace")
            except Exception:
                input_value = str(input_value)
                
        formatted.append({
            "field": ".".join(str(loc) for loc in error.get("loc", [])),
            "message": error.get("msg", "validation error"),
            "type": error.get("type", "unknown"),
            "input": input_value
        })
    
    return formatted


# =============================================================================
# REGISTRATION FUNCTION
# =============================================================================

def register_exception_handlers(app):
    """Register all exception handlers with the FastAPI application."""
    app.add_exception_handler(APIException, api_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
    
    logger.info("Exception handlers registered successfully")

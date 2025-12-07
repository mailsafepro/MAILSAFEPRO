"""
OpenTelemetry Distributed Tracing Module

Provides enterprise-grade distributed tracing for MailSafePro API with:
- Automatic instrumentation for FastAPI, Redis, HTTP clients
- Correlation ID propagation across services
- Custom span attributes for business context
- Export to Jaeger, Zipkin, or OTLP collectors
"""

from __future__ import annotations

import os
import logging
from typing import Optional, Dict, Any
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
from opentelemetry.trace import Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Conditional imports for exporters
try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    JAEGER_AVAILABLE = True
except ImportError:
    JAEGER_AVAILABLE = False

try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    OTLP_AVAILABLE = True
except ImportError:
    OTLP_AVAILABLE = False

from app.logger import logger

# =============================================================================
# CONFIGURATION
# =============================================================================

class TracingConfig:
    """Configuration for distributed tracing."""
    
    def __init__(self):
        self.enabled = os.getenv("TRACING_ENABLED", "true").lower() == "true"
        self.service_name = os.getenv("SERVICE_NAME", "mailsafepro-api")
        self.service_version = os.getenv("SERVICE_VERSION", "2.1.0")
        self.environment = os.getenv("ENVIRONMENT", "development")
        
        # Exporter configuration
        self.exporter_type = os.getenv("TRACING_EXPORTER", "console")  # console, jaeger, otlp
        self.jaeger_agent_host = os.getenv("JAEGER_AGENT_HOST", "localhost")
        self.jaeger_agent_port = int(os.getenv("JAEGER_AGENT_PORT", "6831"))
        self.otlp_endpoint = os.getenv("OTLP_ENDPOINT", "http://localhost:4317")
        
        # Sampling configuration
        self.sample_rate = float(os.getenv("TRACING_SAMPLE_RATE", "1.0"))  # 1.0 = 100%
        
        # Feature flags
        self.instrument_redis = os.getenv("TRACING_INSTRUMENT_REDIS", "true").lower() == "true"
        self.instrument_http = os.getenv("TRACING_INSTRUMENT_HTTP", "true").lower() == "true"


# =============================================================================
# TRACER SETUP
# =============================================================================

_tracer_provider: Optional[TracerProvider] = None
_tracer: Optional[trace.Tracer] = None
_config: Optional[TracingConfig] = None


def setup_tracing(app=None) -> None:
    """
    Initialize OpenTelemetry tracing with configured exporter.
    
    Args:
        app: FastAPI application instance to instrument (optional)
    """
    global _tracer_provider, _tracer, _config
    
    _config = TracingConfig()
    
    if not _config.enabled:
        logger.info("Distributed tracing is disabled")
        return
    
    # Create resource with service information
    resource = Resource.create({
        SERVICE_NAME: _config.service_name,
        SERVICE_VERSION: _config.service_version,
        "deployment.environment": _config.environment,
        "telemetry.sdk.language": "python",
        "telemetry.sdk.name": "opentelemetry",
    })
    
    # Create tracer provider
    _tracer_provider = TracerProvider(resource=resource)
    
    # Configure exporter based on configuration
    exporter = _create_exporter(_config)
    
    if exporter:
        # Add batch span processor for efficient export
        span_processor = BatchSpanProcessor(
            exporter,
            max_queue_size=2048,
            max_export_batch_size=512,
            export_timeout_millis=30000,
        )
        _tracer_provider.add_span_processor(span_processor)
        logger.info(f"✅ Tracing exporter configured: {_config.exporter_type}")
    else:
        logger.info("ℹ️ No tracing exporter configured (development mode)")
    
    # Set as global tracer provider
    trace.set_tracer_provider(_tracer_provider)
    
    # Get tracer instance
    _tracer = trace.get_tracer(__name__, _config.service_version)
    
    # ✅ NUEVO: Silenciar logs verbose de OpenTelemetry en development
    if _config.environment.lower() == "development":
        logging.getLogger("opentelemetry").setLevel(logging.ERROR)
        logging.getLogger("opentelemetry.sdk").setLevel(logging.ERROR)
        logging.getLogger("opentelemetry.instrumentation").setLevel(logging.ERROR)
        logging.getLogger("opentelemetry.exporter").setLevel(logging.ERROR)
        logger.info("🔇 OpenTelemetry verbose logging disabled in development")
    
    # Instrument FastAPI if app provided
    if app:
        try:
            FastAPIInstrumentor.instrument_app(app)
            logger.success("✅ FastAPI instrumented for tracing")
        except Exception as e:
            logger.error(f"Failed to instrument FastAPI: {e}")
    
    # Instrument Redis if enabled
    if _config.instrument_redis:
        try:
            RedisInstrumentor().instrument()
            logger.success("✅ Redis instrumented for tracing")
        except Exception as e:
            logger.error(f"Failed to instrument Redis: {e}")
    
    # Instrument aiohttp if enabled
    if _config.instrument_http:
        try:
            AioHttpClientInstrumentor().instrument()
            logger.success("✅ HTTP client instrumented for tracing")
        except Exception as e:
            logger.error(f"Failed to instrument HTTP client: {e}")
    
    logger.success(f"🔍 Distributed tracing initialized for {_config.service_name}")


def _create_exporter(config: TracingConfig):
    """Create span exporter based on configuration."""
    
    # ✅ NUEVO: En development, NO exportar traces (reduce log noise)
    if config.environment.lower() == "development" and config.exporter_type == "console":
        logger.info("🔇 Console tracing disabled in development (reducing log noise)")
        return None  # No exporter = no traces en consola
    
    if config.exporter_type == "jaeger":
        if not JAEGER_AVAILABLE:
            logger.warning("Jaeger exporter not available, install opentelemetry-exporter-jaeger")
            return None
        
        return JaegerExporter(
            agent_host_name=config.jaeger_agent_host,
            agent_port=config.jaeger_agent_port,
        )
    
    elif config.exporter_type == "otlp":
        if not OTLP_AVAILABLE:
            logger.warning("OTLP exporter not available, install opentelemetry-exporter-otlp")
            return None
        
        return OTLPSpanExporter(
            endpoint=config.otlp_endpoint,
            insecure=True,  # Use TLS in production
        )
    
    elif config.exporter_type == "console":
        # Solo en production/staging
        return ConsoleSpanExporter()
    
    else:
        logger.warning(f"Unknown exporter type: {config.exporter_type}")
        return None


def shutdown_tracing() -> None:
    """Shutdown tracing and flush remaining spans."""
    global _tracer_provider
    
    if _tracer_provider:
        try:
            _tracer_provider.shutdown()
            logger.info("✅ Tracing shut down cleanly")
        except Exception as e:
            logger.error(f"Error shutting down tracing: {e}")


# =============================================================================
# TRACING UTILITIES
# =============================================================================

def get_tracer() -> trace.Tracer:
    """Get the global tracer instance."""
    global _tracer
    if _tracer is None:
        # Fallback to no-op tracer if not initialized
        return trace.get_tracer(__name__)
    return _tracer


@contextmanager
def trace_span(
    name: str,
    attributes: Optional[Dict[str, Any]] = None,
    kind: trace.SpanKind = trace.SpanKind.INTERNAL
):
    """
    Context manager for creating custom spans.
    
    Usage:
        with trace_span("validate_email", {"email": email}):
            # Your code here
            pass
    """
    tracer = get_tracer()
    
    with tracer.start_as_current_span(name, kind=kind) as span:
        if attributes:
            for key, value in attributes.items():
                # Only set primitive types as attributes
                if isinstance(value, (str, int, float, bool)):
                    span.set_attribute(key, value)
                else:
                    span.set_attribute(key, str(value))
        
        try:
            yield span
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise


def add_span_attributes(**attributes):
    """Add attributes to the current active span."""
    current_span = trace.get_current_span()
    
    if current_span and current_span.is_recording():
        for key, value in attributes.items():
            if isinstance(value, (str, int, float, bool)):
                current_span.set_attribute(key, value)
            else:
                current_span.set_attribute(key, str(value))


def add_span_event(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Add an event to the current active span."""
    current_span = trace.get_current_span()
    
    if current_span and current_span.is_recording():
        current_span.add_event(name, attributes or {})


def get_trace_context() -> Dict[str, str]:
    """
    Get current trace context for propagation to external services.
    
    Returns:
        Dictionary with traceparent and tracestate headers
    """
    carrier = {}
    TraceContextTextMapPropagator().inject(carrier)
    return carrier


def set_span_error(error: Exception, message: Optional[str] = None):
    """Mark current span as error with exception details."""
    current_span = trace.get_current_span()
    
    if current_span and current_span.is_recording():
        current_span.set_status(Status(StatusCode.ERROR, message or str(error)))
        current_span.record_exception(error)


# =============================================================================
# BUSINESS-SPECIFIC TRACING HELPERS
# =============================================================================

def trace_validation(email: str, plan: str = "FREE"):
    """
    Decorator/context manager for email validation spans.
    
    Usage:
        with trace_validation(email, plan):
            result = validate_email_logic(email)
    """
    return trace_span(
        "email.validation",
        attributes={
            "email.domain": email.split("@")[1] if "@" in email else "unknown",
            "user.plan": plan,
            "validation.type": "single",
        },
        kind=trace.SpanKind.INTERNAL
    )


def trace_smtp_check(mx_host: str, email: str):
    """Context manager for SMTP verification spans."""
    return trace_span(
        "smtp.verification",
        attributes={
            "smtp.host": mx_host,
            "email.domain": email.split("@")[1] if "@" in email else "unknown",
            "network.protocol": "smtp",
        },
        kind=trace.SpanKind.CLIENT
    )


def trace_dns_lookup(domain: str, record_type: str = "MX"):
    """Context manager for DNS lookup spans."""
    return trace_span(
        "dns.lookup",
        attributes={
            "dns.domain": domain,
            "dns.record_type": record_type,
            "network.protocol": "dns",
        },
        kind=trace.SpanKind.CLIENT
    )


def trace_cache_operation(operation: str, key: str):
    """Context manager for cache operation spans."""
    return trace_span(
        f"cache.{operation}",
        attributes={
            "cache.key": key,
            "cache.operation": operation,
        },
        kind=trace.SpanKind.INTERNAL
    )


def trace_batch_job(job_id: str, email_count: int):
    """Context manager for batch job processing spans."""
    return trace_span(
        "batch.job.process",
        attributes={
            "job.id": job_id,
            "job.email_count": email_count,
            "job.type": "email_validation",
        },
        kind=trace.SpanKind.INTERNAL
    )


# =============================================================================
# CORRELATION ID UTILITIES
# =============================================================================

def get_correlation_id() -> Optional[str]:
    """
    Get correlation ID from current span context.
    
    Returns:
        Trace ID as hex string, or None if no active span
    """
    current_span = trace.get_current_span()
    
    if current_span and current_span.is_recording():
        span_context = current_span.get_span_context()
        if span_context and span_context.trace_id:
            # Convert trace_id to hex string
            return format(span_context.trace_id, '032x')
    
    return None


def inject_correlation_id(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Inject current trace context into HTTP headers.
    
    Args:
        headers: Existing headers dictionary
        
    Returns:
        Headers with traceparent and tracestate added
    """
    trace_context = get_trace_context()
    headers.update(trace_context)
    return headers


# =============================================================================
# SAMPLING CONFIGURATION
# =============================================================================

def should_sample_trace(email: str = "", plan: str = "FREE") -> bool:
    """
    Determine if a trace should be sampled based on config and context.
    
    In production, you might want to sample:
    - 100% of ENTERPRISE plan requests
    - 50% of PREMIUM plan requests  
    - 10% of FREE plan requests
    
    Args:
        email: Email being validated (for custom sampling logic)
        plan: User's plan level
        
    Returns:
        True if trace should be sampled
    """
    global _config
    
    if not _config:
        return False
    
    # Always sample in development
    if _config.environment == "development":
        return True
    
    # Plan-based sampling in production
    if plan == "ENTERPRISE":
        return True
    elif plan == "PREMIUM":
        return _config.sample_rate >= 0.5
    else:  # FREE
        return _config.sample_rate >= 0.1

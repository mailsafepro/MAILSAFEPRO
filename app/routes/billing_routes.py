"""
Billing and Subscription Management Module

Refactor orientado a seguridad, confiabilidad, observabilidad y testabilidad,
manteniendo la integración con Stripe, Redis y FastAPI.
"""

import asyncio
import json
import traceback
import uuid
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union, Callable

import stripe
import jwt  # PyJWT
from fastapi import APIRouter, Depends, HTTPException, Request, status, BackgroundTasks, Body
from pydantic import BaseModel, Field, field_validator
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.auth import (
    get_current_client,
    validate_api_key_or_token,
    get_redis,
    create_hashed_key,
    enforce_rate_limit,
    create_access_token,
    create_refresh_token,
    store_refresh_token,
    PLAN_SCOPES,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from app.config import get_settings
from app.models import TokenData
from app.utils import update_all_user_api_keys
from app.logger import logger
from app.email_service import email_service

router = APIRouter(prefix="/billing", tags=["Billing"])

# Configuración
settings = get_settings()
stripe.api_key = settings.stripe.secret_key.get_secret_value()  # type: ignore[attr-defined]

# Constantes
RAW_EVENTS_QUEUE = "stripe:webhook:raw"
ERRORS_LIST = "stripe:webhook:errors"
PROCESSED_EVENTS_SET = "stripe:processed:events"
PROCESSED_EVENT_KEY_PREFIX = "stripe:processed:event:"
PROCESSED_EVENT_TTL_SECONDS = 7 * 24 * 3600  # 7 días

ALLOWED_EVENTS: set[str] = {
    "checkout.session.completed",
    "customer.subscription.updated",
    "customer.subscription.deleted",
}

RAW_EVENTS_MAX = 2000
ERRORS_MAX = 1000

IDEMPOTENCY_TTL = 24 * 3600  # 24h (si se añade expiración a la marca de idempotencia)
PROCESSING_LOCK_TTL = 90  # s
USER_LOCK_TTL = 60  # s

STRIPE_CALL_TIMEOUT = 10  # s
STRIPE_RETRIES = 3
STRIPE_SEMAPHORE = asyncio.Semaphore(50)  # concurrencia hacia Stripe

# Modelos Pydantic
class CheckoutRequest(BaseModel):
    """Request para crear checkout sessions."""
    plan: str = Field(..., description="Plan: PREMIUM o ENTERPRISE")

    @field_validator("plan", mode="before")
    @classmethod
    def validate_plan(cls, v: str) -> str:
        """Valida y normaliza el plan a uppercase."""
        if not v or not isinstance(v, str):
            raise ValueError("Plan must be a string")
        
        up = v.strip().upper()
        
        if up not in {"PREMIUM", "ENTERPRISE"}:
            raise ValueError(f"Plan must be PREMIUM or ENTERPRISE, got: {v}")
        
        return up


class SubscriptionResponse(BaseModel):
    """Respuesta con información de suscripción."""
    plan: str
    next_billing_date: Optional[str] = None
    status: str = "active"
    customer_id: Optional[str] = None


class WebhookResponse(BaseModel):
    """Respuesta genérica para el webhook."""
    status: str
    event_id: Optional[str] = None
    message: Optional[str] = None


class CheckoutSessionResponse(BaseModel):
    """Respuesta al crear checkout session."""
    session_id: str


class BillingSecurity:
    """Utilidades de seguridad para operaciones de billing."""

    @staticmethod
    def sanitize_metadata_value(value: Optional[str]) -> str:
        """Sanea valores de metadata para usarlos en claves/Redis."""
        if not value:
            return ""
        import re
        sanitized = re.sub(r"[^a-zA-Z0-9_\-]", "", str(value))
        return sanitized[:128]
    
    @staticmethod
    def mask_pii(raw: str) -> str:
        """
        Ofusca PII básica en el payload crudo (emails).
        Ej.: juan.perez@example.com -> j***@e***.com
        """
        import re

        def _mask_email(match: "re.Match[str]") -> str:
            email = match.group(0)
            try:
                user, domain = email.split("@", 1)
                u = (user[0] + "***") if user else "***"
                d_parts = domain.split(".")
                if d_parts:
                    d_parts[0] = (d_parts[0][0] + "***") if d_parts[0] else "***"
                masked_domain = ".".join(d_parts)
                return f"{u}@{masked_domain}"
            except Exception:
                return "***@***"

        # Patrón simple para emails
        email_re = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
        return email_re.sub(_mask_email, raw or "")

    @staticmethod
    def validate_webhook_signature(payload: bytes, sig_header: str, secret: str) -> Dict[str, Any]:
        """Valida la firma del webhook de Stripe."""
        try:
            return stripe.Webhook.construct_event(payload, sig_header, secret)
        except stripe.SignatureVerificationError as e:
            logger.warning(f"Webhook signature verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid webhook signature",
            )
        except ValueError as e:
            logger.warning(f"Webhook payload error: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid webhook payload",
            )


class RedisOperations:
    """Operaciones Redis con manejo de errores."""

    @staticmethod
    async def bytes_to_str(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return value.decode("latin-1", errors="ignore")
        return str(value)

    @staticmethod
    async def lpush_trim(redis: Redis, key: str, value: str, maxlen: int) -> None:
        try:
            pipeline = redis.pipeline()
            pipeline.rpush(key, value)
            pipeline.ltrim(key, -maxlen, -1)
            await pipeline.execute()
        except RedisError as e:
            logger.warning(f"Redis list operation failed for {key}: {e}")

    @staticmethod
    async def get_json(redis: Redis, key: str) -> Optional[Dict[str, Any]]:
        try:
            data = await redis.get(key)
            if data:
                data_str = await RedisOperations.bytes_to_str(data)
                return json.loads(data_str) if data_str else None
        except (json.JSONDecodeError, RedisError) as e:
            logger.warning(f"Failed to parse JSON from {key}: {e}")
        return None

    @staticmethod
    async def set_json(redis: Redis, key: str, data: Dict[str, Any], ex: Optional[int] = None) -> None:
        try:
            await redis.set(key, json.dumps(data), ex=ex)
        except RedisError as e:
            logger.warning(f"Failed to set JSON in {key}: {e}")


class LockManager:
    """Locks distribuidos para operaciones atómicas."""

    @staticmethod
    @asynccontextmanager
    async def acquire_lock(redis: Redis, lock_key: str, ttl: int, operation: str = "lock"):
        owner = str(uuid.uuid4())
        acquired = False
        try:
            acquired = await redis.set(lock_key, owner, nx=True, ex=ttl)
            if acquired:
                logger.debug(f"Acquired {operation} lock: {lock_key}")
                yield owner
            else:
                logger.debug(f"Could not acquire {operation} lock: {lock_key}")
                yield None
        finally:
            if acquired:
                try:
                    current_owner = await redis.get(lock_key)
                    if current_owner and await RedisOperations.bytes_to_str(current_owner) == owner:
                        await redis.delete(lock_key)
                        logger.debug(f"Released {operation} lock: {lock_key}")
                except RedisError as e:
                    logger.warning(f"Failed to release lock {lock_key}: {e}")

    @staticmethod
    async def acquire_processing_lock(redis: Redis, event_id: str) -> Optional[str]:
        lock_key = f"processing:event:{event_id}"
        async with LockManager.acquire_lock(redis, lock_key, PROCESSING_LOCK_TTL, "processing") as owner:
            return owner

    @staticmethod
    async def acquire_user_lock(redis: Redis, user_id: str) -> Optional[str]:
        lock_key = f"lock:user:update:{user_id}"
        async with LockManager.acquire_lock(redis, lock_key, USER_LOCK_TTL, "user") as owner:
            return owner


class StripeClient:
    """Cliente Stripe seguro con reintentos y timeouts."""

    @staticmethod
    async def call_with_retry(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        backoff = 0.5
        last_error: Optional[Exception] = None
        for attempt in range(1, STRIPE_RETRIES + 1):
            try:
                async with STRIPE_SEMAPHORE:
                    coro = asyncio.to_thread(func, *args, **kwargs)
                    result = await asyncio.wait_for(coro, timeout=STRIPE_CALL_TIMEOUT)
                    return result
            except (asyncio.TimeoutError, stripe.RateLimitError, stripe.APIConnectionError) as e:
                last_error = e
                logger.warning(f"Stripe call attempt {attempt}/{STRIPE_RETRIES} failed: {e}")
                if attempt < STRIPE_RETRIES:
                    # Pequeño jitter
                    await asyncio.sleep(backoff + 0.1 * attempt)
                    backoff *= 2
            except stripe.StripeError as e:
                logger.error(f"Stripe API error: {e}")
                raise
            except Exception as e:
                logger.error(f"Unexpected error in Stripe call: {e}")
                last_error = e
                break
        raise last_error or Exception("Stripe call failed after retries")

    @staticmethod
    async def retrieve_subscription(subscription_id: str) -> Dict[str, Any]:
        return await StripeClient.call_with_retry(
            stripe.Subscription.retrieve,
            subscription_id,
            expand=["customer", "items.data.price"],
        )

    @staticmethod
    async def retrieve_checkout_session(session_id: str) -> Dict[str, Any]:
        return await StripeClient.call_with_retry(
            stripe.checkout.Session.retrieve,
            session_id,
            expand=["subscription", "customer", "subscription.default_payment_method"],
        )

    @staticmethod
    async def create_customer(metadata: Dict[str, str]) -> Dict[str, Any]:
        return await StripeClient.call_with_retry(
            stripe.Customer.create,
            metadata=metadata,
        )

    @staticmethod
    async def create_checkout_session(**params: Any) -> Dict[str, Any]:
        return await StripeClient.call_with_retry(
            stripe.checkout.Session.create,
            **params,
        )


class EventProcessor:
    """Procesamiento de eventos de Stripe con idempotencia."""

    @staticmethod
    async def is_event_processed(redis: Redis, event_id: str) -> bool:
        try:
            key = f"{PROCESSED_EVENT_KEY_PREFIX}{event_id}"
            val = await redis.get(key)
            return bool(val)
        except RedisError:
            logger.warning(f"Failed to check event processing status: {event_id}")
            return False

    @staticmethod
    async def mark_event_processed(redis: Redis, event_id: str) -> None:
        try:
            key = f"{PROCESSED_EVENT_KEY_PREFIX}{event_id}"
            await redis.setex(key, PROCESSED_EVENT_TTL_SECONDS, "1")
        except RedisError:
            logger.warning(f"Failed to mark event as processed: {event_id}")

    @staticmethod
    async def process_checkout_session_completed(event: Dict[str, Any], redis: Redis) -> None:
        """Process checkout.session.completed - with graceful fallback."""
        session_data = event.get("data", {}).get("object", {})
        session_id = session_data.get("id")
        logger.info(f"Processing checkout.session.completed: {session_id}")

        # Validate session mode - must be subscription for plan upgrades
        session_mode = session_data.get("mode")
        if session_mode not in ["subscription", "payment"]:
            logger.info(f"Skipping unsupported session mode: {session_mode}")
            return

        # Only process subscription sessions for plan upgrades
        # Payment mode is for one-time purchases, not subscriptions
        if session_mode != "subscription":
            logger.info(f"Skipping non-subscription session: {session_mode}")
            return

        # ✅ NUEVO: Intentar obtener de Stripe, pero usar webhook data si falla
        session = session_data
        try:
            fetched_session = await StripeClient.retrieve_checkout_session(session_id)
            session = fetched_session if hasattr(fetched_session, "get") else fetched_session
            logger.info("Session retrieved from Stripe successfully")
        except Exception as e:
            # ✅ FALLBACK: Usar datos del webhook en lugar de retornar
            logger.warning(f"Could not fetch session from Stripe (using webhook data): {e}")
            session = session_data

        # Extraer usuario (del webhook o de Stripe)
        user_info = await EventProcessor._extract_user_info(session, redis)
        if not user_info.get("user_id"):
            logger.error("User ID not found in session metadata")
            await EventProcessor._store_failed_event(redis, event, "missing_user_id", "User ID not found")
            return

        # ✅ Actualizar suscripción
        await EventProcessor._update_user_subscription(user_info, session, redis)
        logger.info(f"✅ Subscription updated for user {user_info.get('user_id')}")


    @staticmethod
    async def _extract_user_info(session: Dict[str, Any], redis: Redis) -> Dict[str, Any]:
        metadata = session.get("metadata", {}) or {}
        user_id = BillingSecurity.sanitize_metadata_value(metadata.get("user_id"))
        api_key_hash = BillingSecurity.sanitize_metadata_value(metadata.get("api_key_hash"))
        customer_id = session.get("customer")

        if not user_id and customer_id:
            user_id, api_key_hash = await EventProcessor._get_user_from_customer(customer_id, redis)

        return {"user_id": user_id, "api_key_hash": api_key_hash, "customer_id": customer_id}

    @staticmethod
    async def _get_user_from_customer(customer_id: str, redis: Redis) -> Tuple[Optional[str], Optional[str]]:
        try:
            # Intento por Redis
            user_id_b = await redis.hget(f"customer:{customer_id}", "user_id")
            api_key_hash_b = await redis.hget(f"customer:{customer_id}", "api_key_hash")
            if user_id_b:
                return (
                    await RedisOperations.bytes_to_str(user_id_b),
                    await RedisOperations.bytes_to_str(api_key_hash_b),
                )
            # Fallback a Stripe
            customer = await StripeClient.call_with_retry(stripe.Customer.retrieve, customer_id)
            customer_metadata = customer.get("metadata", {}) if hasattr(customer, "get") else {}
            return (
                BillingSecurity.sanitize_metadata_value(customer_metadata.get("user_id")),
                BillingSecurity.sanitize_metadata_value(customer_metadata.get("api_key_hash")),
            )
        except Exception as e:
            logger.warning(f"Failed to get user from customer {customer_id}: {e}")
            return None, None

    @staticmethod
    def _extract_plan_info(subscription: Dict[str, Any]) -> Dict[str, Any]:
        items = subscription.get("items", {}).get("data", []) or []
        price_id = items[0].get("price", {}).get("id") if items else None
        
        plan_mapping = {
            settings.stripe.premium_plan_id: "PREMIUM",
            settings.stripe.enterprise_plan_id: "ENTERPRISE",
        }
        
        plan = plan_mapping.get(price_id, "PREMIUM")
        next_billing = ""
        current_period_end = subscription.get("current_period_end")
        
        if current_period_end:
            try:
                next_billing = datetime.fromtimestamp(int(current_period_end), tz=timezone.utc).isoformat()
            except (ValueError, TypeError):
                next_billing = ""
        
        return {
            "plan": plan,
            "next_billing": next_billing,  # Always include this
            "subscription_id": subscription.get("id"),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }

    @staticmethod
    async def _persist_user_data(user_id: str, api_key_hash: Optional[str], plan_info: Dict[str, Any], redis: Redis) -> None:
        user_key = f"user:{user_id}"
        
        # ✅ GARANTIZAR que plan siempre existe en el hash del usuario
        plan_info.setdefault("plan", "PREMIUM")
        plan_info.setdefault("next_billing", "")
        plan_info.setdefault("subscription_id", "")
        plan_info.setdefault("updated_at", datetime.now(timezone.utc).isoformat())

        # ✅ PRIMERO: Actualizar el hash principal del usuario
        await redis.hset(
            user_key,
            mapping={
                "plan": plan_info["plan"],
                "next_billing_date": plan_info["next_billing"],
                "stripe_subscription_id": plan_info["subscription_id"],
                "updated_at": plan_info["updated_at"],
            },
        )
        
        # Luego: actualizar API keys
        if api_key_hash:
            key_key = f"key:{api_key_hash}"
            key_data = await RedisOperations.get_json(redis, key_key) or {}
            key_data.update({"plan": plan_info["plan"], "updated_at": datetime.now(timezone.utc).isoformat()})
            await RedisOperations.set_json(redis, key_key, key_data)

        await update_all_user_api_keys(user_id, plan_info["plan"], redis)

        # ✅ FINALMENTE: Actualizar caché de suscripción (esto es secundario)
        cache_data = {"plan": plan_info["plan"], "next_billing_date": plan_info["next_billing"]}
        await RedisOperations.set_json(redis, f"user:{user_id}:subscription", cache_data, ex=3600)
        
        logger.info(f"✅ Persisted user data: {user_id} -> {plan_info['plan']}")


    @staticmethod
    async def _store_failed_event(redis: Redis, event: Dict[str, Any], phase: str, error: str) -> None:
        await RedisOperations.lpush_trim(
            redis,
            RAW_EVENTS_QUEUE,
            json.dumps(
                {
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "phase": phase,
                    "event_id": event.get("id"),
                    "error": error,
                    "event_type": event.get("type"),
                }
            ),
            RAW_EVENTS_MAX,
        )

    @staticmethod
    async def _store_error(redis: Redis, phase: str, error: str, **context: Any) -> None:
        error_data = {
            "time": datetime.now(timezone.utc).isoformat(),
            "phase": phase,
            "error": error,
            "trace": traceback.format_exc(),
            **context,
        }
        await RedisOperations.lpush_trim(redis, ERRORS_LIST, json.dumps(error_data), ERRORS_MAX)

    @staticmethod
    async def _update_user_subscription(user_info: Dict[str, Any], session: Dict[str, Any], redis: Redis) -> None:
        user_id = user_info["user_id"]
        subscription_id = session.get("subscription")
        
        # Extract subscription_id as string (handle both object and string cases)
        if isinstance(subscription_id, dict):
            subscription_id = subscription_id.get("id")
        elif hasattr(subscription_id, "id"):
            subscription_id = subscription_id.id
        
        if not subscription_id:
            await EventProcessor._store_error(redis, "subscription_missing", "No subscription in session", user_id=user_id)
            return
        
        # Ensure it's a string
        subscription_id = str(subscription_id)
        
        async with LockManager.acquire_lock(redis, f"lock:user:update:{user_id}", USER_LOCK_TTL, "user") as owner:
            if not owner:
                logger.warning(f"Could not acquire user lock for {user_id}")
                return
            
            try:
                subscription = await StripeClient.retrieve_subscription(subscription_id)
            except Exception as e:
                logger.warning(f"Could not fetch subscription from Stripe, using webhook data: {e}")
                subscription = session
            
            try:
                # Extract plan info with proper fallback
                plan_info = EventProcessor._extract_plan_info(subscription)
                
                # Ensure all required fields exist
                if not plan_info.get("next_billing"):
                    current_period_end = subscription.get("current_period_end")
                    if current_period_end:
                        try:
                            plan_info["next_billing"] = datetime.fromtimestamp(
                                int(current_period_end), 
                                tz=timezone.utc
                            ).isoformat()
                        except (ValueError, TypeError):
                            plan_info["next_billing"] = ""
                    else:
                        plan_info["next_billing"] = ""
                
                await EventProcessor._persist_user_data(user_id, user_info.get("api_key_hash"), plan_info, redis)
                logger.info(f"✅ Updated subscription for user {user_id}: {plan_info['plan']}")
            except Exception as e:
                logger.error(f"Failed to update user subscription {user_id}: {e}")
                await EventProcessor._store_error(redis, "subscription_update_failed", str(e), user_id=user_id)


class BillingManager:
    """Orquestador de eventos de billing."""

    @staticmethod
    async def process_webhook_event(event: Dict[str, Any], redis: Redis) -> None:
        event_id = event.get("id", str(uuid.uuid4()))
        event_type = event.get("type", "unknown")
        logger.info(f"Processing webhook event: {event_type} ({event_id})")

        # Idempotencia
        if await EventProcessor.is_event_processed(redis, event_id):
            logger.info(f"Event already processed: {event_id}")
            return

        async with LockManager.acquire_lock(redis, f"processing:event:{event_id}", PROCESSING_LOCK_TTL, "processing") as owner:
            if not owner:
                logger.info(f"Event already being processed: {event_id}")
                return

            try:
                if event_type == "checkout.session.completed":
                    await EventProcessor.process_checkout_session_completed(event, redis)
                elif event_type == "customer.subscription.updated":
                    await BillingManager._process_subscription_updated(event, redis)
                elif event_type == "invoice.payment_succeeded":
                    await BillingManager._process_invoice_payment_succeeded(event, redis)
                else:
                    logger.info(f"Unhandled event type: {event_type}")
                    await EventProcessor._store_failed_event(
                        redis, event, "unhandled_event", f"Event type {event_type} not handled"
                    )

                await EventProcessor.mark_event_processed(redis, event_id)
            except Exception as e:
                logger.error(f"Failed to process event {event_id}: {e}")
                await EventProcessor._store_error(
                    redis, "event_processing", str(e), event_id=event_id, event_type=event_type
                )

    @staticmethod
    async def _process_subscription_updated(event: Dict[str, Any], redis: Redis) -> None:
        subscription = event.get("data", {}).get("object", {}) or {}
        if subscription.get("status") != "active":
            logger.info(f"Subscription not active: {subscription.get('id')}")
            return

        customer_id = subscription.get("customer")
        if not customer_id:
            logger.warning("Subscription update without customer id")
            return

        user_id_b = await redis.hget(f"customer:{customer_id}", "user_id")
        if not user_id_b:
            logger.warning(f"No user mapping for customer: {customer_id}")
            return

        user_id = await RedisOperations.bytes_to_str(user_id_b)
        if not user_id:
            return

        async with LockManager.acquire_lock(redis, f"lock:user:update:{user_id}", USER_LOCK_TTL, "user") as owner:
            if not owner:
                return
            plan_info = EventProcessor._extract_plan_info(subscription)
            await EventProcessor._persist_user_data(user_id, None, plan_info, redis)

    @staticmethod
    async def _process_invoice_payment_succeeded(event: Dict[str, Any], redis: Redis) -> None:
        invoice = event.get("data", {}).get("object", {}) or {}
        customer_id = invoice.get("customer")
        subscription_id = invoice.get("subscription")
        if not subscription_id or not customer_id:
            return

        try:
            subscription = await StripeClient.retrieve_subscription(subscription_id)
            next_billing = ""
            current_period_end = subscription.get("current_period_end")
            if current_period_end:
                next_billing = datetime.fromtimestamp(int(current_period_end), tz=timezone.utc).isoformat()

            user_id_b = await redis.hget(f"customer:{customer_id}", "user_id")
            if user_id_b:
                user_id = await RedisOperations.bytes_to_str(user_id_b)
                if user_id:
                    user_key = f"user:{user_id}"
                    await redis.hset(user_key, "next_billing_date", next_billing)

                    cache_key = f"user:{user_id}:subscription"
                    cached = await RedisOperations.get_json(redis, cache_key)
                    if cached:
                        cached["next_billing_date"] = next_billing
                        await RedisOperations.set_json(redis, cache_key, cached, ex=3600)
                    logger.info(f"Updated billing date for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to process invoice payment: {e}")


# Endpoints

@router.post("/webhook", response_model=WebhookResponse)
async def stripe_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    redis: Redis = Depends(get_redis),
) -> WebhookResponse:
    """Webhook de Stripe."""
    request_id = getattr(request.state, "correlation_id", "unknown")
    logger.info("🔔 Stripe webhook received")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    # ⚠️ SECURITY FIX: Only skip signature in explicit test mode, never in dev
    # Previous code bypassed validation when DOCKER_ENV=1 (vulnerability)
    is_testing = os.getenv("TESTING") == "1"

    if is_testing and not sig_header:
        logger.warning("⚠️ TEST MODE ONLY: Skipping Stripe signature validation")
        try:
            event = json.loads(payload.decode("utf-8"))
            event["_unvalidated_test_mode"] = True  # Mark as unvalidated
        except Exception as e:
            logger.error(f"Invalid JSON payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON")
    else:
        # PRODUCCIÓN: Validar firma
        if not sig_header:
            raise HTTPException(status_code=400, detail="Missing Stripe signature")

        # ✅ CRÍTICO: Extraer el valor de SecretStr
        webhook_secret = settings.stripe.webhook_secret
        if hasattr(webhook_secret, "get_secret_value"):
            webhook_secret = webhook_secret.get_secret_value()  # ✅ ESTO EXTRAE EL STRING

        if not webhook_secret:
            logger.error("Stripe webhook secret not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        try:
            # ✅ AHORA webhook_secret es un string válido
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Webhook signature verification failed: {e}")
            raise HTTPException(status_code=400, detail="Invalid signature")
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            raise HTTPException(status_code=400, detail="Invalid webhook")

    event_id = event.get("id", "unknown")
    event_type = event.get("type", "unknown")

    logger.info(f"✅ Processing webhook: {event_type} ({event_id})")

    background_tasks.add_task(BillingManager.process_webhook_event, event, redis)

    return WebhookResponse(status="received", event_id=event_id)



@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    request: Request,
    current_client: TokenData = Depends(validate_api_key_or_token),
    redis: Redis = Depends(get_redis),
) -> SubscriptionResponse:
    """
    Devuelve información de suscripción (plan y próxima fecha de cobro).
    """
    request_id = getattr(request.state, "correlation_id", "unknown")
    with logger.contextualize(request_id=request_id):
        try:
            user_id = await _resolve_user_id(current_client, redis)
            if not user_id:
                logger.info("No user ID resolved, returning FREE plan")
                return SubscriptionResponse(plan="FREE", next_billing_date="")

            cache_key = f"user:{user_id}:subscription"
            force_refresh = request.query_params.get("refresh")
            if not force_refresh:
                cached = await RedisOperations.get_json(redis, cache_key)
                if cached:
                    return SubscriptionResponse(**cached)

            user_key = f"user:{user_id}"
            plan_b = await redis.hget(user_key, "plan")
            next_billing_b = await redis.hget(user_key, "next_billing_date")
            customer_id_b = await redis.hget(user_key, "stripe_customer_id")

            plan = (await RedisOperations.bytes_to_str(plan_b)) or "FREE"
            next_billing = (await RedisOperations.bytes_to_str(next_billing_b)) or ""
            customer_id = await RedisOperations.bytes_to_str(customer_id_b)

            if plan == "FREE" and customer_id:
                try:
                    subscriptions = await StripeClient.call_with_retry(
                        stripe.Subscription.list,
                        customer=customer_id,
                        status="active",
                        limit=1,
                    )
                    if getattr(subscriptions, "data", None):
                        subscription = subscriptions.data[0]
                        plan_info = EventProcessor._extract_plan_info(subscription)
                        plan = plan_info["plan"]
                        next_billing = plan_info["next_billing"]
                        await redis.hset(user_key, mapping={"plan": plan, "next_billing_date": next_billing})
                except Exception as e:
                    logger.warning(f"Failed to fetch subscription from Stripe: {e}")

            subscription_data = SubscriptionResponse(
                plan=plan, next_billing_date=next_billing, customer_id=customer_id
            )
            await RedisOperations.set_json(redis, cache_key, subscription_data.dict(), ex=3600)
            return subscription_data
        except Exception as e:
            logger.error(f"Subscription lookup failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve subscription information",
            )


@router.post("/create-checkout-session", response_model=CheckoutSessionResponse)
async def create_checkout_session(
    request: Request,
    data: CheckoutRequest,
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
) -> CheckoutSessionResponse:
    """
    Crea una checkout session de Stripe para suscripción.
    """
    request_id = getattr(request.state, "correlation_id", "unknown")
    with logger.contextualize(request_id=request_id):
        try:
            user_id = current_client.sub
            plan = data.plan

            logger.info(f"Creating checkout session for user {user_id}, plan: {plan}")
            # Rate limit de creación de checkout por usuario+IP: 5/min
            client_ip = request.client.host if request.client else "unknown"
            await enforce_rate_limit(redis, bucket=f"bill:create:{user_id}:{client_ip}", limit=5, window=60)

            client_hash = create_hashed_key(user_id)
            api_key_hashes = await redis.smembers(f"api_keys:{client_hash}")
            if not api_key_hashes:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No API keys found. Please create an API key first.",
                )

            api_key_hash = await _get_active_api_key(api_key_hashes, redis)
            if not api_key_hash:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active API keys found")

            customer_id = await _get_or_create_customer(user_id, api_key_hash, redis)
            price_id = settings.stripe.premium_plan_id if plan == "PREMIUM" else settings.stripe.enterprise_plan_id
            # Idempotencia hacia Stripe (resolución a minuto)
            minute_bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
            idemp_key = f"checkout:{user_id}:{plan}:{minute_bucket}"

            session = await StripeClient.create_checkout_session(
                customer=customer_id,
                payment_method_types=["card"],
                line_items=[{"price": price_id, "quantity": 1}],
                mode="subscription",
                success_url=settings.stripe.success_url,
                cancel_url=settings.stripe.cancel_url,
                metadata={"user_id": user_id, "api_key_hash": api_key_hash, "plan": plan},
                subscription_data={"metadata": {"user_id": user_id, "api_key_hash": api_key_hash, "plan": plan}},
                idempotency_key=idemp_key,
            )

            session_id = session.get("id") if hasattr(session, "get") else session.id
            logger.info(f"Checkout session created: {session_id}")
            return CheckoutSessionResponse(session_id=session_id)
        except stripe.StripeError as e:
            logger.error(f"Stripe error creating checkout session: {e}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Payment provider error: {str(e)}")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error creating checkout session: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@router.post("/test-notification")
async def test_notification(
    data: Dict[str, str],
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
) -> Dict[str, Union[str, bool]]:
    """
    Envía un email de prueba de cambio de plan.
    """
    user_id = current_client.sub
    # Rate limit de notificaciones de prueba: 3/10min por usuario+IP
    client_ip = None
    try:
        from fastapi import Request as _R  # para hints estáticos si fuese necesario
        # request no está en la firma aquí; si lo deseas, añade 'request: Request' al endpoint
    except Exception:
        pass
    client_ip = locals().get("request").client.host if "request" in locals() and locals()["request"] and getattr(locals()["request"], "client", None) else "unknown"
    await enforce_rate_limit(redis, bucket=f"bill:testnote:{user_id}:{client_ip}", limit=3, window=600)
    user_key = f"user:{user_id}"
    user_email_b = await redis.hget(user_key, "email")
    user_email = await RedisOperations.bytes_to_str(user_email_b)

    success = await email_service.send_plan_change_notification(
        user_email, data.get("old_plan", "FREE"), data.get("new_plan", "PREMIUM")
    )
    return {"notification_sent": bool(success), "email": user_email}


@router.post("/change-plan")
async def change_plan(
    plan: str = Body(..., embed=True),
    current_user: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
) -> Dict[str, Any]:
    """Cambiar el plan del usuario."""
    if plan not in ["FREE", "PREMIUM", "ENTERPRISE"]:
        raise HTTPException(status_code=400, detail="Plan inválido")

    user_id = current_user.sub
    email = getattr(current_user, "email", "")

    # ✅ Actualizar PRIMERO en Redis
    now = datetime.now(timezone.utc).isoformat()
    await redis.hset(
        f"user:{user_id}",
        mapping={
            "plan": plan,
            "updated_at": now,
        },
    )

    # ✅ LIMPIAR caché de suscripción para forzar refresh
    await redis.delete(f"user:{user_id}:subscription")

    # ✅ Propagar a todas las API keys
    await update_all_user_api_keys(user_id, plan, redis)

    # ✅ Generar NUEVOS tokens con plan actualizado
    from app.auth import create_access_token, create_refresh_token, store_refresh_token
    
    scopes = PLAN_SCOPES.get(plan.upper(), PLAN_SCOPES["FREE"])
    new_access_token = create_access_token(
        {"sub": user_id, "email": email},
        plan=plan,
        scopes=scopes
    )

    new_refresh_token, refresh_exp = create_refresh_token(
        {"sub": user_id, "email": email},
        plan=plan,
        scopes=scopes
    )

    refresh_payload = jwt.decode(new_refresh_token, options={"verify_signature": False})
    await store_refresh_token(refresh_payload["jti"], refresh_exp, redis)

    logger.info(f"Plan changed to {plan} for user {user_id}, new tokens generated")

    return {
        "status": "success",
        "plan": plan,
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": str(ACCESS_TOKEN_EXPIRE_MINUTES * 60),
    }


# Helpers

async def _resolve_user_id(current_client: TokenData, redis: Redis) -> Optional[str]:
    """
    Resuelve user_id desde el token actual o desde una API key hash asociada.
    """
    subject = current_client.sub
    if await redis.exists(f"user:{subject}"):
        return subject

    try:
        possible_hash = create_hashed_key(str(subject))
        key_data = await RedisOperations.get_json(redis, f"key:{possible_hash}")
        if key_data:
            return key_data.get("user_id")
    except Exception:
        pass
    return None


async def _get_active_api_key(api_key_hashes: List[bytes], redis: Redis) -> Optional[str]:
    """
    Devuelve el primer API key activo (no revocado).
    """
    for key_hash in api_key_hashes:
        key_hash_str = await RedisOperations.bytes_to_str(key_hash)
        if not key_hash_str:
            continue
        key_data = await RedisOperations.get_json(redis, f"key:{key_hash_str}")
        if key_data and key_data.get("status") != "revoked" and not key_data.get("revoked"):
            return key_hash_str
    return None


async def _get_or_create_customer(user_id: str, api_key_hash: str, redis: Redis) -> str:
    """
    Recupera o crea un customer en Stripe y mantiene el mapeo en Redis.
    """
    customer_id_b = await redis.hget(f"user:{user_id}", "stripe_customer_id")
    customer_id = await RedisOperations.bytes_to_str(customer_id_b)
    if customer_id:
        await redis.hset(f"customer:{customer_id}", mapping={"user_id": user_id, "api_key_hash": api_key_hash})
        return customer_id

    customer = await StripeClient.create_customer({"user_id": user_id, "api_key_hash": api_key_hash})
    new_customer_id = customer.get("id") if hasattr(customer, "get") else customer.id
    await redis.hset(f"user:{user_id}", "stripe_customer_id", new_customer_id)
    await redis.hset(f"customer:{new_customer_id}", mapping={"user_id": user_id, "api_key_hash": api_key_hash})
    logger.info(f"Created new customer: {new_customer_id}")
    return new_customer_id

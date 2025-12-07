import pytest
import pytest_asyncio
from unittest.mock import Mock, patch, AsyncMock
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from app.auth import router as auth_router
import fakeredis
import json
from datetime import datetime, timezone
import os
import stripe
import importlib
import sys

# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_settings():
    """Mock settings configuration"""
    settings = Mock()
    settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
    settings.jwt.access_token_expire_minutes = 30
    settings.jwt.refresh_token_expire_days = 7
    settings.jwt.issuer = "test-issuer"
    settings.jwt.audience = "test-audience"
    settings.stripe.secret_key.get_secret_value.return_value = "sk_test_123"
    settings.stripe.webhook_secret.get_secret_value.return_value = "whsec_test_123"
    settings.stripe.premium_plan_id = "price_premium_test"
    settings.stripe.enterprise_plan_id = "price_enterprise_test"
    settings.stripe.success_url = "http://test.com/success"
    settings.stripe.cancel_url = "http://test.com/cancel"
    # Add validation settings for DNSResolver
    settings.validation.mx_lookup_timeout = 2.0
    settings.validation.blocked_domains = []
    settings.validation.allowed_domains = []
    settings.validation.dns_nameservers = ["8.8.8.8", "1.1.1.1"]
    return settings

@pytest_asyncio.fixture
async def redis_client():
    """Fake Redis async client"""
    client = fakeredis.FakeAsyncRedis()
    await client.flushall()
    yield client
    await client.flushall()
    await client.aclose()

@pytest.fixture(scope="module", autouse=True)
def patch_validation_config():
    """Patch app.validation.config module-wide to avoid TypeError from Mock objects"""
    from app.validation import ValidationConfig
    validation_config = ValidationConfig(
        mx_lookup_timeout=2.0,
        smtp_timeout=8.0,
        smtp_ports=[25, 587, 465],
        smtp_use_tls=True,
        smtp_max_retries=2,
        mx_cache_ttl=3600,
        mx_cache_maxsize=500,
        disposable_domains=set(),
        dns_nameservers=["8.8.8.8", "1.1.1.1"],
        advanced_mx_check=True,
        prefer_ipv4=True,
        retry_attempts=3,
        retry_base_backoff=0.25,
        retry_max_backoff=2.0,
        smtp_max_total_time=15,
        smtp_sender="noreply@emailvalidator.com",
        smtp_skip_tls_verify=False,
        SMTP_HOST_LIMIT_PER_MIN=60
    )
    
    with patch('app.validation.config', validation_config):
        yield

@pytest.fixture
def billing_app(redis_client, mock_settings):
    """FastAPI app with billing routes"""
    with patch('app.config.settings', mock_settings), \
         patch('app.routes.billing_routes.settings', mock_settings), \
         patch('app.validation.settings', mock_settings), \
         patch('app.validation.DNSResolver') as mock_dns_resolver, \
         patch('app.routes.billing_routes.create_hashed_key', side_effect=lambda x: f"hash_{x}"), \
         patch('app.utils.create_hashed_key', side_effect=lambda x: f"hash_{x}"), \
         patch('app.auth.create_hashed_key', side_effect=lambda x: f"hash_{x}"):
        
        # Configure mock DNS resolver
        mock_dns_resolver.return_value = Mock()
        
        # Mock app.validation.config directly with a proper ValidationConfig
        # This avoids the TypeError from Mock objects being used in comparisons
        from app.validation import ValidationConfig
        validation_config = ValidationConfig(
            mx_lookup_timeout=2.0,
            smtp_timeout=8.0,
            smtp_ports=[25, 587, 465],
            smtp_use_tls=True,
            smtp_max_retries=2,
            mx_cache_ttl=3600,
            mx_cache_maxsize=500,
            disposable_domains=set(),
            dns_nameservers=["8.8.8.8", "1.1.1.1"],
            advanced_mx_check=True,
            prefer_ipv4=True,
            retry_attempts=3,
            retry_base_backoff=0.25,
            retry_max_backoff=2.0,
            smtp_max_total_time=15,
            smtp_sender="noreply@emailvalidator.com",
            smtp_skip_tls_verify=False,
            SMTP_HOST_LIMIT_PER_MIN=60
        )
        
        with patch('app.validation.config', validation_config):
            from app.routes.billing_routes import router as billing_router
            
            app = FastAPI()
            app.state.redis = redis_client
            app.include_router(auth_router)
            app.include_router(billing_router)
            yield app


@pytest_asyncio.fixture
async def client(billing_app):
    """Async client for billing app"""
    async with AsyncClient(transport=ASGITransport(app=billing_app), base_url="http://test") as ac:
        yield ac

@pytest.fixture
def valid_token():
    """Valid JWT token for testing"""
    from app.auth import create_access_token
    return create_access_token(
        data={"sub": "user_123", "email": "test@example.com"},
        plan="PREMIUM"
    )

# =============================================================================
# TESTS
# =============================================================================

class TestBillingWebhook:
    """Tests for POST /billing/webhook"""

    @pytest.mark.asyncio
    async def test_webhook_missing_signature(self, client):
        """Test webhook without signature header"""
        # Ensure we're NOT in dev/test mode - clear both DOCKER_ENV and TESTING
        with patch.dict(os.environ, {"TESTING": "", "DOCKER_ENV": ""}, clear=False):
            response = await client.post("/billing/webhook", json={"type": "test"})
            assert response.status_code == 400
            assert "Missing Stripe signature" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_webhook_invalid_signature(self, client):
        """Test webhook with invalid signature"""
        # Ensure we're NOT in dev/test mode
        with patch.dict(os.environ, {"TESTING": "", "DOCKER_ENV": ""}, clear=False):
            # Use real stripe exception class
            with patch('app.routes.billing_routes.stripe.Webhook.construct_event', 
                   side_effect=stripe.error.SignatureVerificationError("Invalid signature", "sig")):
                response = await client.post(
                    "/billing/webhook",
                    json={"type": "test"},
                    headers={"stripe-signature": "invalid_sig"}
                )
                assert response.status_code == 400
                assert "Invalid signature" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_webhook_success(self, client, redis_client):
        """Test successful webhook processing"""
        event_data = {
            "id": "evt_123",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_123",
                    "mode": "subscription",
                    "subscription": "sub_123",
                    "metadata": {"user_id": "user_123"}
                }
            }
        }
        
        with patch('stripe.Webhook.construct_event', return_value=event_data), \
             patch('app.routes.billing_routes.BillingManager.process_webhook_event') as mock_process:
            
            response = await client.post(
                "/billing/webhook",
                json=event_data,
                headers={"stripe-signature": "valid_sig"}
            )
            
            assert response.status_code == 200
            assert response.json()["status"] == "received"
            # Background task should be triggered
            # Note: Testing background tasks with TestClient is tricky, usually we verify the response
            # and assume FastAPI handles the background task dispatch.

    @pytest.mark.asyncio
    async def test_webhook_dev_mode(self, client, redis_client):
        """Test webhook in dev mode (skips signature)"""
        with patch.dict(os.environ, {"DOCKER_ENV": "1"}):
            event_data = {"id": "evt_dev", "type": "test.event"}
            
            response = await client.post(
                "/billing/webhook",
                json=event_data
                # No signature header
            )
            
            assert response.status_code == 200
            assert response.json()["status"] == "received"

class TestSubscriptionEndpoint:
    """Tests for GET /billing/subscription"""

    @pytest.mark.asyncio
    async def test_get_subscription_unauthorized(self, client):
        """Test access without token"""
        response = await client.get("/billing/subscription")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_get_subscription_cached(self, client, redis_client, valid_token):
        """Test retrieving cached subscription"""
        user_id = "user_123"
        # Setup user existence for _resolve_user_id
        await redis_client.hset(f"user:{user_id}", "plan", "ENTERPRISE")
        
        cache_key = f"user:{user_id}:subscription"
        cached_data = {
            "plan": "ENTERPRISE",
            "next_billing_date": "2025-01-01T00:00:00Z",
            "customer_id": "cus_123"
        }
        await redis_client.set(cache_key, json.dumps(cached_data))
        
        response = await client.get(
            "/billing/subscription",
            headers={"Authorization": f"Bearer {valid_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["plan"] == "ENTERPRISE"
        assert data["customer_id"] == "cus_123"

    @pytest.mark.asyncio
    async def test_get_subscription_db_fallback(self, client, redis_client, valid_token):
        """Test retrieving from DB (Redis hash) when cache miss"""
        user_id = "user_123"
        user_key = f"user:{user_id}"
        
        await redis_client.hset(user_key, mapping={
            "plan": "PREMIUM",
            "next_billing_date": "2025-02-01T00:00:00Z",
            "stripe_customer_id": "cus_456"
        })
        
        response = await client.get(
            "/billing/subscription",
            headers={"Authorization": f"Bearer {valid_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["plan"] == "PREMIUM"
        assert data["customer_id"] == "cus_456"

class TestCheckoutSession:
    """Tests for POST /billing/create-checkout-session"""

    @pytest.fixture
    def long_user_id(self):
        return "user_" + "a" * 32

    @pytest.fixture
    def valid_token_long(self, long_user_id):
        from app.auth import create_access_token
        return create_access_token(
            data={"sub": long_user_id, "email": "test@example.com"},
            plan="PREMIUM"
        )

    @pytest.mark.asyncio
    async def test_create_checkout_session_success(self, client, valid_token_long, redis_client, long_user_id):
        """Test successful session creation"""
        # Setup API key for user to pass validation
        # We use the same logic as the mock: hash_{user_id}
        client_hash = f"hash_{long_user_id}"
        
        # We need to simulate that the user has at least one API key
        # And that key must be active for _get_active_api_key
        key_hash = "some_key_hash"
        await redis_client.sadd(f"api_keys:{client_hash}", key_hash)
        await redis_client.set(f"key:{key_hash}", json.dumps({"status": "active", "revoked": False}))
        
        # Also need user mapping for _get_or_create_customer
        await redis_client.hset(f"user:{long_user_id}", "stripe_customer_id", "cus_existing")
        await redis_client.hset("customer:cus_existing", mapping={"user_id": long_user_id, "api_key_hash": key_hash})

        with patch('app.routes.billing_routes.StripeClient.create_checkout_session') as mock_create:
            mock_create.return_value = {"id": "cs_test_123"}
            
            response = await client.post(
                "/billing/create-checkout-session",
                headers={"Authorization": f"Bearer {valid_token_long}"},
                json={"plan": "PREMIUM"}
            )
            
            assert response.status_code == 200
            assert response.json()["session_id"] == "cs_test_123"

    @pytest.mark.asyncio
    async def test_create_checkout_session_invalid_plan(self, client, valid_token_long):
        """Test with invalid plan"""
        response = await client.post(
            "/billing/create-checkout-session",
            headers={"Authorization": f"Bearer {valid_token_long}"},
            json={"plan": "INVALID_PLAN"}
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_checkout_session_no_api_keys(self, client, valid_token_long, redis_client):
        """Test failing when user has no API keys"""
        # Ensure no keys exist
        
        response = await client.post(
            "/billing/create-checkout-session",
            headers={"Authorization": f"Bearer {valid_token_long}"},
            json={"plan": "PREMIUM"}
        )
        assert response.status_code == 400
        assert "No API keys found" in response.json()["detail"]

class TestChangePlan:
    """Tests for POST /billing/change-plan"""

    @pytest.mark.asyncio
    async def test_change_plan_success(self, client, valid_token, redis_client):
        """Test changing plan successfully"""
        user_id = "user_123"
        await redis_client.hset(f"user:{user_id}", "plan", "FREE")
        
        response = await client.post(
            "/billing/change-plan",
            headers={"Authorization": f"Bearer {valid_token}"},
            json={"plan": "ENTERPRISE"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["plan"] == "ENTERPRISE"
        assert "access_token" in data
        
        # Verify Redis update
        new_plan = await redis_client.hget(f"user:{user_id}", "plan")
        assert new_plan.decode() == "ENTERPRISE"

    @pytest.mark.asyncio
    async def test_change_plan_invalid(self, client, valid_token):
        """Test changing to invalid plan"""
        response = await client.post(
            "/billing/change-plan",
            headers={"Authorization": f"Bearer {valid_token}"},
            json={"plan": "INVALID"}
        )
        assert response.status_code == 400

class TestNotification:
    """Tests for POST /billing/test-notification"""

    @pytest.mark.asyncio
    async def test_notification_success(self, client, valid_token, redis_client):
        """Test sending notification"""
        user_id = "user_123"
        await redis_client.hset(f"user:{user_id}", "email", "test@example.com")
        
        with patch('app.routes.billing_routes.email_service.send_plan_change_notification', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = True
            
            response = await client.post(
                "/billing/test-notification",
                headers={"Authorization": f"Bearer {valid_token}"},
                json={"old_plan": "FREE", "new_plan": "PREMIUM"}
            )
            
            assert response.status_code == 200
            assert response.json()["notification_sent"] is True
            mock_send.assert_called_once()

class TestBillingManagerCoverage:
    """Tests for BillingManager and EventProcessor logic"""

    @pytest.fixture(autouse=True)
    def setup_patches(self, billing_app):
        """Ensure patches from billing_app are active"""
        pass

    @pytest.mark.asyncio
    async def test_process_webhook_idempotency(self, redis_client):
        """Test that processed events are skipped"""
        from app.routes.billing_routes import BillingManager, EventProcessor
        
        event = {"id": "evt_idempotent", "type": "test.event"}
        await EventProcessor.mark_event_processed(redis_client, "evt_idempotent")
        
        # Should return early
        with patch('app.routes.billing_routes.LockManager.acquire_lock') as mock_lock:
            await BillingManager.process_webhook_event(event, redis_client)
            mock_lock.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_webhook_lock_busy(self, redis_client):
        """Test when lock is busy"""
        from app.routes.billing_routes import BillingManager
        
        event = {"id": "evt_busy", "type": "test.event"}
        
        # Mock lock to return None (busy)
        with patch('app.routes.billing_routes.LockManager.acquire_lock') as mock_lock:
            mock_lock.return_value.__aenter__.return_value = None
            
            await BillingManager.process_webhook_event(event, redis_client)
            
            # Should not mark as processed
            from app.routes.billing_routes import EventProcessor
            assert not await EventProcessor.is_event_processed(redis_client, "evt_busy")

    @pytest.mark.asyncio
    async def test_process_checkout_session_payment_mode(self, redis_client):
        """Test skipping payment mode sessions"""
        from app.routes.billing_routes import EventProcessor
        
        event = {
            "data": {
                "object": {
                    "id": "cs_payment",
                    "mode": "payment"
                }
            }
        }
        
        with patch('app.routes.billing_routes.logger') as mock_logger:
            await EventProcessor.process_checkout_session_completed(event, redis_client)
            # Should log skipping
            mock_logger.info.assert_any_call("Skipping non-subscription session: payment")

    @pytest.mark.asyncio
    async def test_process_subscription_updated(self, redis_client):
        """Test processing subscription update"""
        from app.routes.billing_routes import BillingManager
        
        event = {
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_updated",
                    "status": "active",
                    "customer": "cus_updated",
                    "items": {"data": [{"price": {"id": "price_premium_test"}}]},
                    "current_period_end": 1735689600
                }
            }
        }
        
        await redis_client.hset("customer:cus_updated", "user_id", "user_updated")
        
        # ✅ AGREGAR: Mock las operaciones de Stripe
        with patch('app.routes.billing_routes.StripeClient.retrieve_subscription') as mock_retrieve, \
            patch('app.routes.billing_routes.LockManager.acquire_lock') as mock_lock:
            
            # Configurar el mock para devolver la subscripción del evento
            mock_retrieve.return_value = event["data"]["object"]
            mock_lock.return_value.__aenter__.return_value = "token"
            
            await BillingManager._process_subscription_updated(event, redis_client)
        
        plan = await redis_client.hget("user:user_updated", "plan")
        assert plan.decode() == "PREMIUM"


    @pytest.mark.asyncio
    async def test_extract_user_info_fallback(self, redis_client):
        """Test extracting user info from customer when metadata missing"""
        from app.routes.billing_routes import EventProcessor, StripeClient
        
        session = {
            "metadata": {},
            "customer": "cus_fallback"
        }
        
        # Mock Stripe customer retrieval
        with patch('app.routes.billing_routes.StripeClient.call_with_retry') as mock_call:
            mock_call.return_value = {
                "metadata": {"user_id": "user_fallback", "api_key_hash": "hash_fallback"}
            }
            
            info = await EventProcessor._extract_user_info(session, redis_client)
            
            assert info["user_id"] == "user_fallback"
            assert info["api_key_hash"] == "hash_fallback"
            
            # Note: The code does NOT cache the fallback result in Redis, so we don't assert that.

    @pytest.mark.asyncio
    async def test_process_checkout_session_missing_user(self, redis_client):
        """Test session with missing user info"""
        from app.routes.billing_routes import EventProcessor
        
        event = {
            "id": "evt_missing_user",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_missing",
                    "mode": "subscription",
                    "metadata": {}
                }
            }
        }
        
        await EventProcessor.process_checkout_session_completed(event, redis_client)
        
        # Should be in failed events queue
        from app.routes.billing_routes import RAW_EVENTS_QUEUE
        failed = await redis_client.lrange(RAW_EVENTS_QUEUE, 0, -1)
        assert len(failed) > 0
        assert b"missing_user_id" in failed[0]

class TestErrorHandlingCoverage:
    """Tests for error handling in endpoints"""

    @pytest.fixture(autouse=True)
    def setup_patches(self, billing_app):
        """Ensure billing_app fixture is loaded"""
        yield

    @pytest.mark.asyncio
    async def test_webhook_signature_error(self, client):
        """Test webhook with invalid signature"""
        # Ensure we're NOT in dev/test mode
        with patch.dict(os.environ, {"TESTING": "", "DOCKER_ENV": ""}, clear=False):
            # Use the real stripe exception, just patch the construct_event method
            with patch('app.routes.billing_routes.stripe.Webhook.construct_event', 
                       side_effect=stripe.error.SignatureVerificationError("Bad sig", "sig")):
                response = await client.post(
                    "/billing/webhook",
                    json={"id": "evt_test"},
                    headers={"stripe-signature": "bad_sig"}
                )
                assert response.status_code == 400
                assert "Invalid signature" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_webhook_value_error(self, client):
        """Test webhook with invalid payload"""
        # Ensure we're NOT in dev/test mode
        with patch.dict(os.environ, {"TESTING": "", "DOCKER_ENV": ""}, clear=False):
            # Don't mock stripe module, just patch construct_event
            with patch('app.routes.billing_routes.stripe.Webhook.construct_event', 
                       side_effect=ValueError("Invalid payload")):
                response = await client.post(
                    "/billing/webhook",
                    content=b"invalid",
                    headers={"stripe-signature": "sig"}
                )
                assert response.status_code == 400
                assert "Invalid webhook" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_webhook_generic_exception(self, client):
        """Test webhook with unexpected error"""
        # Ensure we're NOT in dev/test mode
        with patch.dict(os.environ, {"TESTING": "", "DOCKER_ENV": ""}, clear=False):
            # Don't mock stripe module, just patch construct_event
            with patch('app.routes.billing_routes.stripe.Webhook.construct_event', 
                       side_effect=TypeError("Boom")):
                response = await client.post(
                    "/billing/webhook",
                    json={"id": "evt_test"},
                    headers={"stripe-signature": "sig"}
                )
                assert response.status_code == 400
                # All exceptions (except SignatureVerificationError) return "Invalid webhook"
                assert "Invalid webhook" in response.json()["detail"]

class TestBillingUtilitiesCoverage:
    """Tests for utility classes and helpers"""

    def test_mask_pii(self):
        from app.routes.billing_routes import BillingSecurity
        
        assert BillingSecurity.mask_pii("test@example.com") == "t***@e***.com"
        assert BillingSecurity.mask_pii("user.name@domain.co.uk") == "u***@d***.co.uk"
        assert BillingSecurity.mask_pii("no_email_here") == "no_email_here"
        assert BillingSecurity.mask_pii(None) == ""

    def test_sanitize_metadata_value(self):
        from app.routes.billing_routes import BillingSecurity
        
        assert BillingSecurity.sanitize_metadata_value("valid_123") == "valid_123"
        assert BillingSecurity.sanitize_metadata_value("invalid!@#") == "invalid"
        assert BillingSecurity.sanitize_metadata_value(None) == ""

    @pytest.mark.asyncio
    async def test_redis_operations_errors(self):
        """Test RedisOperations error handling"""
        from app.routes.billing_routes import RedisOperations
        from redis.exceptions import RedisError
        
        mock_redis = AsyncMock()
        mock_redis.get.side_effect = RedisError("Fail")
        mock_redis.set.side_effect = RedisError("Fail")
        
        # Properly mock pipeline (pipeline() is sync, but execute() is async)
        mock_pipeline = Mock()
        mock_pipeline.rpush = Mock()
        mock_pipeline.ltrim = Mock()
        mock_pipeline.execute = AsyncMock(side_effect=RedisError("Fail"))
        mock_redis.pipeline = Mock(return_value=mock_pipeline)
        
        # Should not raise exceptions
        await RedisOperations.get_json(mock_redis, "key")
        await RedisOperations.set_json(mock_redis, "key", {})
        await RedisOperations.lpush_trim(mock_redis, "key", "val", 10)

    @pytest.mark.asyncio
    async def test_redis_operations_json_error(self):
        """Test JSON decode error"""
        from app.routes.billing_routes import RedisOperations
        
        mock_redis = AsyncMock()
        mock_redis.get.return_value = b"invalid json"
        
        result = await RedisOperations.get_json(mock_redis, "key")
        assert result is None

    @pytest.mark.asyncio
    async def test_lock_manager_helpers(self, redis_client):
        """Test LockManager helper methods"""
        from app.routes.billing_routes import LockManager
        
        with patch('app.routes.billing_routes.LockManager.acquire_lock') as mock_lock:
            mock_lock.return_value.__aenter__.return_value = "token"
            
            assert await LockManager.acquire_processing_lock(redis_client, "evt_1") == "token"
            assert await LockManager.acquire_user_lock(redis_client, "user_1") == "token"

    def test_extract_plan_info(self):
        """Test extracting plan info from subscription"""
        from app.routes.billing_routes import EventProcessor
        
        # Test standard case
        sub = {
            "id": "sub_123",
            "current_period_end": 1735689600,
            "items": {"data": [{"price": {"id": "price_premium"}}]}
        }
        
        with patch('app.routes.billing_routes.settings') as mock_settings:
            mock_settings.stripe.premium_plan_id = "price_premium"
            
            info = EventProcessor._extract_plan_info(sub)
            assert info["plan"] == "PREMIUM"
            assert "2025" in info["next_billing"]

    def test_extract_plan_info_invalid_date(self):
        """Test extracting plan info with invalid date"""
        from app.routes.billing_routes import EventProcessor
        
        sub = {
            "id": "sub_123",
            "current_period_end": "invalid",
            "items": {"data": []}
        }
        
        info = EventProcessor._extract_plan_info(sub)
        assert info["next_billing"] == ""

    @pytest.mark.asyncio
    async def test_store_failed_event(self, redis_client):
        """Test storing failed event"""
        from app.routes.billing_routes import EventProcessor, RAW_EVENTS_QUEUE
        
        event = {"id": "evt_fail", "type": "test"}
        await EventProcessor._store_failed_event(redis_client, event, "phase_1", "error_1")
        
        stored = await redis_client.lrange(RAW_EVENTS_QUEUE, 0, -1)
        assert len(stored) == 1
        data = json.loads(stored[0])
        assert data["event_id"] == "evt_fail"
        assert data["error"] == "error_1"

    @pytest.mark.asyncio
    async def test_get_subscription_redis_error(self, client, valid_token, redis_client):
        """Test get subscription with Redis error"""
        # If Redis fails, it should fallback to FREE plan gracefully
        with patch.object(redis_client, 'get', side_effect=Exception("Redis fail")):
            response = await client.get(
                "/billing/subscription",
                headers={"Authorization": f"Bearer {valid_token}"}
            )
            assert response.status_code == 200
            assert response.json()["plan"] == "FREE"

    @pytest.mark.asyncio
    async def test_create_checkout_session_stripe_error(self, client, valid_token, redis_client):
        """Test checkout session with Stripe error"""
        import stripe
        
        # Setup prerequisites
        user_id = "user_123"
        client_hash = f"hash_{user_id}"
        await redis_client.sadd(f"api_keys:{client_hash}", "key_hash")
        await redis_client.set("key:key_hash", json.dumps({"status": "active"}))
        await redis_client.hset(f"user:{user_id}", "stripe_customer_id", "cus_123")
        await redis_client.hset("customer:cus_123", mapping={"user_id": user_id, "api_key_hash": "key_hash"})

        with patch('app.routes.billing_routes.StripeClient.create_checkout_session', side_effect=stripe.StripeError("Stripe fail")):
            response = await client.post(
                "/billing/create-checkout-session",
                headers={"Authorization": f"Bearer {valid_token}"},
                json={"plan": "PREMIUM"}
            )
            assert response.status_code == 400
            assert "Payment provider error" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_user_subscription_lock_fail(self, redis_client):
        """Test subscription update when user lock fails"""
        from app.routes.billing_routes import EventProcessor
        
        user_info = {"user_id": "user_locked"}
        session = {"subscription": "sub_123"}
        
        with patch('app.routes.billing_routes.LockManager.acquire_lock') as mock_lock:
            mock_lock.return_value.__aenter__.return_value = None
            
            await EventProcessor._update_user_subscription(user_info, session, redis_client)
            # Should return without error but log warning
            # We can verify no update happened in Redis
            assert not await redis_client.exists("user:user_locked")

class TestStripeClientCoverage:
    """Tests for StripeClient retry logic"""

    @pytest.mark.asyncio
    async def test_call_with_retry_success(self):
        """Test successful call"""
        from app.routes.billing_routes import StripeClient
        
        mock_func = Mock(return_value="success")
        result = await StripeClient.call_with_retry(mock_func)
        assert result == "success"

    @pytest.mark.asyncio
    async def test_call_with_retry_failure(self):
        """Test failure after retries"""
        from app.routes.billing_routes import StripeClient
        import stripe
        
        mock_func = Mock(side_effect=stripe.APIConnectionError("Connection fail"))
        
        with pytest.raises(stripe.APIConnectionError):
            await StripeClient.call_with_retry(mock_func)
        
        assert mock_func.call_count == 3  # STRIPE_RETRIES default is 3

    @pytest.mark.asyncio
    async def test_call_with_retry_rate_limit(self):
        """Test rate limit handling"""
        from app.routes.billing_routes import StripeClient
        import stripe
        
        # Fail twice then succeed
        mock_func = Mock(side_effect=[
            stripe.RateLimitError("Rate limit"),
            stripe.RateLimitError("Rate limit"),
            "success"
        ])
        
        result = await StripeClient.call_with_retry(mock_func)
        assert result == "success"
        assert mock_func.call_count == 3


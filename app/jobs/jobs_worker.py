# jobs_worker.py — ARQ worker for batch email validation

from __future__ import annotations

import asyncio
import math
import os
import time
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional
from types import SimpleNamespace # Kept from original, not in instruction's snippet but needed for _StubRequest
from prometheus_client import start_http_server # Kept from original, not in instruction's snippet
from arq.connections import RedisSettings  # type: ignore
from redis.asyncio import Redis

import hashlib # Added from instruction's snippet
import hmac # Added from instruction's snippet
import httpx # Added from instruction's snippet
import json  # Standard json for response parsing

from app.logger import logger
from app.config import get_settings # Kept get_settings as it's used, instruction's snippet had 'settings' directly
from app.metrics import metrics_recorder # Kept from original, not in instruction's snippet
from app.json_utils import dumps as json_dumps, loads as json_loads  # Replaced orjson
from app.routes.validation_routes import validation_engine, validation_service
from app.utils import increment_usage
from app.jobs.webhooks import send_webhook


# Obtener configuración
settings = get_settings()
JOBS_QUEUE_KEY = "jobs:queue"
RETENTION_SECONDS_DEFAULT = 24 * 3600
DEFAULT_PAGE_SIZE = int(os.getenv("JOB_RESULTS_PAGE_SIZE", "1000"))
WORKER_CONCURRENCY = int(os.getenv("JOB_WORKER_CONCURRENCY", "20"))

async def get_redis_worker():
    # Usa la misma URL que tu API para compartir estado y colas
    return Redis.from_url(str(settings.redis_url), encoding="utf-8", decode_responses=False)

class _StubRequest(SimpleNamespace):
    # Mínimo necesario para métricas y compatibilidad
    def __init__(self) -> None:
        super().__init__(headers={}, client=SimpleNamespace(host="jobs-worker"))

async def _load_emails_for_job(redis, payload: Dict[str, Any]) -> List[str]:
    source = payload.get("source")
    if source == "list":
        emails = payload.get("emails") or []
        if not isinstance(emails, list):
            raise ValueError("Invalid emails payload")
        return [str(e).strip() for e in emails if e]
    if source == "upload":
        token = (payload.get("file_token") or "").strip()
        if not token:
            raise ValueError("file_token missing for upload source")
        key = f"upload:{token}:emails"
        raw = await redis.get(key)
        if not raw:
            raise ValueError("Upload token not found or expired")
        try:
            emails = json_loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw))
        except Exception:
            emails = []
        if not isinstance(emails, list):
            raise ValueError("Upload token does not contain a list")
        return [str(e).strip() for e in emails if e]
    raise ValueError("Unsupported source")

async def _set_meta(redis, job_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    meta_key = f"jobs:{job_id}:meta"
    raw = await redis.get(meta_key)
    meta: Dict[str, Any] = {}
    if raw:
        try:
            meta = json_loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw))
        except Exception:
            meta = {}
    meta.update(patch or {})
    ttl = int(meta.get("retention_seconds", RETENTION_SECONDS_DEFAULT) or RETENTION_SECONDS_DEFAULT)
    await redis.set(meta_key, json_dumps(meta), ex=ttl)
    return meta

async def _write_page(redis, job_id: str, page_index: int, total_pages: int, results: List[Dict[str, Any]]) -> None:
    key = f"jobs:{job_id}:results:page:{page_index}"
    payload = {"total_pages": int(total_pages), "results": results}
    await redis.set(key, json_dumps(payload), ex=RETENTION_SECONDS_DEFAULT)

def _sandbox_result(email: str) -> Dict[str, Any]:
    e = (email or "").lower().strip()
    def base(valid: bool, detail: str, risk: float, quality: float, extra: Dict[str, Any] = None):
        out = {
            "email": email,
            "valid": valid,
            "detail": detail,
            "processing_time": 0.012,
            "risk_score": round(risk, 3),
            "quality_score": round(quality, 3),
            "validation_tier": "sandbox",
            "suggested_action": "accept" if valid and risk < 0.5 else ("review" if risk < 0.8 else "reject"),
            "provider_analysis": {"provider": "sandbox.mx", "reputation": 0.75, "fingerprint": "sandbox"},
            "smtp_validation": {"checked": False, "mailbox_exists": valid},
            "dns_checks": {"checked": False, "mx": [], "spf": None, "dkim": None, "dmarc": None},
            "error_type": None,
            "metadata": {"sandbox": True},
        }
        if extra:
            out.update(extra)
        return out
    if e.startswith("valid+"):
        return base(True, "Deliverable (sandbox)", 0.1, 0.95)
    if e.startswith("invalid+"):
        return base(False, "Undeliverable (sandbox)", 0.95, 0.2, {"error_type": "mailbox_not_found"})
    if e.startswith("catchall+"):
        return base(True, "Catch-all domain (sandbox)", 0.4, 0.7, {"error_type": "catch_all"})
    if e.startswith("unknown+"):
        return base(False, "Unknown (sandbox)", 0.7, 0.5, {"error_type": "unknown"})
    if e.startswith("disposable+"):
        return base(False, "Disposable domain (sandbox)", 0.9, 0.1, {"error_type": "disposable_domain"})
    if e.startswith("role+"):
        return base(False, "Role-based address (sandbox)", 0.8, 0.4, {"error_type": "role_based"})
    return base(True, "Deliverable (sandbox default)", 0.3, 0.8)

async def _validate_one(email: str, opts: Dict[str, Any], redis, user_id: str, plan: str) -> Dict[str, Any]:
    if bool(opts.get("sandbox")):
        return _sandbox_result(email)
    resp = await validation_engine.perform_comprehensive_validation(
        email=email,
        check_smtp=bool(opts.get("checksmtp")),
        include_raw_dns=bool(opts.get("includerawdns")),
        request=_StubRequest(),
        redis=redis,
        user_id=user_id,
        plan=plan,
    )
    try:
        return json.loads(resp.body.decode())
    except Exception:
        return {"email": email, "valid": False, "detail": "Unexpected response", "error_type": "unexpected_response"}

async def _get_secret_for_endpoint(redis, user_id: str, callback_url: str) -> Optional[str]:
    import hashlib
    eid = hashlib.sha256(callback_url.encode("utf-8")).hexdigest()
    active = await redis.get(f"webhook:{user_id}:{eid}:secret_active")
    if active:
        return active.decode("utf-8") if isinstance(active, (bytes, bytearray)) else str(active)
    return None

async def _send_job_webhook(redis, user_id: str, callback_url: Optional[str], event: str, job_id: str, summary: Dict[str, Any], finished_at_iso: Optional[str], metadata: Dict[str, Any]) -> None:
    if not callback_url:
        return
    secret = await _get_secret_for_endpoint(redis, user_id, callback_url)
    if not secret:
        return
    payload = {
        "event": event,
        "job_id": job_id,
        "summary": summary,
        "finished_at": finished_at_iso,
        "metadata": metadata or {},
        "version": "1",
    }
    try:
        await send_webhook(callback_url, secret, payload, event_id=job_id)
    except Exception as ex:
        await _set_meta(redis, job_id, {"webhook_error": str(ex)})

async def process_job(redis, payload: Dict[str, Any]) -> None:
    job_id = payload["job_id"]
    creator = payload.get("creator") or "unknown"
    plan = (payload.get("plan") or "FREE").upper()
    options = payload.get("options") or {}
    started_at = time.time()

    # evento started
    try:
        metrics_recorder.record_job_event(plan, "started")
    except Exception as e:
        logger.debug(f"Metrics recording failed: {e}")

    # Estado inicial: processing
    meta = await _set_meta(redis, job_id, {"status": "processing", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at))})

    # Cargar emails
    emails = await _load_emails_for_job(redis, payload)
    total = len(emails)
    callback_url = meta.get("callback_url")
    metadata = meta.get("metadata") or {}

    # Fast-fail: sin emails
    if total == 0:
        await _set_meta(redis, job_id, {"status": "failed", "error": "no_emails", "counts": {"total": 0, "completed": 0, "failed": 0, "processing": 0}})
        await _send_job_webhook(redis, creator, callback_url, "job.failed", job_id, {"total": 0, "completed": 0, "failed": 0, "processing": 0}, None, metadata)
        try:
            metrics_recorder.observe_job_duration(plan, time.time() - started_at)
            metrics_recorder.record_job_event(plan, "failed")
        except Exception as e:
            logger.debug(f"Metrics recording failed: {e}")
        return

    # Chequeo de cuota diaria
    rate = await validation_service.check_rate_limits(redis, user_id=creator, plan=plan, requested_count=total)
    if not rate.get("allowed", True):
        await _set_meta(redis, job_id, {"status": "failed", "error": f"quota_exceeded: remaining={rate.get('remaining')}", "counts": {"total": total, "completed": 0, "failed": 0, "processing": 0}})
        await _send_job_webhook(redis, creator, callback_url, "job.failed", job_id, {"total": total, "completed": 0, "failed": 0, "processing": 0}, None, metadata)
        try:
            metrics_recorder.observe_job_duration(plan, time.time() - started_at)
            metrics_recorder.record_job_event(plan, "failed")
        except Exception as e:
            logger.debug(f"Metrics recording failed: {e}")
        return

    # Concurrencia interna del worker
    sem = asyncio.Semaphore(WORKER_CONCURRENCY)

    async def runner(e: str) -> Dict[str, Any]:
        async with sem:
            t0 = time.time()
            try:
                r = await _validate_one(e, options, redis, creator, plan)
            except Exception as ex:
                logger.error("Validation failed for %s: %s", e, str(ex))
                r = {
                    "email": e,
                    "valid": False,
                    "detail": f"Validation error: {ex}",
                    "error_type": "validation_error",
                    "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                }
            # métrica de validación individual
            try:
                dur = time.time() - t0
                # clasifica resultado: unknown tiene prioridad si aparece
                err = (r.get("error_type") or "").lower()
                if err == "unknown":
                    result = "unknown"
                else:
                    result = "valid" if bool(r.get("valid")) else "invalid"
                # usa el recorder existente para validations_total y validation_duration
                from app.metrics import track_validation_metrics  # si ya tienes decorador, emite directamente:
                metrics_recorder.record_validation("batch", result, plan, dur)  # método ya presente en metrics.py
            except Exception as e:
                logger.debug(f"Validation metrics recording failed: {e}")
            return r

    # Procesar en lotes y paginar
    page_size = max(1, int(os.getenv("JOB_RESULTS_PAGE_SIZE", DEFAULT_PAGE_SIZE)))
    total_pages = max(1, math.ceil(total / page_size))
    completed = 0
    failed = 0

    for page_index in range(1, total_pages + 1):
        start = (page_index - 1) * page_size
        chunk = emails[start : start + page_size]
        tasks = [asyncio.create_task(runner(e)) for e in chunk]
        page_results = await asyncio.gather(*tasks)

        # Conteos
        for r in page_results:
            if r.get("valid"):
                completed += 1
            else:
                # "failed" reservado para errores de sistema; los inválidos funcionales no suman aquí
                failed += 0

        # Escribir página
        await _write_page(redis, job_id, page_index, total_pages, page_results)

        # Progreso parcial
        await _set_meta(redis, job_id, {"counts": {"total": total, "completed": completed, "failed": failed, "processing": max(0, total - completed)}})

    # Incrementar uso al final
    try:
        await increment_usage(redis, creator, total)
    except Exception as e:
        logger.debug(f"Usage increment failed: {e}")

    finished_at_ts = time.time()
    finished_at_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished_at_ts))
    final_counts = {"total": total, "completed": completed, "failed": failed, "processing": 0}

    await _set_meta(
        redis,
        job_id,
        {
            "status": "completed",
            "finished_at": finished_at_iso,
            "counts": final_counts,
            "duration_sec": round(finished_at_ts - started_at, 3),
        },
    )

    try:
        metrics_recorder.observe_job_duration(plan, finished_at_ts - started_at)
        metrics_recorder.record_job_event(plan, "completed")
    except Exception as e:
        logger.debug(f"Metrics recording failed: {e}")

    # Webhook final (completed)
    await _send_job_webhook(redis, creator, callback_url, "job.completed", job_id, final_counts, finished_at_iso, metadata)

JOBS_QUEUE_KEY = "jobs:queue"
QUEUE_SAMPLER_INTERVAL = int(os.getenv("QUEUE_SAMPLER_INTERVAL", "5"))  # 5s por defecto

async def _queue_depth_sampler(redis):
    while True:
        try:
            depth = await redis.llen(JOBS_QUEUE_KEY)
            metrics_recorder.set_job_queue_depth(JOBS_QUEUE_KEY, depth)
        except Exception as e:
            logger.debug(f"Queue depth sampling failed: {e}")
        await asyncio.sleep(QUEUE_SAMPLER_INTERVAL)

async def run_worker_forever() -> None:
    redis = await get_redis_worker()
    asyncio.create_task(_queue_depth_sampler(redis))  # lanzar sampler en background
    logger.info("Jobs worker started; waiting for jobs...")
    while True:
        try:
            item = await redis.brpop(JOBS_QUEUE_KEY, timeout=10)
            if not item:
                # también puedes muestrear la cola periódicamente
                try:
                    depth = await redis.llen(JOBS_QUEUE_KEY)
                    metrics_recorder.set_job_queue_depth(JOBS_QUEUE_KEY, depth)
                except Exception as e:
                    logger.debug(f"Queue depth check failed: {e}")
                continue
            _, raw = item
            try:
                depth = await redis.llen(JOBS_QUEUE_KEY)
                metrics_recorder.set_job_queue_depth(JOBS_QUEUE_KEY, depth)
            except Exception as e:
                logger.debug(f"Queue depth check failed: {e}")
            try:
                payload = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw))
            except Exception:
                logger.error("Invalid job payload: cannot parse JSON")
                continue
            job_id = payload.get("job_id") or "unknown"
            try:
                await process_job(redis, payload)
                logger.info("Job %s processed", job_id)
            except Exception as ex:
                logger.exception("Job %s failed: %s", job_id, str(ex))
                await _set_meta(redis, job_id, {"status": "failed", "error": f"{ex}"})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Worker loop error")
            await asyncio.sleep(1.0)

if __name__ == "__main__":
    # expón /metrics del worker en 0.0.0.0:8001
    start_http_server(int(os.getenv("WORKER_METRICS_PORT", "8001")))
    asyncio.run(run_worker_forever())
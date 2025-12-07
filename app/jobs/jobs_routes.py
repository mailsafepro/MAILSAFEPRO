# app/jobs_routes.py
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import SecurityScopes
from pydantic import BaseModel, Field, model_validator   

from app.auth import get_redis, get_arq_redis, validate_api_key_or_token, TokenData  # nombres según tus exports reales
from app.config import get_settings
from app.logger import logger
from app.metrics import metrics_recorder

router = APIRouter(prefix="/v1", tags=["Jobs"])

RETENTION_SECONDS_DEFAULT = 24 * 3600  # privacidad por defecto: no-store > 24h
IDEMPOTENCY_TTL = 24 * 3600
JOBS_QUEUE_KEY = "jobs:queue"

class JobCreateRequest(BaseModel):
    source: str = Field(..., pattern="^(list|upload)$", description="Origen de los datos")
    emails: Optional[List[str]] = None
    file_token: Optional[str] = None
    checksmtp: bool = False
    includerawdns: bool = False
    callback_url: Optional[str] = None
    sandbox: bool = False
    metadata: Optional[Dict[str, Any]] = None

    @model_validator(mode='after')
    def validate_source_requirements(self):
        # Si source es 'list', emails es obligatorio
        if self.source == "list" and (not self.emails or len(self.emails) == 0):
            raise ValueError("emails requeridos cuando source = list")

        # Si source es 'upload', file_token es obligatorio
        if self.source == "upload" and not self.file_token:
            raise ValueError("file_token requerido cuando source = upload")

        return self


class JobCreateResponse(BaseModel):
    job_id: str
    status: str
    created_at: str

class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    counts: Dict[str, int] = Field(default_factory=dict)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None

class JobResultEntry(BaseModel):
    # Reusa tu contrato de batch/single; aquí campos mínimos para empezar
    email: str
    valid: bool
    riskscore: Optional[float] = None
    qualityscore: Optional[float] = None
    provider: Optional[str] = None
    reputation: Optional[float] = None
    smtp: Dict[str, Any] = Field(default_factory=dict)
    dns: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class JobResultsPage(BaseModel):
    job_id: str
    page: int
    size: int
    total_pages: int
    results: List[JobResultEntry]

def _now_iso() -> str:
    return datetime.utcnow().isoformat()

def _hash_idempotency(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

async def _get_json(redis, key: str) -> Optional[Dict[str, Any]]:
    raw = await redis.get(key)
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw))
    except Exception:
        return None

@router.post(
    "/jobs",
    response_model=JobCreateResponse,
    summary="Create validation job",
    responses={
        201: {"description": "Job queued"},
        400: {"description": "Invalid request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        409: {"description": "Idempotent replay"},
    },
)
async def create_job(
    request: Request,
    body: JobCreateRequest,
    current: TokenData = Security(validate_api_key_or_token, scopes=["job:create"]),
    x_idempotency_key: Optional[str] = Header(default=None, alias="X-Idempotency-Key"),
    redis=Depends(get_redis),
    arq_redis=Depends(get_arq_redis),
):
    # Idempotencia: si llega clave repetida en 24h, devolver el mismo job_id
    if x_idempotency_key:
        idem_hash = _hash_idempotency(x_idempotency_key)
        idem_key = f"idempotency:{idem_hash}"
        existing = await redis.get(idem_key)
        if existing:
            job_id = existing.decode("utf-8") if isinstance(existing, (bytes, bytearray)) else str(existing)
            meta = await _get_json(redis, f"jobs:{job_id}:meta")
            if meta:
                return JSONResponse(
                    status_code=status.HTTP_201_CREATED,
                    content={"job_id": job_id, "status": meta.get("status", "queued"), "created_at": meta.get("created_at", _now_iso())},
                )
    # Límite básico de tamaño por plan (reusa tu get_plan_config si quieres)
    if body.source == "list":
        emails_count = len(body.emails or [])
        if current.plan.upper() == "FREE" and emails_count > 100:
            raise HTTPException(status_code=403, detail="Batch not available on FREE plan")
    # Crea job_id y meta inicial
    job_id = str(uuid.uuid4())
    meta_key = f"jobs:{job_id}:meta"
    progress_key = f"jobs:{job_id}:progress"

    meta = {
        "job_id": job_id,
        "creator": getattr(current, "sub", "unknown"),
        "plan": getattr(current, "plan", "FREE"),
        "status": "queued",
        "created_at": _now_iso(),
        "source": body.source,
        "counts": {"queued": 0, "processing": 0, "completed": 0, "failed": 0, "total": 0},
        "options": {
            "checksmtp": body.checksmtp and current.plan.upper() != "FREE",
            "includerawdns": body.includerawdns and current.plan.upper() != "FREE",
            "sandbox": bool(body.sandbox),
        },
        "callback_url": body.callback_url,
        "metadata": body.metadata or {},
        "retention_seconds": RETENTION_SECONDS_DEFAULT,
        "started_at": None,
        "finished_at": None,
        "error": None,
    }
    # Persistir meta + encolar payload ligero (no-store por defecto)
    await redis.set(meta_key, json.dumps(meta), ex=RETENTION_SECONDS_DEFAULT)
    payload = {
        "job_id": job_id,
        "source": body.source,
        "emails": body.emails if (body.source == "list") else None,
        "file_token": body.file_token if (body.source == "upload") else None,
        "options": meta["options"],
        "creator": meta["creator"],
        "plan": meta["plan"],
        "callback_url": body.callback_url,
        "metadata": body.metadata or {},
        "created_at": meta["created_at"],
    }
    
    # Enqueue with ARQ
    await arq_redis.enqueue_job("validate_batch_task", job_id, payload)
    
    try:
        metrics_recorder.record_arq_job_event("default", "validate_batch_task", "queued")
    except Exception as e:
        logger.debug(f"Metrics recording failed (non-critical): {e}")
    await redis.set(progress_key, json.dumps({"status": "queued", "queued_at": _now_iso()}), ex=RETENTION_SECONDS_DEFAULT)
    if x_idempotency_key:
        await redis.setex(f"idempotency:{_hash_idempotency(x_idempotency_key)}", IDEMPOTENCY_TTL, job_id)
    logger.info(f"Job queued {job_id} by {meta['creator']}")
    try:
        metrics_recorder.record_job_event(getattr(current, "plan", "FREE"), "queued")
    except Exception as e:
        logger.debug(f"Metrics recording failed (non-critical): {e}")
    return JSONResponse(status_code=status.HTTP_201_CREATED, content={"job_id": job_id, "status": "queued", "created_at": meta["created_at"]})

@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Get job status",
)
async def get_job_status(
    job_id: str,
    current: TokenData = Security(validate_api_key_or_token, scopes=["job:read"]),
    redis=Depends(get_redis),
):
    meta = await _get_json(redis, f"jobs:{job_id}:meta")
    if not meta:
        raise HTTPException(status_code=404, detail="Job not found or expired")
    # AutZ básica por creador; para admin podrías añadir excepción
    if meta.get("creator") != getattr(current, "sub", None):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {
        "job_id": job_id,
        "status": meta.get("status", "queued"),
        "counts": meta.get("counts", {}),
        "started_at": meta.get("started_at"),
        "finished_at": meta.get("finished_at"),
        "error": meta.get("error"),
    }

@router.get(
    "/jobs/{job_id}/results",
    response_model=JobResultsPage,
    summary="Get job results (paged)",
)
async def get_job_results(
    job_id: str,
    page: int = 1,
    size: int = 500,
    current: TokenData = Security(validate_api_key_or_token, scopes=["job:results"]),
    redis=Depends(get_redis),
):
    if page < 1 or size < 1 or size > 2000:
        raise HTTPException(status_code=400, detail="Invalid pagination")
    meta = await _get_json(redis, f"jobs:{job_id}:meta")
    if not meta:
        raise HTTPException(status_code=404, detail="Job not found or expired")
    if meta.get("creator") != getattr(current, "sub", None):
        raise HTTPException(status_code=403, detail="Forbidden")
    # Cargar página pre-generada por el worker
    page_key = f"jobs:{job_id}:results:page:{page}"
    page_data = await _get_json(redis, page_key) or {}
    total_pages = int(page_data.get("total_pages", 0))
    results = page_data.get("results", [])
    return {
        "job_id": job_id,
        "page": page,
        "size": size,
        "total_pages": total_pages,
        "results": results,
    }

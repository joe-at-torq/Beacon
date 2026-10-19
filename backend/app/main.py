import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import db as db_module
from app import scheduler
from app.bootstrap import init_app_state
from app.config import config
from app.db import session_scope
from app.intel.queue import reset_running as reset_enrichment_jobs
from app.sync import priority  # noqa: F401 - registers the priority-sync change listeners
from app.models import SyncRun, utcnow
from app.api_v1.app import v1 as api_v1
from app.routers import (api_keys, auth, dashboard, enrichment_rules, feeds, integrations, normalization, observables,
                         rules, settings, sync, taxii, users, workspaces)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _recover_interrupted_runs() -> None:
    with session_scope() as db:
        for run in db.query(SyncRun).filter(SyncRun.status == "running"):
            run.status = "error"
            run.finished_at = run.finished_at or utcnow()
            run.errors = (run.errors or []) + ["Interrupted by restart"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    if db_module._engine is None:
        init_app_state()
    _recover_interrupted_runs()
    reset_enrichment_jobs()
    if not config.disable_scheduler:
        scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(title="Beacon — Threat Intelligence Manager", lifespan=lifespan, docs_url="/api/docs",
              redoc_url=None, openapi_url="/api/openapi.json")

for module in (auth, users, workspaces, rules, observables, sync, dashboard, settings, integrations, api_keys,
               normalization, enrichment_rules, feeds, taxii):
    app.include_router(module.router)

# Public, versioned API (must be mounted before the /api catch-all and the SPA fallback below).
app.mount("/api/v1", api_v1)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if not request.url.path.startswith("/api/docs"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; font-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'",
        )
    return response


@app.get("/api/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
def api_not_found(path: str):
    return JSONResponse({"detail": "Not found"}, status_code=404)


# ---- Single-page app ---------------------------------------------------------------------------
_static = config.static_dir
if (_static / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=_static / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def spa(path: str):
    candidate = (_static / path).resolve()
    if path and candidate.is_file() and _static.resolve() in candidate.parents:
        return FileResponse(candidate)
    index = _static / "index.html"
    if index.is_file():
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
    return JSONResponse({"detail": "UI not built. Run `npm run build` in frontend/."}, status_code=404)

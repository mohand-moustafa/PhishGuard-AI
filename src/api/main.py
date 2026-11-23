"""PhishGuard local sandbox API and same-origin analyst interface."""

import hmac
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.routing import get_route_path

from src.sandbox.isolation import SandboxError, validate_url
from src.sandbox.jobs import JobDispatcher, audit
from src.sandbox.store import CapacityError, EvidenceStore, ReplayUnavailable

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "/api/sandbox"
Mode = Literal["analyze", "interaction-scan", "javascript-analysis"]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: Annotated[str, Field(min_length=1, max_length=2048)]


class SandboxBoundary:
    """Authenticate before reading request bodies and bound even chunked uploads."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        if get_route_path(scope).startswith(PREFIX + "/"):
            if not hmac.compare_digest(headers.get(b"authorization", b""), self.token):
                return await JSONResponse({"detail": "A sandbox access token is required."}, 401,
                                          {"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"})(scope, receive, send)
            if scope["method"] == "POST":
                body = bytearray()
                while True:
                    chunk = await receive()
                    if chunk["type"] == "http.disconnect":
                        return
                    if len(body) + len(chunk["body"]) > 8192:
                        return await JSONResponse({"detail": "Request body too large."}, 413)(scope, receive, send)
                    body.extend(chunk["body"])
                    if not chunk.get("more_body"):
                        break
                original = receive
                delivered = False
                async def replay():
                    nonlocal delivered
                    if delivered:
                        return await original()
                    delivered = True
                    return {"type": "http.request", "body": bytes(body)}
                receive = replay

        async def secure(message):
            if message["type"] == "http.response.start":
                message["headers"] += [
                    (b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"), (b"x-frame-options", b"DENY"),
                    (b"content-security-policy", b"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
                ]
            await send(message)
        await self.app(scope, receive, secure)


def create_app(directory: Path | None = None, token: str | None = None, *, dispatch: bool = True) -> FastAPI:
    key = token if token is not None else os.environ.get("PHISHGUARD_SANDBOX_TOKEN", "")
    @asynccontextmanager
    async def lifespan(application):
        if not key:
            raise RuntimeError("Set PHISHGUARD_SANDBOX_TOKEN before starting the sandbox API.")
        application.state.store = EvidenceStore(directory or Path(os.environ.get(
            "PHISHGUARD_SANDBOX_DATA", str(ROOT / ".sandbox-data"))))
        dispatcher = JobDispatcher(application.state.store)
        application.state.dispatcher = dispatcher
        if dispatch:
            dispatcher.start()
        try:
            yield
        finally:
            if dispatch:
                dispatcher.stop()

    app = FastAPI(title="PhishGuard Sandbox", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.add_middleware(SandboxBoundary, token=key)
    router = APIRouter(prefix=PREFIX)

    def submit(url: str, request: Request, mode: Mode, replay_of: str | None = None):
        try:
            if replay_of is None:
                url = validate_url(url)
            job = request.app.state.store.enqueue(url, mode, replay_of=replay_of)
        except ReplayUnavailable:
            raise HTTPException(409, "No offline snapshot is available for this analysis.") from None
        except SandboxError:
            raise HTTPException(422, "Enter a public HTTP or HTTPS URL allowed by the capture policy.") from None
        except CapacityError as exc:
            raise HTTPException(429, str(exc), headers={"Retry-After": "60"}) from None
        request.app.state.dispatcher.wake.set()
        audit("sandbox.queued", job, mode=mode)
        return JSONResponse({"analysis_id": job, "status": "queued", "mode": mode,
                             "report_url": f"{PREFIX}/report/{job}"}, 202,
                            {"Location": f"{PREFIX}/report/{job}"})

    @router.post("/analyze", status_code=202)
    def analyze(body: ScanRequest, request: Request):
        return submit(body.url, request, "analyze")

    @router.post("/interaction-scan", status_code=202)
    def interaction_scan(body: ScanRequest, request: Request):
        return submit(body.url, request, "interaction-scan")

    @router.post("/javascript-analysis", status_code=202)
    def javascript_analysis(body: ScanRequest, request: Request):
        return submit(body.url, request, "javascript-analysis")

    def status(request: Request, job: UUID):
        record = request.app.state.store.status(job.hex)
        if record is None:
            raise HTTPException(404, "Analysis unknown or expired.")
        return record

    @router.post("/replay/{analysis_id}", status_code=202)
    def replay(analysis_id: UUID, request: Request):
        source = status(request, analysis_id)
        return submit(source["url"], request, source["mode"], replay_of=analysis_id.hex)

    @router.get("/report/{analysis_id}")
    def report(analysis_id: UUID, request: Request):
        record = status(request, analysis_id)
        if record["status"] == "completed":
            result = request.app.state.store.report(analysis_id.hex)
            if result is None:
                raise HTTPException(404, "Analysis expired.")
            record["report"] = result
        return record

    @router.get("/screenshot/{analysis_id}")
    def screenshot(analysis_id: UUID, request: Request, view: str = Query("viewport", max_length=64)):
        data = request.app.state.store.image(analysis_id.hex, view)
        if data is None:
            raise HTTPException(404, "Screenshot unavailable.")
        return Response(data, media_type="image/png")

    def completed(request: Request, job: UUID):
        result = request.app.state.store.report(job.hex)
        if result is None:
            status(request, job)
            raise HTTPException(409, "Evidence is available after a successful scan.")
        return result

    @router.get("/interaction-map/{analysis_id}")
    def interaction_map(analysis_id: UUID, request: Request):
        result = completed(request, analysis_id)
        return {key: result.get(key) for key in ("viewport", "regions", "interactions")}

    @router.get("/behavior-trace/{analysis_id}")
    def behavior_trace(analysis_id: UUID, request: Request):
        return completed(request, analysis_id).get("behavior", [])

    @router.get("/network-trace/{analysis_id}")
    def network_trace(analysis_id: UUID, request: Request):
        return completed(request, analysis_id).get("network", [])

    app.include_router(router)
    @app.get("/", include_in_schema=False)
    def home():
        return RedirectResponse("/explorer/")

    assets = ROOT / "frontend" / "dist"
    if (assets / "index.html").is_file():
        app.mount("/explorer", StaticFiles(directory=assets, html=True), name="explorer")
    else:
        @app.get("/explorer/", include_in_schema=False)
        def missing_frontend():
            return JSONResponse({"detail": "Build the local explorer with npm ci and npm run build in frontend."}, 503)
    return app


app = create_app()

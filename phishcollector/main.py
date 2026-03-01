"""FastAPI application entry point."""

import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .database import init_db
from .api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (idempotent)
    await init_db()
    yield


app = FastAPI(
    title="PhishCollector",
    description=(
        "Automated phishing site collector: captures rendered HTML, screenshots, "
        "network traffic, and rich fingerprints to identify kits and TTPs."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key"],
)


# ── Optional API-key authentication ──────────────────────────────────────────

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if settings.api_key and request.url.path not in ("/", "/docs", "/openapi.json"):
        key = request.headers.get("X-API-Key", "")
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(key.encode(), settings.api_key.encode()):
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return await call_next(request)


# ── Routes ────────────────────────────────────────────────────────────────────

app.include_router(router, prefix="/api/v1")


@app.get("/")
async def root():
    return {"service": "PhishCollector", "docs": "/docs"}

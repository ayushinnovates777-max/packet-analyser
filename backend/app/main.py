import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from .api.endpoints import analysis, captures, live
from .api.main_limiter import limiter          # shared singleton
from .core.config import settings
from .db.database import engine
from .db import models

# ── Create all DB tables ────────────────────────────────────────────────────
models.Base.metadata.create_all(bind=engine)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Rate limiter ─────────────────────────────────────────────────────────────
# Imported from shared module — same instance used by endpoint decorators


# ── Security Headers Middleware ───────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects security-hardening HTTP response headers on every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
        response.headers["Cache-Control"]             = "no-store"
        response.headers["Content-Security-Policy"]   = (
            "default-src 'none'; "
            "frame-ancestors 'none';"
        )
        # Remove server fingerprinting header
        if "server" in response.headers:
            del response.headers["server"]
        return response


# ── FastAPI App ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="PacketLens AI API",
    description="Backend API for PacketLens AI PCAP analysis platform",
    version="1.0.0",
    # Hide schema endpoints in production hardening
    docs_url="/docs",
    redoc_url=None,
)

# Attach rate limiter state and its error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Middleware stack (order matters – outermost first) ────────────────────────
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    # Locked to our own frontend only
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=False,          # no cookies / auth tokens needed
    allow_methods=["GET", "POST"],    # only what we actually use
    allow_headers=["Content-Type"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])
app.include_router(captures.router, prefix="/api/captures", tags=["captures"])
app.include_router(live.router, prefix="/api/live", tags=["live"])


# ── Health check ─────────────────────────────────────────────────────────────
@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok"}

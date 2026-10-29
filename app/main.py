import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as v1_router
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.observability import configure_logging, metrics_middleware, metrics_response
from app.services.bootstrap import bootstrap_defaults


configure_logging()


# ── Rate Limiter (token-bucket per IP) ───────────────────────────────────────
class RateLimiter:
    """Simple in-memory token-bucket rate limiter per client IP."""

    def __init__(self, requests_per_second: float = 20.0, burst: int = 50):
        self._rate = requests_per_second
        self._burst = burst
        self._buckets: dict[str, list[float]] = {}  # ip -> [tokens, last_time]

    def allow(self, client_ip: str) -> bool:
        now = time.monotonic()
        if client_ip not in self._buckets:
            self._buckets[client_ip] = [self._burst - 1.0, now]
            return True
        tokens, last = self._buckets[client_ip]
        elapsed = now - last
        tokens = min(self._burst, tokens + elapsed * self._rate)
        if tokens < 1.0:
            return False
        self._buckets[client_ip] = [tokens - 1.0, now]
        return True


_limiter = RateLimiter(
    requests_per_second=float(settings.rate_limit_rps),
    burst=int(settings.rate_limit_burst),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.auto_create_schema:
        Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        bootstrap_defaults(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.app_name,
    description="Zombie API Discovery and Defense platform for enterprise banking",
    version="0.4.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Rate-limit middleware ─────────────────────────────────────────────────────
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    if not _limiter.allow(client_ip):
        return Response(
            content='{"detail":"Rate limit exceeded. Slow down."}',
            status_code=429,
            media_type="application/json",
        )
    return await call_next(request)


app.middleware("http")(metrics_middleware)
app.include_router(v1_router, prefix=settings.api_v1_prefix)

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/metrics", include_in_schema=False)
def metrics():
    return metrics_response()


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/demo")


@app.get("/demo", include_in_schema=False)
def demo_page() -> FileResponse:
    return FileResponse(static_dir / "index.html")

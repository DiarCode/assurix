"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routers import findings, policies, reports, scans, targets
from src.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    await init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Assurix API",
        description="Authorized Autonomous Security Validation Platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(targets.router, prefix="/api/v1/targets", tags=["targets"])
    app.include_router(policies.router, prefix="/api/v1/policies", tags=["policies"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])

    @app.get("/health", tags=["health"])
    async def health_check() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()

"""Application entry point.  [SHARED contract file]

Every member's router and M5's middleware are already registered here, so
nobody needs to edit this file to add their work.
Run from backend/:  uvicorn app.main:app --reload
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.accounts.router import router as accounts_router
from app.core.db import init_db
from app.core.errors import register_error_handlers
from app.orchestrator.middleware import install_middleware
from app.orchestrator.router import router as orchestrator_router
from app.otp.router import router as otp_router
from app.passkeys.router import router as passkeys_router

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Cryptix accessible MFA", lifespan=lifespan)
install_middleware(app)
register_error_handlers(app)

for router in (accounts_router, otp_router, passkeys_router, orchestrator_router):
    app.include_router(router, prefix="/api")


@app.get("/api/health", tags=["Shared"])
def health() -> dict[str, str]:
    return {"status": "ok"}


# The client is served by the same server (IA-1), so cookies stay SameSite=Strict
# and the passkey origin is the page's own origin. Must stay the last line.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

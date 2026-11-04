"""FastAPI application entrypoint for the IoT Security Framework backend."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure backend root is importable for app/, scanner/ and risk_engine/.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.api.v1 import router as api_v1_router  # noqa: E402
from app.core.config import get_settings  # noqa: E402

settings = get_settings()

app = FastAPI(
    title=settings.project_name,
    version="0.1.0",
    description=(
        "AI-Assisted IoT Vulnerability Assessment and IoT-Specific "
        "Dynamic Risk Scoring Framework API"
    ),
)

# Local dashboard origins only (Vite defaults).
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Accept", "Content-Type"],
)

app.include_router(api_v1_router)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "project": settings.project_name,
        "docs": "/docs",
        "health": "/api/v1/health",
    }

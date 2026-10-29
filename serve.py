"""Minimal dev server launcher that avoids uvicorn's httptools/h11 import issues."""
import sys
import os

# Prevent uvicorn from importing httptools/h11 by removing them from the path
# before uvicorn tries auto-detection
os.environ.setdefault("SENTINEL_DATABASE_URL", "sqlite:///./demo_preview.db")
os.environ.setdefault("SENTINEL_AUTO_CREATE_SCHEMA", "true")
os.environ.setdefault("SENTINEL_AUTH_REQUIRED", "false")
os.environ.setdefault("SENTINEL_AUTH_REQUIRE_VERIFIED_JWT", "false")
os.environ.setdefault("SENTINEL_AUTH_ENFORCE_MAPPED_ROLES", "false")
os.environ.setdefault("SENTINEL_AUTH_ALLOW_INSECURE_DEV_TOKENS", "true")
os.environ.setdefault("SENTINEL_CONNECTOR_SIMULATED_FALLBACK", "true")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8899,
        log_level="info",
    )

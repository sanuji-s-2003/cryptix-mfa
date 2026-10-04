"""HTTPS-only, security headers and request tokens (SR-1, §6.3 C3, §6.6).  Owner: M5

Installed once by app/main.py, so nobody else needs to edit main.py.
"""
from fastapi import FastAPI


def install_middleware(app: FastAPI) -> None:
    """TODO M5:
    - refuse plain HTTP and send Strict-Transport-Security when settings.force_https (SR-1, C3)
    - security headers: Content-Security-Policy, X-Content-Type-Options, frame-ancestors
    - check the X-CSRF-Token header against AuthSession.csrf_token on POST/PUT/PATCH/DELETE (§6.6)
    """

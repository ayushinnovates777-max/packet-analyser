"""
Shared rate-limiter instance.

Imported by both main.py (to attach to the app) and individual routers
(to apply per-endpoint limits via @limiter.limit(...)).
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

from fastapi import APIRouter
from .endpoints import analysis, captures

router = APIRouter()
router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
router.include_router(captures.router, prefix="/captures", tags=["captures"])

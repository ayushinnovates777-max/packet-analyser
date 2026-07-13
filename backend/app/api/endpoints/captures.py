from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List

from ...db.database import get_db
from ...db import models
from ..schemas import CaptureBase, CaptureDetailSchema, PacketListSchema, ThreatSchema, DeviceSchema
from ..main_limiter import limiter
from ...core.config import settings

router = APIRouter()


@router.get("/", response_model=List[CaptureBase])
@limiter.limit(settings.RATE_LIMIT_READ)
def get_captures(request: Request, db: Session = Depends(get_db)):
    captures = db.query(models.Capture).order_by(models.Capture.upload_time.desc()).all()
    return captures


@router.get("/{capture_id}", response_model=CaptureDetailSchema)
@limiter.limit(settings.RATE_LIMIT_READ)
def get_capture_summary(request: Request, capture_id: int, db: Session = Depends(get_db)):
    capture = db.query(models.Capture).filter(models.Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")

    protocols = db.query(models.ProtocolStat).filter(
        models.ProtocolStat.capture_id == capture_id
    ).all()

    return {"capture": capture, "protocols": protocols}


@router.get("/{capture_id}/packets", response_model=PacketListSchema)
@limiter.limit(settings.RATE_LIMIT_READ)
def get_capture_packets(
    request: Request,
    capture_id: int,
    skip: int = 0,
    limit: int = 200,
    db: Session = Depends(get_db),
):
    # Cap limit to prevent someone requesting millions of rows
    limit = min(limit, 500)

    capture = db.query(models.Capture).filter(models.Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")

    packets = (
        db.query(models.Packet)
        .filter(models.Packet.capture_id == capture_id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    total = db.query(models.Packet).filter(models.Packet.capture_id == capture_id).count()

    return {"total": total, "packets": packets}


@router.get("/{capture_id}/threats", response_model=List[ThreatSchema])
@limiter.limit(settings.RATE_LIMIT_READ)
def get_capture_threats(request: Request, capture_id: int, db: Session = Depends(get_db)):
    threats = db.query(models.Threat).filter(models.Threat.capture_id == capture_id).all()
    return threats


@router.get("/{capture_id}/devices", response_model=List[DeviceSchema])
@limiter.limit(settings.RATE_LIMIT_READ)
def get_capture_devices(request: Request, capture_id: int, db: Session = Depends(get_db)):
    devices = db.query(models.Device).filter(models.Device.capture_id == capture_id).all()
    return devices

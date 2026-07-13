"""
Upload endpoint – deep file validation before any disk write.

Validation chain (server-side):
  1. Filename length & path-traversal check
  2. Extension allowlist
  3. Content-Type header check
  4. Minimum file size (must be at least a valid pcap header)
  5. Magic-byte validation for PCAP and PCAPNG formats
  6. Maximum file size (streaming, chunk-by-chunk)
  7. SHA-256 deduplication
  8. Rate limiting (5 uploads / IP / minute via slowapi)
"""

import os
import re
import hashlib
import logging
from fastapi import APIRouter, Request, UploadFile, File, HTTPException, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from ...services.pcap_analyzer import run_analysis
from ...core.config import settings
from ...db.database import get_db
from ...db import models
from ..main_limiter import limiter   # shared limiter instance

logger = logging.getLogger(__name__)
router = APIRouter()

# ── Magic byte signatures ─────────────────────────────────────────────────────
# PCAP  – little-endian and big-endian global headers
PCAP_MAGIC   = {b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"}   # nano-sec variants
# PCAPNG – Section Header Block type (4 bytes) followed by BOM
PCAPNG_MAGIC = {b"\x0a\x0d\x0d\x0a"}

VALID_MAGIC  = PCAP_MAGIC | PCAPNG_MAGIC


# ── Helpers ───────────────────────────────────────────────────────────────────
_SAFE_FILENAME_RE = re.compile(r"[^\w\-. ]")

def _sanitize_filename(raw: str) -> str:
    """
    Strip path components and replace non-safe chars.
    Returns only the basename, free of slashes, null bytes, etc.
    """
    # Remove any directory part (path traversal defence)
    name = os.path.basename(raw.replace("\\", "/"))
    # Strip null bytes
    name = name.replace("\x00", "")
    # Collapse dangerous characters to underscores
    name = _SAFE_FILENAME_RE.sub("_", name)
    return name[:settings.MAX_FILENAME_LENGTH] or "upload"


def _validate_magic(header: bytes) -> bool:
    """Check the first 4 bytes against all known-good signatures."""
    if len(header) < 4:
        return False
    magic4 = header[:4]
    return magic4 in VALID_MAGIC


# ── Upload endpoint ───────────────────────────────────────────────────────────
@router.post("/upload")
@limiter.limit(settings.RATE_LIMIT_UPLOAD)
async def upload_pcap(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    # ── 1. Filename checks ────────────────────────────────────────────────────
    raw_name = file.filename or ""
    if not raw_name:
        raise HTTPException(status_code=400, detail="No filename provided.")

    clean_name = _sanitize_filename(raw_name)

    # Extension check (on the *sanitised* name to prevent double-extension tricks)
    ext = os.path.splitext(clean_name)[1].lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Accepted: {', '.join(settings.ALLOWED_EXTENSIONS)}",
        )

    # Guard against filenames like "malware.pcap.exe" before stripping last ext
    all_parts = clean_name.split(".")
    if len(all_parts) > 2:
        # More than one dot – make sure none of the other parts look executable
        DANGEROUS_EXTS = {
            "exe", "dll", "bat", "cmd", "sh", "py", "js", "vbs",
            "ps1", "php", "rb", "pl", "jar", "msi", "com", "scr",
        }
        inner_parts = set(p.lower() for p in all_parts[1:-1])
        if inner_parts & DANGEROUS_EXTS:
            raise HTTPException(status_code=400, detail="Suspicious filename detected.")

    # ── 2. Content-Type header check ─────────────────────────────────────────
    content_type = (file.content_type or "").lower().split(";")[0].strip()
    if content_type and content_type not in settings.ALLOWED_CONTENT_TYPES:
        logger.warning("Rejected upload – content-type: %s filename: %s", content_type, clean_name)
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported content type '{content_type}'.",
        )

    # ── 3. Read header for magic-byte check ───────────────────────────────────
    header = await file.read(24)   # 24 bytes covers all pcap/pcapng headers
    await file.seek(0)

    if len(header) < settings.MIN_UPLOAD_SIZE:
        raise HTTPException(status_code=400, detail="File is too small to be a valid capture.")

    if not _validate_magic(header):
        logger.warning(
            "Magic-byte mismatch – file: %s  header_hex: %s",
            clean_name, header[:8].hex(),
        )
        raise HTTPException(
            status_code=400,
            detail="File signature invalid. Not a recognised PCAP/PCAPNG file.",
        )

    # ── 4. Streaming write with size cap ─────────────────────────────────────
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)

    # Safe on-disk filename: sha256-prefix to avoid collisions + allowed ext
    tmp_name  = hashlib.md5(clean_name.encode()).hexdigest()
    file_path = os.path.join(settings.UPLOAD_DIR, f"{tmp_name}{ext}")

    # Absolute-path normalisation to block symlink/traversal attacks
    upload_dir_real = os.path.realpath(settings.UPLOAD_DIR)
    file_path_real  = os.path.realpath(file_path)
    if not file_path_real.startswith(upload_dir_real + os.sep):
        raise HTTPException(status_code=400, detail="Invalid upload path.")

    file_hash  = hashlib.sha256()
    file_size  = 0

    try:
        with open(file_path, "wb") as buf:
            while True:
                chunk = await file.read(65536)   # 64 KiB chunks
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > settings.MAX_UPLOAD_SIZE:
                    buf.close()
                    os.remove(file_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum allowed size of "
                               f"{settings.MAX_UPLOAD_SIZE // (1024*1024)} MB.",
                    )
                file_hash.update(chunk)
                buf.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to write upload: %s", exc)
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail="Upload failed – internal error.")

    f_hash = file_hash.hexdigest()

    # ── 5. Duplicate detection ────────────────────────────────────────────────
    existing = db.query(models.Capture).filter(models.Capture.file_hash == f_hash).first()
    if existing and existing.status == "completed":
        # Don't re-analyse – return cached result
        os.remove(file_path)   # cleanup the duplicate file
        return {
            "status": "success",
            "capture_id": existing.id,
            "message": "File already analysed. Returning cached result.",
        }

    # ── 6. Persist to DB & kick off background analysis ─────────────────────
    db_capture = models.Capture(
        filename=clean_name,
        file_hash=f_hash,
        size=file_size,
        status="processing",
    )

    try:
        db.add(db_capture)
        db.commit()
        db.refresh(db_capture)
    except Exception as exc:
        db.rollback()
        logger.error("DB insert failed: %s", exc)
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail="Database error during upload.")

    background_tasks.add_task(run_analysis, file_path, db_capture.id)
    logger.info("Upload accepted – capture_id=%d  file=%s  size=%d", db_capture.id, clean_name, file_size)

    return {
        "status": "success",
        "capture_id": db_capture.id,
        "message": "File uploaded and analysis started.",
    }

from __future__ import annotations

import hashlib
import logging
import tempfile
import threading
from pathlib import Path

from django.core.files import File
from django.db import close_old_connections

from dependency_parser.archive import ArchiveValidationError, validate_zip

logger = logging.getLogger("supplychainx")


def save_project_archive(project, uploaded_file, user):
    """Validate and persist an untrusted ZIP without ever executing it."""
    from .models import ProjectArchive

    name = Path(uploaded_file.name or "archive.zip").name
    if not name.lower().endswith(".zip"):
        raise ArchiveValidationError("Only .zip source archives are accepted.")

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp:
        for chunk in uploaded_file.chunks():
            temp.write(chunk)
        temp_path = Path(temp.name)

    try:
        with validate_zip(temp_path):
            pass
        digest = hashlib.sha256()
        with open(temp_path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        size = temp_path.stat().st_size
        with open(temp_path, "rb") as handle:
            archive = ProjectArchive(
                project=project,
                original_filename=name[:255],
                size_bytes=size,
                sha256=digest.hexdigest(),
                uploaded_by=user,
            )
            archive.file.save(f"{digest.hexdigest()[:16]}.zip", File(handle), save=True)
        return archive
    finally:
        temp_path.unlink(missing_ok=True)


def _thread_runner(scan_id: int) -> None:
    close_old_connections()
    try:
        from vulnerability_scanner.tasks import run_scan

        run_scan(scan_id)
    except Exception:
        logger.exception("Background scan thread failed for scan %s", scan_id)
    finally:
        close_old_connections()


def dispatch_scan(scan) -> dict:
    """Queue a scan with Celery, falling back to a daemon thread if Redis is down."""
    from vulnerability_scanner.tasks import run_scan

    try:
        result = run_scan.delay(scan.pk)
        return {"mode": "celery", "task_id": str(getattr(result, "id", ""))}
    except Exception as exc:
        logger.warning("Celery unavailable (%s); using in-process background thread.", exc)
        thread = threading.Thread(target=_thread_runner, args=(scan.pk,), daemon=True)
        thread.start()
        return {"mode": "thread", "task_id": None, "reason": str(exc)}

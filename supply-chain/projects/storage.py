import uuid


def archive_upload_path(instance, filename):
    safe_suffix = "".join(ch for ch in filename.lower() if ch.isalnum() or ch in {".", "_", "-"})[-40:]
    if not safe_suffix.endswith(".zip"):
        safe_suffix = (safe_suffix or "archive") + ".zip"
    return f"archives/{uuid.uuid4().hex}-{safe_suffix}"

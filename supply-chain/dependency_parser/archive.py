"""Secure handling of untrusted ZIP uploads.

Uploaded archives are never executed. Only text manifests are read in memory;
full extraction is available (with strict limits) solely for static tools.
"""
from __future__ import annotations

import io
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

from django.conf import settings

from .parsers import parse_manifest_file

MANIFEST_NAMES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pom.xml",
}


class ArchiveValidationError(ValueError):
    pass


def _safe_name(name: str) -> str:
    if not name or "\x00" in name:
        raise ArchiveValidationError("Archive contains an empty or null-byte filename.")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re_drive(normalized):
        raise ArchiveValidationError(f"Absolute path rejected: {name}")
    parts = PurePosixPath(normalized).parts
    if ".." in parts:
        raise ArchiveValidationError(f"Path traversal rejected: {name}")
    return normalized


def re_drive(value: str) -> bool:
    return len(value) >= 2 and value[1] == ":" and value[0].isalpha()


def validate_zip(zip_path: Path | str) -> zipfile.ZipFile:
    path = Path(zip_path)
    if not path.is_file():
        raise ArchiveValidationError("Archive file does not exist.")
    if path.stat().st_size > settings.SCAN_MAX_ZIP_BYTES:
        raise ArchiveValidationError("Archive exceeds the maximum allowed compressed size.")

    archive = zipfile.ZipFile(path, "r")
    infos = archive.infolist()
    if len(infos) > settings.SCAN_MAX_FILES:
        archive.close()
        raise ArchiveValidationError("Archive contains too many files.")
    total_uncompressed = 0
    for info in infos:
        _safe_name(info.filename)
        if info.flag_bits & 0x1:
            archive.close()
            raise ArchiveValidationError("Encrypted archive entries are not supported.")
        mode = info.external_attr >> 16
        if mode and stat.S_ISLNK(mode):
            archive.close()
            raise ArchiveValidationError(f"Symbolic link rejected: {info.filename}")
        if info.file_size > settings.SCAN_MAX_FILE_BYTES:
            archive.close()
            raise ArchiveValidationError(f"File too large in archive: {info.filename}")
        total_uncompressed += info.file_size
        if info.compress_size and info.file_size / info.compress_size > settings.SCAN_COMPRESSION_RATIO_LIMIT:
            archive.close()
            raise ArchiveValidationError(f"Suspicious compression ratio: {info.filename}")
    if total_uncompressed > settings.SCAN_MAX_UNCOMPRESSED_BYTES:
        archive.close()
        raise ArchiveValidationError("Archive exceeds the maximum allowed uncompressed size.")
    return archive


def _is_manifest(relative: str) -> bool:
    name = PurePosixPath(relative).name.lower()
    return name in MANIFEST_NAMES or (name.startswith("requirements-") and name.endswith(".txt"))


def read_manifests(zip_path: Path | str) -> tuple[list, list[str]]:
    from .parsers import ParsedManifest

    manifests: list[ParsedManifest] = []
    warnings: list[str] = []
    with validate_zip(zip_path) as archive:
        candidates = [i for i in archive.infolist() if not i.is_dir() and _is_manifest(i.filename)]
        if not candidates:
            warnings.append(
                "No supported manifests found (requirements*.txt, package.json, package-lock.json, yarn.lock, pom.xml)."
            )
        for info in candidates:
            try:
                raw = archive.read(info)
                text = raw.decode("utf-8-sig")
            except (UnicodeDecodeError, RuntimeError, OSError) as exc:
                warnings.append(f"Could not read {info.filename}: {exc}")
                continue
            parsed = parse_manifest_file(info.filename, text)
            manifests.append(parsed)
            warnings.extend(f"{info.filename}: {w}" for w in parsed.warnings)
    return manifests, warnings


def safe_extract(zip_path: Path | str, destination: Path | str) -> Path:
    """Extract a validated archive beneath destination, or raise."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    resolved_destination = destination.resolve()
    with validate_zip(zip_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            target = (destination / _safe_name(info.filename)).resolve()
            if os.path.commonpath([str(resolved_destination), str(target)]) != str(resolved_destination):
                raise ArchiveValidationError("Archive entry escapes the extraction directory.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as sink:
                remaining = settings.SCAN_MAX_FILE_BYTES
                while remaining > 0:
                    chunk = source.read(min(64 * 1024, remaining))
                    if not chunk:
                        break
                    sink.write(chunk)
                    remaining -= len(chunk)
    return destination

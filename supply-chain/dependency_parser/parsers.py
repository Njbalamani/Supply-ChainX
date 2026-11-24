from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from config.constants import DependencyType, Ecosystem

try:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
except ImportError:
    Requirement = None

    def canonicalize_name(value: str) -> str:
        return re.sub(r"[-_.]+", "-", value).lower()


@dataclass
class ParsedManifest:
    source_file: str
    ecosystem: str
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "ecosystem": self.ecosystem,
            "dependency_count": len(self.dependencies),
            "warnings": self.warnings,
        }


def _dependency(
    *,
    name: str,
    version: str = "",
    ecosystem: str,
    source_file: str,
    is_direct: bool = True,
    dependency_type: str = DependencyType.RUNTIME,
    specifier: str = "",
    parent_name: str = "",
    license_name: str = "",
    metadata: dict | None = None,
) -> dict[str, Any]:
    return {
        "name": name.strip(),
        "version": (version or "").strip(),
        "ecosystem": ecosystem,
        "source_file": source_file,
        "is_direct": bool(is_direct),
        "dependency_type": dependency_type,
        "specifier": specifier,
        "parent_name": parent_name,
        "license": license_name,
        "metadata": metadata or {},
    }


def _type_from_filename(source_file: str) -> str:
    lowered = source_file.lower()
    if "test" in lowered:
        return DependencyType.TEST
    if "dev" in lowered:
        return DependencyType.DEVELOPMENT
    return DependencyType.RUNTIME


def _exact_version(specifier: str) -> str:
    match = re.search(r"(?:^|,)\s*==\s*([^\s,;]+)", specifier)
    return match.group(1).lstrip("v") if match else ""


def parse_requirements_txt(text: str, source_file: str = "requirements.txt") -> ParsedManifest:
    result = ParsedManifest(source_file=source_file, ecosystem=Ecosystem.PYTHON)
    dep_type = _type_from_filename(source_file)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement", "-c ", "--constraint")):
            result.warnings.append(f"Reference directive skipped (not executed): {line}")
            continue
        if line.startswith("-e ") or line.startswith("--editable"):
            result.warnings.append("Editable/local dependency skipped (never executed).")
            continue
        if line.startswith(("-", "git+", "http://", "https://")):
            result.warnings.append("URL/VCS requirement skipped (version not resolvable statically).")
            continue
        line = line.split(" # ", 1)[0].strip()
        line = line.split("#", 1)[0].strip() if line.startswith("#") else line
        try:
            if Requirement is not None:
                req = Requirement(line)
                name = canonicalize_name(req.name)
                specifier = str(req.specifier)
                extras = sorted(req.extras)
                marker = str(req.marker) if req.marker else ""
                metadata = {"extras": extras}
                if marker:
                    metadata["marker"] = marker
                if req.url:
                    result.warnings.append(f"{name}: URL requirement recorded without version.")
            else:
                match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(\[[^\]]+\])?\s*(.*)$", line)
                if not match:
                    result.warnings.append(f"Unparsed line: {line}")
                    continue
                name = canonicalize_name(match.group(1))
                specifier = match.group(3).split(";", 1)[0].strip()
                metadata = {"extras": []}
                if ";" in line:
                    metadata["marker"] = line.split(";", 1)[1].strip()
        except Exception as exc:
            result.warnings.append(f"Could not parse requirement '{line}': {exc}")
            continue
        if not name:
            continue
        result.dependencies.append(
            _dependency(
                name=name,
                version=_exact_version(specifier),
                ecosystem=Ecosystem.PYTHON,
                source_file=source_file,
                dependency_type=dep_type,
                specifier=specifier,
                license_name="",
                metadata=metadata,
            )
        )
    return result


def _node_type(section: str) -> str:
    return {
        "dependencies": DependencyType.RUNTIME,
        "optionalDependencies": DependencyType.RUNTIME,
        "peerDependencies": DependencyType.RUNTIME,
        "devDependencies": DependencyType.DEVELOPMENT,
    }.get(section, DependencyType.UNKNOWN)


def _node_name_version(name: str, raw: Any) -> tuple[str, str, str, dict]:
    metadata: dict[str, Any] = {}
    specifier = str(raw) if raw is not None else ""
    if specifier.startswith("npm:"):
        alias = specifier[4:]
        metadata["alias"] = name
        if "@" in alias.lstrip("@"):
            alias_name, _, alias_version = alias.rpartition("@")
            name = alias_name
            specifier = alias_version
        else:
            name = alias
            specifier = ""
    version = specifier if re.match(r"^\d", specifier) and not re.search(r"[^\d.\-+~]", specifier) else ""
    return name, version, specifier, metadata


def parse_package_json(data: dict, source_file: str = "package.json") -> ParsedManifest:
    result = ParsedManifest(source_file=source_file, ecosystem=Ecosystem.NODE)
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            result.warnings.append(f"Ignored non-object '{section}' section.")
            continue
        for raw_name, raw_version in entries.items():
            name, version, specifier, metadata = _node_name_version(str(raw_name), raw_version)
            result.dependencies.append(
                _dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NODE,
                    source_file=source_file,
                    dependency_type=_node_type(section),
                    specifier=specifier,
                    metadata=metadata,
                )
            )
    return result


def parse_package_lock_json(data: dict, source_file: str = "package-lock.json") -> ParsedManifest:
    result = ParsedManifest(source_file=source_file, ecosystem=Ecosystem.NODE)
    root_direct: set[str] = set()
    packages = data.get("packages") or {}
    if isinstance(packages, dict):
        root = packages.get("", {})
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            root_direct.update((root.get(section) or {}).keys())
        for path, info in packages.items():
            if not path or not isinstance(info, dict):
                continue
            name = path.split("node_modules/")[-1].strip("/")
            if not name or name.startswith("@") and "/" not in name:
                continue
            version = str(info.get("version") or "")
            dep_type = DependencyType.DEVELOPMENT if info.get("dev") else DependencyType.RUNTIME
            if info.get("optional"):
                dep_type = DependencyType.RUNTIME
            result.dependencies.append(
                _dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NODE,
                    source_file=source_file,
                    is_direct=name in root_direct,
                    dependency_type=dep_type,
                    specifier=version,
                    license_name=str(info.get("license") or ""),
                    metadata={
                        "integrity": info.get("integrity", ""),
                        "resolved": info.get("resolved", ""),
                        "deprecated": info.get("deprecated", ""),
                    },
                )
            )
    legacy = data.get("dependencies") or {}
    if isinstance(legacy, dict) and not packages:
        def walk(items: dict, parent: str = ""):
            for name, info in items.items():
                if not isinstance(info, dict):
                    continue
                result.dependencies.append(
                    _dependency(
                        name=name,
                        version=str(info.get("version") or ""),
                        ecosystem=Ecosystem.NODE,
                        source_file=source_file,
                        is_direct=not parent,
                        dependency_type=DependencyType.DEVELOPMENT if info.get("dev") else DependencyType.RUNTIME,
                        specifier=str(info.get("version") or ""),
                        license_name=str(info.get("license") or ""),
                        parent_name=parent,
                        metadata={"integrity": info.get("integrity", ""), "deprecated": info.get("deprecated", "")},
                    )
                )
                walk(info.get("dependencies") or {}, name)

        walk(legacy)
    return result


_YARN_ENTRY = re.compile(r'^(?:"?)([^\s"].*?)(?:"?):\s*$')


def parse_yarn_lock(text: str, source_file: str = "yarn.lock") -> ParsedManifest:
    result = ParsedManifest(source_file=source_file, ecosystem=Ecosystem.NODE)
    current_names: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")) and line.endswith(":"):
            header = line[:-1]
            parts = [p.strip().strip('"') for p in header.split(",")]
            current_names = []
            for part in parts:
                name = part.rsplit("@", 1)[0] if "@" in part[1:] else part
                current_names.append(name)
            continue
        version_match = re.match(r'\s+version\s+"?([^"\s]+)"?', line)
        if version_match and current_names:
            version = version_match.group(1)
            for name in set(current_names):
                result.dependencies.append(
                    _dependency(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.NODE,
                        source_file=source_file,
                        is_direct=True,
                        specifier=version,
                    )
                )
            current_names = []
    if not result.dependencies:
        result.warnings.append("No yarn.lock entries recognized.")
    return result


def _xml_root(text: str):
    try:
        from defusedxml import ElementTree as SafeET

        return SafeET.fromstring(text)
    except ImportError:
        if re.search(r"<!DOCTYPE|<!ENTITY", text, re.IGNORECASE):
            raise ValueError("XML DTD/ENTITY declarations are not permitted.")
        import xml.etree.ElementTree as StdET

        return StdET.fromstring(text)


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _child_text(element, tag: str) -> str:
    for child in element:
        if _strip_ns(child.tag) == tag:
            return (child.text or "").strip()
    return ""


def _maven_scope_type(scope: str) -> str:
    return {
        "test": DependencyType.TEST,
        "provided": DependencyType.BUILD,
        "system": DependencyType.BUILD,
        "runtime": DependencyType.RUNTIME,
        "compile": DependencyType.RUNTIME,
    }.get(scope.lower(), DependencyType.RUNTIME)


def parse_pom_xml(text: str, source_file: str = "pom.xml") -> ParsedManifest:
    result = ParsedManifest(source_file=source_file, ecosystem=Ecosystem.JAVA)
    root = _xml_root(text)
    properties: dict[str, str] = {}
    props_node = next((c for c in root if _strip_ns(c.tag) == "properties"), None)
    if props_node is not None:
        for prop in props_node:
            properties[_strip_ns(prop.tag)] = (prop.text or "").strip()

    def resolve(value: str) -> str:
        resolved = value
        for _ in range(5):
            match = re.search(r"\$\{([^}]+)\}", resolved)
            if not match:
                break
            key = match.group(1)
            replacement = properties.get(key) or {"project.version": _child_text(root, "version")}.get(key, "")
            if not replacement:
                break
            resolved = resolved.replace(match.group(0), replacement)
        return resolved

    for node in root.iter():
        if _strip_ns(node.tag) != "dependency":
            continue
        group = resolve(_child_text(node, "groupId"))
        artifact = resolve(_child_text(node, "artifactId"))
        version = resolve(_child_text(node, "version"))
        if not artifact:
            continue
        scope = resolve(_child_text(node, "scope"))
        exclusions = []
        for child in node:
            if _strip_ns(child.tag) == "exclusions":
                for exclusion in child:
                    exclusions.append(
                        {
                            "groupId": _child_text(exclusion, "groupId"),
                            "artifactId": _child_text(exclusion, "artifactId"),
                        }
                    )
        result.dependencies.append(
            _dependency(
                name=f"{group}:{artifact}" if group else artifact,
                version=version,
                ecosystem=Ecosystem.JAVA,
                source_file=source_file,
                is_direct=True,
                dependency_type=_maven_scope_type(scope),
                specifier=version,
                metadata={
                    "group": group,
                    "artifact": artifact,
                    "scope": scope,
                    "optional": _child_text(node, "optional").lower() == "true",
                    "exclusions": exclusions,
                },
            )
        )
    if not result.dependencies:
        result.warnings.append("No Maven dependencies found in pom.xml.")
    return result


def parse_manifest_file(relative_path: str, content: str) -> ParsedManifest:
    filename = PurePosixPath(relative_path).name.lower()
    if filename == "requirements.txt" or filename.startswith("requirements-") and filename.endswith(".txt"):
        return parse_requirements_txt(content, relative_path)
    if filename in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            manifest = ParsedManifest(relative_path, Ecosystem.NODE)
            manifest.warnings.append(f"Invalid JSON: {exc}")
            return manifest
        if filename == "package.json":
            return parse_package_json(data, relative_path)
        return parse_package_lock_json(data, relative_path)
    if filename == "yarn.lock":
        return parse_yarn_lock(content, relative_path)
    if filename == "pom.xml":
        try:
            return parse_pom_xml(content, relative_path)
        except Exception as exc:
            manifest = ParsedManifest(relative_path, Ecosystem.JAVA)
            manifest.warnings.append(f"Invalid pom.xml: {exc}")
            return manifest
    return ParsedManifest(relative_path, "UNKNOWN", warnings=[f"Unsupported manifest: {relative_path}"])


def dependency_fingerprint(dep: dict) -> str:
    raw = f"{dep['ecosystem']}|{dep['name'].lower()}|{dep.get('version', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()

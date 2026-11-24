from __future__ import annotations

import io
import json
import stat
import zipfile
from pathlib import Path

from django.test import SimpleTestCase

from dependency_parser.archive import ArchiveValidationError, read_manifests, safe_extract, validate_zip
from dependency_parser.parsers import (
    parse_package_json,
    parse_package_lock_json,
    parse_pom_xml,
    parse_requirements_txt,
)

FIXTURES = Path(__file__).parent / "fixtures"


class RequirementsParserTests(SimpleTestCase):
    def test_parses_pinned_ranged_and_marked_requirements(self):
        manifest = parse_requirements_txt(FIXTURES.joinpath("sample-requirements.txt").read_text())
        names = {d["name"]: d for d in manifest.dependencies}
        self.assertEqual(set(names), {"requirements", "django", "requests", "bottle"})
        self.assertEqual(names["requirements"]["version"], "2.31.0")
        self.assertEqual(names["django"]["specifier"], "<7,>=4.2")
        self.assertEqual(names["django"]["version"], "")
        self.assertEqual(names["requests"]["version"], "2.34.2")
        self.assertEqual(names["requests"]["metadata"]["extras"], ["security"])
        self.assertEqual(names["bottle"]["version"], "0.12.25")
        self.assertTrue(any("Reference directive" in w for w in manifest.warnings))

    def test_dev_manifest_marks_development_dependencies(self):
        manifest = parse_requirements_txt("pytest==8.0.0\n", source_file="requirements-dev.txt")
        self.assertEqual(manifest.dependencies[0]["dependency_type"], "DEVELOPMENT")


class NodeParserTests(SimpleTestCase):
    def test_package_json_sections_and_aliases(self):
        data = json.loads(FIXTURES.joinpath("sample-package.json").read_text())
        manifest = parse_package_json(data)
        by_name = {d["name"]: d for d in manifest.dependencies}
        self.assertEqual(by_name["express"]["version"], "4.18.2")
        self.assertEqual(by_name["axios"]["version"], "")
        self.assertEqual(by_name["axios"]["specifier"], "^1.6.0")
        self.assertEqual(by_name["lodash"]["metadata"]["alias"], "safe-alias")
        self.assertEqual(by_name["jest"]["dependency_type"], "DEVELOPMENT")

    def test_lockfile_distinguishes_direct_and_transitive(self):
        data = json.loads(FIXTURES.joinpath("sample-package-lock.json").read_text())
        manifest = parse_package_lock_json(data)
        by_name = {d["name"]: d for d in manifest.dependencies}
        self.assertTrue(by_name["express"]["is_direct"])
        self.assertFalse(by_name["cookie"]["is_direct"])
        self.assertEqual(by_name["express"]["license"], "MIT")
        self.assertEqual(by_name["deprecated-lib"]["metadata"]["deprecated"], "Use another package")


class MavenParserTests(SimpleTestCase):
    def test_properties_scopes_and_java_coordinates(self):
        manifest = parse_pom_xml(FIXTURES.joinpath("sample-pom.xml").read_text())
        by_name = {d["name"]: d for d in manifest.dependencies}
        jackson = by_name["com.fasterxml.jackson.core:jackson-databind"]
        self.assertEqual(jackson["version"], "2.13.0")
        self.assertEqual(jackson["metadata"]["artifact"], "jackson-databind")
        self.assertEqual(by_name["junit:junit"]["dependency_type"], "TEST")

    def test_doctype_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_pom_xml('<!DOCTYPE foo [<!ENTITY x "bar">]><project>&x;</project>')


class ArchiveSecurityTests(SimpleTestCase):
    def test_valid_archive_manifests_are_read(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("requirements.txt", "click==8.1.7\n")
            archive.writestr("src/app.py", "print('never executed')\n")
        buffer.seek(0)
        temp = Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "app.zip"
        temp.write_bytes(buffer.getvalue())
        manifests, warnings = read_manifests(temp)
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0].dependencies[0]["name"], "click")
        self.assertEqual(warnings, [])

    def test_path_traversal_is_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../../escape.txt", "bad")
        buffer.seek(0)
        temp = Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "evil.zip"
        temp.write_bytes(buffer.getvalue())
        with self.assertRaises(ArchiveValidationError):
            validate_zip(temp)

    def test_symlink_is_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "../../etc/passwd")
        buffer.seek(0)
        temp = Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "link.zip"
        temp.write_bytes(buffer.getvalue())
        with self.assertRaises(ArchiveValidationError):
            validate_zip(temp)

    def test_safe_extract_stays_within_destination(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("src/main.py", "print('hello')\n")
        buffer.seek(0)
        tmp = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        archive_path = tmp / "ok.zip"
        archive_path.write_bytes(buffer.getvalue())
        destination = safe_extract(archive_path, tmp / "out")
        self.assertTrue((destination / "src" / "main.py").is_file())

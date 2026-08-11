from __future__ import annotations

import unittest

from releaseguard.config import PolicyConfig
from releaseguard.models import Change
from releaseguard.rules import run_rules


class EcosystemRuleTests(unittest.TestCase):
    def scan(self, path: str, before: str | None, after: str | None, *, extra_changes=None):
        docs = {("base", path): before, ("head", path): after}
        changes = [Change(path=path, status="M")]
        if extra_changes:
            changes.extend(extra_changes)
        return run_rules(
            changes,
            PolicyConfig(),
            "base",
            "head",
            reader=lambda *_: None,
            text_reader=lambda ref, requested: docs.get((ref, requested)),
        )

    def test_pep621_direct_url_is_critical(self) -> None:
        findings = self.scan(
            "pyproject.toml",
            '[project]\nname="demo"\ndependencies=[]\n',
            '[project]\nname="demo"\ndependencies=["widget @ https://example.invalid/widget.whl"]\n',
        )
        self.assertTrue(any(item.rule_id == "RG026" and item.severity == "critical" for item in findings))

    def test_pep621_new_runtime_dependency_is_high(self) -> None:
        findings = self.scan(
            "pyproject.toml",
            '[project]\nname="demo"\ndependencies=[]\n',
            '[project]\nname="demo"\ndependencies=["requests>=2"]\n',
        )
        matching = [item for item in findings if item.rule_id == "RG027"]
        self.assertEqual(matching[0].severity, "high")

    def test_optional_python_dependency_is_medium(self) -> None:
        findings = self.scan(
            "pyproject.toml",
            '[project]\nname="demo"\n',
            '[project]\nname="demo"\n[project.optional-dependencies]\ndocs=["mkdocs>=1"]\n',
        )
        matching = [item for item in findings if item.rule_id == "RG027"]
        self.assertEqual(matching[0].severity, "medium")

    def test_poetry_path_dependency_is_critical(self) -> None:
        findings = self.scan(
            "pyproject.toml",
            '[tool.poetry]\nname="demo"\n[tool.poetry.dependencies]\npython="^3.11"\n',
            '[tool.poetry]\nname="demo"\n[tool.poetry.dependencies]\npython="^3.11"\nwidget={path="../widget"}\n',
        )
        self.assertTrue(any(item.rule_id == "RG026" for item in findings))

    def test_python_build_backend_change_is_high(self) -> None:
        findings = self.scan(
            "pyproject.toml",
            '[build-system]\nrequires=["setuptools"]\nbuild-backend="setuptools.build_meta"\n',
            '[build-system]\nrequires=["hatchling"]\nbuild-backend="hatchling.build"\n',
        )
        self.assertTrue(any(item.rule_id == "RG028" and item.severity == "high" for item in findings))

    def test_dynamic_dependencies_are_reported(self) -> None:
        findings = self.scan(
            "pyproject.toml",
            '[project]\nname="demo"\n',
            '[project]\nname="demo"\ndynamic=["dependencies"]\n',
        )
        self.assertTrue(any(item.rule_id == "RG029" for item in findings))

    def test_cargo_git_dependency_is_critical(self) -> None:
        findings = self.scan(
            "Cargo.toml",
            '[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\n',
            '[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\nwidget={git="https://example.invalid/widget"}\n',
        )
        self.assertTrue(any(item.rule_id == "RG030" and item.severity == "critical" for item in findings))

    def test_new_cargo_dev_dependency_is_medium(self) -> None:
        findings = self.scan(
            "Cargo.toml",
            '[package]\nname="demo"\nversion="0.1.0"\n',
            '[package]\nname="demo"\nversion="0.1.0"\n[dev-dependencies]\nproptest="1"\n',
        )
        matching = [item for item in findings if item.rule_id == "RG031"]
        self.assertEqual(matching[0].severity, "medium")

    def test_build_rs_change_is_high(self) -> None:
        docs = {
            ("base", "Cargo.toml"): '[package]\nname="demo"\nversion="0.1.0"\n',
            ("head", "Cargo.toml"): '[package]\nname="demo"\nversion="0.1.0"\n',
        }
        findings = run_rules(
            [Change(path="build.rs", status="A")],
            PolicyConfig(),
            "base",
            "head",
            reader=lambda *_: None,
            text_reader=lambda ref, requested: docs.get((ref, requested)),
        )
        self.assertTrue(any(item.rule_id == "RG032" and item.severity == "high" for item in findings))

    def test_cargo_patch_override_is_critical(self) -> None:
        findings = self.scan(
            "Cargo.toml",
            '[package]\nname="demo"\nversion="0.1.0"\n',
            '[package]\nname="demo"\nversion="0.1.0"\n[patch.crates-io]\nserde={git="https://example.invalid/serde"}\n',
        )
        self.assertTrue(any(item.rule_id == "RG033" for item in findings))

    def test_invalid_toml_fails_closed(self) -> None:
        findings = self.scan(
            "pyproject.toml",
            '[project]\nname="demo"\n',
            '[project\nname="demo"\n',
        )
        self.assertTrue(any(item.rule_id == "RG034" and item.severity == "critical" for item in findings))

    def test_unchanged_registry_dependency_is_not_reported(self) -> None:
        document = '[project]\nname="demo"\ndependencies=["requests>=2"]\n'
        findings = self.scan("pyproject.toml", document, document)
        self.assertFalse(any(item.rule_id in {"RG026", "RG027", "RG028", "RG029"} for item in findings))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NpmActionMetadataTests(unittest.TestCase):
    def test_npm_verifier_action_pins_third_party_action(self) -> None:
        text = (ROOT / "actions" / "verify-npm" / "action.yml").read_text(encoding="utf-8")
        self.assertIn(
            "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
            text,
        )
        third_party_uses = re.findall(r"^\s*uses:\s*([^\s]+)", text, flags=re.MULTILINE)
        self.assertTrue(third_party_uses)
        self.assertTrue(all(re.search(r"@[0-9a-f]{40}$", item.split(" #", 1)[0]) for item in third_party_uses))

    def test_action_pins_verifier_and_uses_safe_install_flags(self) -> None:
        text = (ROOT / "actions" / "verify-npm" / "action.yml").read_text(encoding="utf-8")
        self.assertIn('node-version: "24.18.1"', text)
        self.assertIn("default: 11.19.0", text)
        self.assertIn("env -i", text)
        self.assertIn("--ignore-scripts", text)
        self.assertIn("--audit=false", text)
        self.assertIn("--fund=false", text)
        self.assertIn("python3 -I -c", text)
        self.assertIn('runpy.run_module("releaseguard", run_name="__main__", alter_sys=True)', text)
        self.assertNotIn("PYTHONPATH=", text)
        self.assertNotIn("python3 -m releaseguard", text)

    def test_root_action_uses_isolated_python_launcher(self) -> None:
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("python3 -I -c", text)
        self.assertIn('runpy.run_module("releaseguard", run_name="__main__", alter_sys=True)', text)
        self.assertNotIn("PYTHONPATH=", text)

    def test_attested_evidence_example_runs_after_policy_block(self) -> None:
        text = (ROOT / "examples" / "npm-post-publish-with-attested-evidence.yml").read_text(encoding="utf-8")
        self.assertIn("if: always() && hashFiles('releaseguard-npm-report.json') != ''", text)
        self.assertIn(
            "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d",
            text,
        )


if __name__ == "__main__":
    unittest.main()

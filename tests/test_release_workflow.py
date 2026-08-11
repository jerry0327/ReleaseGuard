from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowTests(unittest.TestCase):
    def test_bootstrap_release_is_owner_and_main_bound(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn('branches: ["release/v*"]', text)
        self.assertIn("github.actor == github.repository_owner", text)
        self.assertIn("Bootstrap branch must point to the current main commit", text)
        self.assertIn('git push origin "refs/tags/$RELEASE_TAG"', text)
        self.assertIn('git push origin --delete "$RELEASE_BRANCH"', text)

    def test_release_workflow_is_idempotent(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn('gh release view "$RELEASE_TAG"', text)
        self.assertIn("GitHub Release $RELEASE_TAG already exists", text)
        self.assertIn("--verify-tag", text)


if __name__ == "__main__":
    unittest.main()

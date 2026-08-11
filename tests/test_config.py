from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from releaseguard.config import load_config


class ConfigTests(unittest.TestCase):
    def test_missing_file_uses_defaults(self) -> None:
        config = load_config("does-not-exist.toml")
        self.assertEqual(config.fail_on, "critical")
        self.assertEqual(config.review.minimum_independent_approvals, 0)

    def test_custom_threshold_and_review_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releaseguard.toml"
            path.write_text(
                """[releaseguard]
fail_on = "high"
max_changed_files = 25

[releaseguard.review]
minimum_independent_approvals = 2
required_on = "critical"
allow_stale_approvals = true
exclude_bots = false
fail_closed = false
allowed_author_associations = ["OWNER", "MEMBER"]
trusted_reviewers = ["security-auditor"]
""",
                encoding="utf-8",
            )
            config = load_config(path)
            self.assertEqual(config.fail_on, "high")
            self.assertEqual(config.max_changed_files, 25)
            self.assertEqual(config.review.minimum_independent_approvals, 2)
            self.assertEqual(config.review.required_on, "critical")
            self.assertTrue(config.review.allow_stale_approvals)
            self.assertFalse(config.review.exclude_bots)
            self.assertFalse(config.review.fail_closed)
            self.assertEqual(config.review.allowed_author_associations, ("OWNER", "MEMBER"))
            self.assertEqual(config.review.trusted_reviewers, ("security-auditor",))

    def test_invalid_threshold_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releaseguard.toml"
            path.write_text('[releaseguard]\nfail_on = "banana"\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_invalid_review_count_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releaseguard.toml"
            path.write_text(
                "[releaseguard.review]\nminimum_independent_approvals = -1\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(path)

    def test_boolean_is_not_accepted_as_integer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releaseguard.toml"
            path.write_text("[releaseguard]\nmax_changed_files = true\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()

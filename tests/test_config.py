from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from releaseguard.config import load_config


class ConfigTests(unittest.TestCase):
    def test_missing_file_uses_defaults(self) -> None:
        config = load_config("does-not-exist.toml")
        self.assertEqual(config.fail_on, "critical")

    def test_custom_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releaseguard.toml"
            path.write_text('[releaseguard]\nfail_on = "high"\nmax_changed_files = 25\n', encoding="utf-8")
            config = load_config(path)
            self.assertEqual(config.fail_on, "high")
            self.assertEqual(config.max_changed_files, 25)

    def test_invalid_threshold_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releaseguard.toml"
            path.write_text('[releaseguard]\nfail_on = "banana"\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()

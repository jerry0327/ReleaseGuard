from __future__ import annotations

import unittest

from scripts.release_check import run


class ReleaseCheckTests(unittest.TestCase):
    def test_repository_is_release_consistent(self) -> None:
        self.assertEqual(run("v0.4.0"), [])

    def test_wrong_tag_is_rejected(self) -> None:
        errors = run("v9.9.9")
        self.assertTrue(any("must equal v0.4.0" in error for error in errors))


if __name__ == "__main__":
    unittest.main()

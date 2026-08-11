from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest

from releaseguard.config import ReviewPolicy
from releaseguard.github_evidence import (
    GitHubApiClient,
    PullRequestContext,
    collect_review_evidence,
    context_from_event,
    evaluate_reviews,
)
from releaseguard.models import Finding

HEAD = "a" * 40
OLD = "b" * 40


def review(
    login: str,
    state: str,
    commit: str | None = HEAD,
    user_type: str = "User",
    association: str = "COLLABORATOR",
) -> dict[str, object]:
    return {
        "user": {"login": login, "type": user_type},
        "state": state,
        "commit_id": commit,
        "author_association": association,
    }


class FakeClient:
    def __init__(self, _token: str, *, pr: dict[str, object], reviews: list[dict[str, object]], **_: object) -> None:
        self.pr = pr
        self.reviews = reviews

    def get_pull_request(self, _repository: str, _number: int) -> dict[str, object]:
        return self.pr

    def list_reviews(self, _repository: str, _number: int) -> list[dict[str, object]]:
        return self.reviews


class ReviewTests(unittest.TestCase):
    def policy(self, **kwargs: object) -> ReviewPolicy:
        values = {
            "minimum_independent_approvals": 1,
            "required_on": "high",
            "allow_stale_approvals": False,
            "exclude_bots": True,
            "fail_closed": True,
        }
        values.update(kwargs)
        return ReviewPolicy(**values)  # type: ignore[arg-type]

    def evidence(self, reviews: list[dict[str, object]], **policy: object):
        return evaluate_reviews(
            reviews,  # type: ignore[arg-type]
            author="alice",
            base_sha=OLD,
            head_sha=HEAD,
            policy=self.policy(**policy),
            repository="owner/repo",
            pull_request=7,
            observed_base_sha=OLD,
            observed_head_sha=HEAD,
        )

    def test_counts_fresh_independent_approval(self) -> None:
        evidence = self.evidence([review("bob", "APPROVED")])
        self.assertEqual(evidence.status, "passed")
        self.assertEqual(evidence.approvals, ("bob",))

    def test_excludes_self_approval(self) -> None:
        evidence = self.evidence([review("alice", "APPROVED")])
        self.assertEqual(evidence.status, "failed")
        self.assertEqual(evidence.self_approvals, ("alice",))

    def test_excludes_bot_approval(self) -> None:
        evidence = self.evidence([review("dependabot[bot]", "APPROVED", user_type="Bot")])
        self.assertEqual(evidence.bot_approvals, ("dependabot[bot]",))

    def test_stale_approval_does_not_count(self) -> None:
        evidence = self.evidence([review("bob", "APPROVED", OLD)])
        self.assertEqual(evidence.stale_approvals, ("bob",))
        self.assertEqual(evidence.approval_count, 0)

    def test_stale_approval_can_be_allowed_explicitly(self) -> None:
        evidence = self.evidence([review("bob", "APPROVED", OLD)], allow_stale_approvals=True)
        self.assertEqual(evidence.approvals, ("bob",))

    def test_comment_does_not_erase_prior_approval(self) -> None:
        evidence = self.evidence([review("bob", "APPROVED"), review("bob", "COMMENTED")])
        self.assertEqual(evidence.approvals, ("bob",))

    def test_later_changes_requested_replaces_approval(self) -> None:
        evidence = self.evidence([review("bob", "APPROVED"), review("bob", "CHANGES_REQUESTED")])
        self.assertEqual(evidence.approvals, ())
        self.assertEqual(evidence.changes_requested, ("bob",))

    def test_review_policy_not_triggered_by_medium_finding(self) -> None:
        evidence, findings = collect_review_evidence(
            [Finding("RG009", "medium", "Medium", "detail")],
            policy=self.policy(),
            context=None,
            scanned_base_sha=OLD,
            scanned_head_sha=HEAD,
            token=None,
            api_url="https://api.github.com",
            api_version="2022-11-28",
        )
        self.assertEqual(evidence.status, "not_required")
        self.assertEqual(findings, [])

    def test_missing_token_fails_closed(self) -> None:
        evidence, findings = collect_review_evidence(
            [Finding("RG001", "high", "High", "detail")],
            policy=self.policy(),
            context=PullRequestContext("owner/repo", 7, head_sha=HEAD, author="alice"),
            scanned_base_sha=OLD,
            scanned_head_sha=HEAD,
            token=None,
            api_url="https://api.github.com",
            api_version="2022-11-28",
        )
        self.assertEqual(evidence.status, "unavailable")
        self.assertEqual(findings[0].rule_id, "RG013")
        self.assertEqual(findings[0].severity, "critical")

    def test_insufficient_quorum_emits_rg012(self) -> None:
        factory = lambda token, **kwargs: FakeClient(  # noqa: E731
            token,
            pr={"base": {"sha": OLD}, "head": {"sha": HEAD}, "user": {"login": "alice"}},
            reviews=[review("bob", "APPROVED", OLD)],
            **kwargs,
        )
        evidence, findings = collect_review_evidence(
            [Finding("RG001", "high", "High", "detail")],
            policy=self.policy(),
            context=PullRequestContext("owner/repo", 7, head_sha=HEAD, author="alice"),
            scanned_base_sha=OLD,
            scanned_head_sha=HEAD,
            token="token",
            api_url="https://api.github.com",
            api_version="2022-11-28",
            client_factory=factory,  # type: ignore[arg-type]
        )
        self.assertEqual(evidence.status, "failed")
        self.assertEqual(findings[0].rule_id, "RG012")

    def test_head_mismatch_emits_rg014(self) -> None:
        factory = lambda token, **kwargs: FakeClient(  # noqa: E731
            token,
            pr={"base": {"sha": OLD}, "head": {"sha": "c" * 40}, "user": {"login": "alice"}},
            reviews=[review("bob", "APPROVED")],
            **kwargs,
        )
        evidence, findings = collect_review_evidence(
            [Finding("RG001", "high", "High", "detail")],
            policy=self.policy(),
            context=PullRequestContext("owner/repo", 7, head_sha=HEAD, author="alice"),
            scanned_base_sha=OLD,
            scanned_head_sha=HEAD,
            token="token",
            api_url="https://api.github.com",
            api_version="2022-11-28",
            client_factory=factory,  # type: ignore[arg-type]
        )
        self.assertEqual(evidence.status, "mismatch")
        self.assertEqual(findings[0].rule_id, "RG014")

    def test_excludes_untrusted_public_approval(self) -> None:
        evidence = self.evidence([review("outsider", "APPROVED", association="NONE")])
        self.assertEqual(evidence.approval_count, 0)
        self.assertEqual(evidence.untrusted_approvals, ("outsider",))

    def test_explicit_trusted_reviewer_can_count(self) -> None:
        evidence = self.evidence(
            [review("external-auditor", "APPROVED", association="NONE")],
            trusted_reviewers=("external-auditor",),
        )
        self.assertEqual(evidence.approvals, ("external-auditor",))

    def test_event_context_is_parsed(self) -> None:
        payload = {
            "number": 7,
            "repository": {"full_name": "owner/repo"},
            "sender": {"login": "actor"},
            "pull_request": {
                "user": {"login": "alice"},
                "base": {"sha": OLD},
                "head": {"sha": HEAD},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            context = context_from_event(path)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context.repository, "owner/repo")
        self.assertEqual(context.number, 7)
        self.assertEqual(context.author, "alice")
        self.assertEqual(context.actor, "actor")

    def test_rejects_insecure_external_api_url(self) -> None:
        with self.assertRaises(ValueError):
            GitHubApiClient("token", api_url="http://example.com")


if __name__ == "__main__":
    unittest.main()

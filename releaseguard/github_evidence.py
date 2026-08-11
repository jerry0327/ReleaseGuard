from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .config import ReviewPolicy
from .models import Finding, ReviewEvidence, SEVERITY_RANK

_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_DECISIVE_STATES = {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}


@dataclass(frozen=True)
class PullRequestContext:
    repository: str | None = None
    number: int | None = None
    base_sha: str | None = None
    head_sha: str | None = None
    author: str | None = None
    actor: str | None = None


class GitHubApiError(RuntimeError):
    """A sanitized GitHub API failure."""


class GitHubApiClient:
    def __init__(
        self,
        token: str,
        *,
        api_url: str = "https://api.github.com",
        api_version: str = "2022-11-28",
        timeout: float = 10.0,
        requester: Callable[[str], Any] | None = None,
    ) -> None:
        self.token = token
        self.api_url = _validated_api_url(api_url)
        self.api_version = api_version
        self.timeout = timeout
        self._requester = requester

    def _get(self, path: str) -> tuple[Any, str | None]:
        if self._requester is not None:
            return self._requester(path), None

        request = Request(
            f"{self.api_url}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "ReleaseGuard/0.2",
                "X-GitHub-Api-Version": self.api_version,
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - validated URL
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise GitHubApiError("GitHub API response exceeded the 4 MiB safety limit")
                link = response.headers.get("Link")
        except HTTPError as exc:
            raise GitHubApiError(f"GitHub API returned HTTP {exc.code} for {path}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise GitHubApiError(f"GitHub API request failed for {path}: {type(exc).__name__}") from exc

        try:
            return json.loads(raw), link
        except json.JSONDecodeError as exc:
            raise GitHubApiError(f"GitHub API returned invalid JSON for {path}") from exc

    def get_pull_request(self, repository: str, number: int) -> dict[str, Any]:
        _validate_repository(repository)
        payload, _ = self._get(f"/repos/{repository}/pulls/{number}")
        if not isinstance(payload, dict):
            raise GitHubApiError("GitHub pull request response was not an object")
        return payload

    def list_reviews(self, repository: str, number: int) -> list[dict[str, Any]]:
        _validate_repository(repository)
        reviews: list[dict[str, Any]] = []
        path = f"/repos/{repository}/pulls/{number}/reviews?per_page=100"
        for _ in range(10):
            payload, link = self._get(path)
            if not isinstance(payload, list):
                raise GitHubApiError("GitHub reviews response was not an array")
            reviews.extend(item for item in payload if isinstance(item, dict))
            path = _next_path(link, self.api_url)
            if path is None:
                return reviews
        raise GitHubApiError("GitHub reviews pagination exceeded 10 pages")


def _validated_api_url(value: str) -> str:
    candidate = value.rstrip("/")
    parsed = urlparse(candidate)
    if parsed.scheme == "https" and parsed.netloc:
        return candidate
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}:
        return candidate
    raise ValueError("GitHub API URL must use HTTPS (HTTP is allowed only for localhost tests)")


def _validate_repository(repository: str) -> None:
    if not _REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository must use owner/name syntax")


def _next_path(link: str | None, api_url: str) -> str | None:
    if not link:
        return None
    for segment in link.split(","):
        if 'rel="next"' not in segment:
            continue
        match = re.search(r"<([^>]+)>", segment)
        if not match:
            return None
        next_url = match.group(1)
        if not next_url.startswith(f"{api_url}/"):
            raise GitHubApiError("GitHub pagination link changed API origin")
        return next_url[len(api_url) :]
    return None


def context_from_event(path: str | Path | None) -> PullRequestContext | None:
    if not path:
        return None
    event_path = Path(path)
    if not event_path.exists():
        return None
    try:
        payload = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return None

    repository = None
    repository_obj = payload.get("repository")
    if isinstance(repository_obj, dict) and isinstance(repository_obj.get("full_name"), str):
        repository = repository_obj["full_name"]

    number = payload.get("number")
    if isinstance(number, bool) or not isinstance(number, int):
        number = pr.get("number") if isinstance(pr.get("number"), int) else None

    def nested_sha(side: str) -> str | None:
        value = pr.get(side)
        return value.get("sha") if isinstance(value, dict) and isinstance(value.get("sha"), str) else None

    user = pr.get("user")
    sender = payload.get("sender")
    author = user.get("login") if isinstance(user, dict) and isinstance(user.get("login"), str) else None
    actor = sender.get("login") if isinstance(sender, dict) and isinstance(sender.get("login"), str) else None
    return PullRequestContext(
        repository=repository,
        number=number,
        base_sha=nested_sha("base"),
        head_sha=nested_sha("head"),
        author=author,
        actor=actor,
    )


def context_with_overrides(
    event_context: PullRequestContext | None,
    *,
    repository: str | None,
    pull_request: int | None,
    actor: str | None = None,
) -> PullRequestContext | None:
    if event_context is None and repository is None and pull_request is None:
        return None
    base = event_context or PullRequestContext()
    selected_repository = repository or base.repository
    selected_number = pull_request if pull_request is not None else base.number
    if selected_repository is not None:
        _validate_repository(selected_repository)
    if selected_number is not None and selected_number < 1:
        raise ValueError("pull request number must be positive")
    return PullRequestContext(
        repository=selected_repository,
        number=selected_number,
        base_sha=base.base_sha,
        head_sha=base.head_sha,
        author=base.author,
        actor=actor or base.actor,
    )


def _login(review: dict[str, Any]) -> str | None:
    user = review.get("user")
    if not isinstance(user, dict):
        return None
    value = user.get("login")
    return value if isinstance(value, str) and value else None


def _is_bot(review: dict[str, Any], login: str) -> bool:
    user = review.get("user")
    user_type = user.get("type") if isinstance(user, dict) else None
    return user_type == "Bot" or login.lower().endswith("[bot]")


def evaluate_reviews(
    reviews: list[dict[str, Any]],
    *,
    author: str | None,
    base_sha: str,
    head_sha: str,
    policy: ReviewPolicy,
    repository: str,
    pull_request: int,
    observed_base_sha: str,
    observed_head_sha: str,
) -> ReviewEvidence:
    latest: dict[str, dict[str, Any]] = {}
    display_names: dict[str, str] = {}
    for review in reviews:
        state = str(review.get("state", "")).upper()
        login = _login(review)
        if login is None or state not in _DECISIVE_STATES:
            continue
        key = login.casefold()
        latest[key] = review
        display_names[key] = login

    approvals: list[str] = []
    stale: list[str] = []
    self_approvals: list[str] = []
    bots: list[str] = []
    untrusted: list[str] = []
    changes_requested: list[str] = []
    author_key = author.casefold() if author else None

    for key, review in latest.items():
        login = display_names[key]
        state = str(review.get("state", "")).upper()
        if state == "CHANGES_REQUESTED":
            if author_key is None or key != author_key:
                changes_requested.append(login)
            continue
        if state != "APPROVED":
            continue
        if author_key is not None and key == author_key:
            self_approvals.append(login)
            continue
        if policy.exclude_bots and _is_bot(review, login):
            bots.append(login)
            continue
        association = str(review.get("author_association", "NONE")).upper()
        trusted_logins = {item.casefold() for item in policy.trusted_reviewers}
        if association not in policy.allowed_author_associations and key not in trusted_logins:
            untrusted.append(login)
            continue
        commit_id = review.get("commit_id")
        is_fresh = isinstance(commit_id, str) and commit_id == head_sha
        if not is_fresh and not policy.allow_stale_approvals:
            stale.append(login)
            continue
        approvals.append(login)

    status = "passed" if len(approvals) >= policy.minimum_independent_approvals else "failed"
    detail = (
        f"Counted {len(approvals)} independent approval(s); "
        f"policy requires {policy.minimum_independent_approvals}."
    )
    return ReviewEvidence(
        status=status,
        required=True,
        required_on=policy.required_on,
        minimum_approvals=policy.minimum_independent_approvals,
        repository=repository,
        pull_request=pull_request,
        author=author,
        scanned_base_sha=base_sha,
        scanned_head_sha=head_sha,
        observed_base_sha=observed_base_sha,
        observed_head_sha=observed_head_sha,
        approvals=tuple(sorted(approvals, key=str.casefold)),
        stale_approvals=tuple(sorted(stale, key=str.casefold)),
        self_approvals=tuple(sorted(self_approvals, key=str.casefold)),
        bot_approvals=tuple(sorted(bots, key=str.casefold)),
        untrusted_approvals=tuple(sorted(untrusted, key=str.casefold)),
        changes_requested=tuple(sorted(changes_requested, key=str.casefold)),
        detail=detail,
    )


def collect_review_evidence(
    findings: list[Finding],
    *,
    policy: ReviewPolicy,
    context: PullRequestContext | None,
    scanned_base_sha: str,
    scanned_head_sha: str,
    token: str | None,
    api_url: str,
    api_version: str,
    client_factory: Callable[..., GitHubApiClient] = GitHubApiClient,
) -> tuple[ReviewEvidence, list[Finding]]:
    trigger_rank = SEVERITY_RANK[policy.required_on]
    required = policy.minimum_independent_approvals > 0 and any(
        SEVERITY_RANK[finding.severity] >= trigger_rank for finding in findings
    )
    if not required:
        return (
            ReviewEvidence(
                status="not_required",
                required=False,
                required_on=policy.required_on,
                minimum_approvals=policy.minimum_independent_approvals,
                repository=context.repository if context else None,
                pull_request=context.number if context else None,
                scanned_base_sha=scanned_base_sha,
                scanned_head_sha=scanned_head_sha,
                detail="No finding reached the configured review trigger, or the minimum approval count is zero.",
            ),
            [],
        )

    if context is None or context.repository is None or context.number is None:
        return _unavailable(
            policy,
            context,
            scanned_base_sha,
            scanned_head_sha,
            "Review policy is active, but repository and pull request context are unavailable.",
        )
    if not token:
        return _unavailable(
            policy,
            context,
            scanned_base_sha,
            scanned_head_sha,
            "Review policy is active, but no GitHub token was provided through the environment or action input.",
        )

    try:
        client = client_factory(token, api_url=api_url, api_version=api_version)
        pr = client.get_pull_request(context.repository, context.number)
        reviews = client.list_reviews(context.repository, context.number)
    except (GitHubApiError, ValueError) as exc:
        return _unavailable(policy, context, scanned_base_sha, scanned_head_sha, str(exc))

    head = pr.get("head")
    base = pr.get("base")
    observed_head = head.get("sha") if isinstance(head, dict) else None
    observed_base = base.get("sha") if isinstance(base, dict) else None
    if not isinstance(observed_head, str) or not isinstance(observed_base, str):
        return _unavailable(policy, context, scanned_base_sha, scanned_head_sha, "GitHub PR data did not include base and head commit SHAs.")

    expected_base = context.base_sha or observed_base
    base_mismatch = expected_base != scanned_base_sha
    event_head_mismatch = context.head_sha is not None and context.head_sha != scanned_head_sha
    api_head_mismatch = observed_head != scanned_head_sha
    if base_mismatch or event_head_mismatch or api_head_mismatch:
        evidence = ReviewEvidence(
            status="mismatch",
            required=True,
            required_on=policy.required_on,
            minimum_approvals=policy.minimum_independent_approvals,
            repository=context.repository,
            pull_request=context.number,
            author=context.author,
            scanned_base_sha=scanned_base_sha,
            scanned_head_sha=scanned_head_sha,
            observed_base_sha=observed_base,
            observed_head_sha=observed_head,
            detail="The scanned head commit does not match the pull request head commit.",
        )
        return evidence, [
            Finding(
                rule_id="RG014",
                severity="critical",
                title="Review evidence is bound to a different commit",
                detail=(
                    f"Scanned range is {scanned_base_sha}...{scanned_head_sha}; "
                    f"expected PR range is {expected_base}...{observed_head}. "
                    "Approvals cannot be reused across an unverified commit boundary."
                ),
                path="releaseguard.toml",
                remediation="Fetch and scan the exact pull request head commit, then obtain fresh review evidence.",
            )
        ]

    user = pr.get("user")
    author = user.get("login") if isinstance(user, dict) and isinstance(user.get("login"), str) else context.author
    evidence = evaluate_reviews(
        reviews,
        author=author,
        base_sha=scanned_base_sha,
        head_sha=scanned_head_sha,
        policy=policy,
        repository=context.repository,
        pull_request=context.number,
        observed_base_sha=observed_base,
        observed_head_sha=observed_head,
    )
    if evidence.approval_count >= policy.minimum_independent_approvals:
        return evidence, []

    details = [
        f"Counted {evidence.approval_count} fresh independent approval(s); policy requires {policy.minimum_independent_approvals}."
    ]
    if evidence.stale_approvals:
        details.append(f"Stale approvals: {', '.join(evidence.stale_approvals)}.")
    if evidence.self_approvals:
        details.append(f"Self-approvals excluded: {', '.join(evidence.self_approvals)}.")
    if evidence.bot_approvals:
        details.append(f"Bot approvals excluded: {', '.join(evidence.bot_approvals)}.")
    if evidence.untrusted_approvals:
        details.append(f"Untrusted approvals excluded: {', '.join(evidence.untrusted_approvals)}.")
    if evidence.changes_requested:
        details.append(f"Changes requested by: {', '.join(evidence.changes_requested)}.")
    return evidence, [
        Finding(
            rule_id="RG012",
            severity="critical",
            title="Independent review quorum not met",
            detail=" ".join(details),
            path="releaseguard.toml",
            remediation="Obtain the configured number of fresh approvals from reviewers other than the PR author.",
        )
    ]


def _unavailable(
    policy: ReviewPolicy,
    context: PullRequestContext | None,
    scanned_base_sha: str,
    scanned_head_sha: str,
    detail: str,
) -> tuple[ReviewEvidence, list[Finding]]:
    severity = "critical" if policy.fail_closed else "high"
    evidence = ReviewEvidence(
        status="unavailable",
        required=True,
        required_on=policy.required_on,
        minimum_approvals=policy.minimum_independent_approvals,
        repository=context.repository if context else None,
        pull_request=context.number if context else None,
        author=context.author if context else None,
        scanned_base_sha=scanned_base_sha,
        scanned_head_sha=scanned_head_sha,
        observed_base_sha=context.base_sha if context else None,
        observed_head_sha=context.head_sha if context else None,
        detail=detail,
    )
    return evidence, [
        Finding(
            rule_id="RG013",
            severity=severity,
            title="Required review evidence is unavailable",
            detail=detail,
            path="releaseguard.toml",
            remediation=(
                "Provide pull-requests: read permission and pass github-token to the action, "
                "or disable the review quorum explicitly for offline scans."
            ),
        )
    ]

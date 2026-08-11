# Reproducible demo

This demo creates a temporary Git repository and shows ReleaseGuard blocking an npm install-time execution change.

```bash
python -m pip install .

tmp="$(mktemp -d)"
cd "$tmp"
git init -q
git config user.name "ReleaseGuard Demo"
git config user.email "demo@example.invalid"

cat > package.json <<'JSON'
{"name":"releaseguard-demo","version":"1.0.0"}
JSON

git add package.json
git commit -qm "baseline"
base="$(git rev-parse HEAD)"

cat > package.json <<'JSON'
{
  "name": "releaseguard-demo",
  "version": "1.0.0",
  "scripts": {"postinstall": "node payload.js"}
}
JSON

git add package.json
git commit -qm "add install hook"

releaseguard scan \
  --base "$base" \
  --head HEAD \
  --config missing.toml \
  --output releaseguard-report.json \
  --sarif-output releaseguard.sarif
```

Expected behavior:

- finding `RG004` with `critical` severity;
- decision `BLOCK`;
- exit code `2`;
- JSON and SARIF evidence files.

## Python dependency example

A change such as:

```toml
[project]
dependencies = [
  "widget @ https://example.invalid/widget.whl",
]
```

produces critical `RG026` because the dependency bypasses the normal package-index version model.

## Cargo source example

A change such as:

```toml
[dependencies]
widget = { git = "https://example.invalid/widget", rev = "0123456" }
```

produces critical `RG030`. Adding or modifying `build.rs` produces high-severity `RG032`.

## npm provenance demo

The post-publish verifier must use a real, exact published package version because npm performs the cryptographic validation:

```bash
releaseguard verify-npm @scope/package \
  --version 1.2.3 \
  --repository owner/repository \
  --workflow .github/workflows/publish.yml \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --ref refs/tags/v1.2.3
```

Use a package and expected identity you control. A mismatch should remain a policy failure; do not weaken the expected identity merely to obtain a PASS result.

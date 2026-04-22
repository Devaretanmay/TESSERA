#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0
WARNINGS=0

pass() {
  printf 'PASS  %s\n' "$1"
}

warn() {
  WARNINGS=$((WARNINGS + 1))
  printf 'WARN  %s\n' "$1"
}

fail() {
  FAILURES=$((FAILURES + 1))
  printf 'FAIL  %s\n' "$1"
}

check_file() {
  local path="$1"
  local label="$2"
  if [[ -f "$path" ]]; then
    pass "$label present: ${path#$ROOT_DIR/}"
  else
    fail "$label missing: ${path#$ROOT_DIR/}"
  fi
}

check_python_runtime() {
  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is not installed on the host"
    return
  fi

  local version
  version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')"
  local major minor
  major="$(python3 -c 'import sys; print(sys.version_info.major)')"
  minor="$(python3 -c 'import sys; print(sys.version_info.minor)')"

  if [[ "$major" -eq 3 && "$minor" -ge 10 && "$minor" -le 12 ]]; then
    pass "host python version supported for package/CLI: ${version}"
  else
    warn "host python version is ${version}; supported matrix is 3.10-3.12, operational default is 3.11"
  fi
}

check_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    fail "docker is not installed"
    return
  fi

  pass "docker binary found: $(command -v docker)"

  if docker info >/dev/null 2>&1; then
    pass "docker daemon is reachable"
  else
    fail "docker daemon is not reachable"
  fi
}

check_reverse_proxy() {
  local found=0
  local proxy
  for proxy in nginx caddy traefik; do
    if command -v "$proxy" >/dev/null 2>&1; then
      pass "reverse proxy binary found: $proxy"
      found=1
    fi
  done

  if [[ "$found" -eq 0 ]]; then
    fail "no supported reverse proxy found (expected nginx, caddy, or traefik)"
  fi
}

check_port() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    warn "port ${port} already has a listening process"
  else
    pass "port ${port} appears free"
  fi
}

check_api_key_env() {
  if [[ -z "${TESSERA_API_KEYS_JSON:-}" ]]; then
    warn "TESSERA_API_KEYS_JSON is not set in the current environment"
    return
  fi

  if TESSERA_API_KEYS_JSON="$TESSERA_API_KEYS_JSON" python3 - <<'PY'
import json
import os
import sys

raw = os.environ["TESSERA_API_KEYS_JSON"]
data = json.loads(raw)

if not isinstance(data, list) or not data:
    raise SystemExit("expected a non-empty JSON array")

for idx, item in enumerate(data):
    for field in ("token_sha256", "tenant_id"):
        if field not in item or not item[field]:
            raise SystemExit(f"entry {idx} is missing {field}")
    token_hash = item["token_sha256"].lower()
    if len(token_hash) != 64 or any(ch not in "0123456789abcdef" for ch in token_hash):
        raise SystemExit(f"entry {idx} token_sha256 must be a 64-char hex string")

print(len(data))
PY
  then
    pass "TESSERA_API_KEYS_JSON is valid"
  else
    fail "TESSERA_API_KEYS_JSON is invalid"
  fi
}

check_release_artifacts() {
  if compgen -G "$ROOT_DIR/dist/*.whl" >/dev/null && compgen -G "$ROOT_DIR/dist/*.tar.gz" >/dev/null; then
    pass "release artifacts exist under dist/"
  else
    warn "release artifacts are missing from dist/; run python -m build before release validation"
  fi
}

check_gh_auth() {
  if ! command -v gh >/dev/null 2>&1; then
    warn "GitHub CLI is not installed; skip remote workflow checks"
    return
  fi

  if gh auth status >/dev/null 2>&1; then
    pass "GitHub CLI is authenticated"
  else
    warn "GitHub CLI is installed but not authenticated"
  fi
}

check_github_release_controls() {
  if ! command -v gh >/dev/null 2>&1; then
    return
  fi
  if ! gh auth status >/dev/null 2>&1; then
    return
  fi

  local repo branch
  repo="$(gh repo view --json nameWithOwner -q '.nameWithOwner' 2>/dev/null || true)"
  branch="$(gh repo view --json defaultBranchRef -q '.defaultBranchRef.name' 2>/dev/null || true)"

  if [[ -z "$repo" || -z "$branch" ]]; then
    warn "could not resolve GitHub repository metadata for remote checks"
    return
  fi

  if gh api "repos/${repo}/branches/${branch}/protection" >/dev/null 2>&1; then
    pass "default branch protection is enabled on ${repo}:${branch}"
  else
    fail "default branch ${repo}:${branch} is not protected"
  fi

  local environments_count
  environments_count="$(gh api "repos/${repo}/environments" -q '.total_count' 2>/dev/null || true)"
  if [[ -n "$environments_count" && "$environments_count" != "0" ]]; then
    pass "GitHub environments configured: ${environments_count}"
  else
    warn "no GitHub environments configured for ${repo}"
  fi

  local allowed_actions sha_pinning
  if allowed_actions="$(gh api "repos/${repo}/actions/permissions" -q '.allowed_actions' 2>/dev/null)" \
    && sha_pinning="$(gh api "repos/${repo}/actions/permissions" -q '.sha_pinning_required' 2>/dev/null)"; then
    if [[ "$allowed_actions" == "selected" ]]; then
      pass "GitHub Actions policy is restricted to selected actions"
    else
      warn "GitHub Actions policy is ${allowed_actions}; selected actions is safer for production repos"
    fi

    if [[ "$sha_pinning" == "true" ]]; then
      pass "GitHub Actions SHA pinning is required"
    else
      warn "GitHub Actions SHA pinning is not required"
    fi
  else
    warn "could not inspect GitHub Actions repository policy with the current gh token"
  fi
}

main() {
  echo "TESSERA host deployment preflight"
  echo "Repository: $ROOT_DIR"
  echo

  check_file "$ROOT_DIR/Dockerfile" "Dockerfile"
  check_file "$ROOT_DIR/.github/workflows/ci.yml" "CI workflow"
  check_file "$ROOT_DIR/.github/workflows/release.yml" "Release workflow"
  check_file "$ROOT_DIR/docs/DEPLOYMENT.md" "Deployment guide"
  check_file "$ROOT_DIR/docs/ENVIRONMENT.md" "Environment reference"

  check_python_runtime
  check_docker
  check_reverse_proxy
  check_port 8000
  check_api_key_env
  check_release_artifacts
  check_gh_auth
  check_github_release_controls

  echo
  echo "Summary: ${FAILURES} failure(s), ${WARNINGS} warning(s)"

  if [[ "$FAILURES" -gt 0 ]]; then
    exit 1
  fi
}

main "$@"

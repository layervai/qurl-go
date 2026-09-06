#!/usr/bin/env bash
set -euo pipefail

validate_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]
}

validate_ref() {
  [[ "$1" != "@" ]] &&
    [[ "$1" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]] &&
    git check-ref-format "refs/heads/$1" >/dev/null 2>&1
}

case "${CLAUDE_REVIEW_MODE}" in
  automatic)
    marker="${EXPECTED_REVIEW_MARKER}"
    ;;
  interactive)
    marker="${EXPECTED_RESULT_MARKER}"
    if [[ -z "${EXPECTED_TRIGGER_ACTOR}" ]]; then
      echo "::error::Claude command has no trigger actor."
      exit 1
    fi
    ;;
  *)
    echo "::error::Unknown Claude review mode."
    exit 1
    ;;
esac

if [[ -z "${CLAUDE_EXECUTION_FILE}" || ! -f "${CLAUDE_EXECUTION_FILE}" || ! -s "${CLAUDE_EXECUTION_FILE}" ||
      -z "${EXPECTED_ORIGIN}" || -z "${marker}" ]] ||
   ! validate_sha "${EXPECTED_HEAD_SHA}" ||
   ! validate_sha "${EXPECTED_BASE_SHA}" ||
   ! validate_sha "${EXPECTED_LOCAL_SHA}" ||
   ! validate_ref "${EXPECTED_HEAD_REF}" ||
   ! validate_ref "${EXPECTED_BASE_REF}" ||
   ! validate_ref "${TRUSTED_DEFAULT_REF}"; then
  echo "::error::Claude did not produce valid exact-snapshot evidence."
  exit 1
fi

remote_keys="$(git config --local --name-only --get-regexp '^remote\..*\.(url|pushurl)$' || true)"
if [[ "$(git remote)" != "origin" ||
      "${remote_keys}" != "remote.origin.url" ||
      "$(git remote get-url --all origin 2>/dev/null)" != "${EXPECTED_ORIGIN}" ||
      "$(git remote get-url --push --all origin 2>/dev/null)" != "${EXPECTED_ORIGIN}" ||
      "$(git config --local --get-all fetch.recurseSubmodules 2>/dev/null)" != "false" ||
      "$(git rev-parse --verify HEAD 2>/dev/null)" != "${EXPECTED_LOCAL_SHA}" ||
      "$(git --git-dir="${EXPECTED_ORIGIN}" rev-parse --verify "refs/heads/${EXPECTED_HEAD_REF}" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git --git-dir="${EXPECTED_ORIGIN}" rev-parse --verify "refs/heads/${EXPECTED_BASE_REF}" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ||
      "$(git rev-parse --verify "refs/heads/${EXPECTED_HEAD_REF}" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git rev-parse --verify "refs/heads/${EXPECTED_BASE_REF}" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ||
      "$(git rev-parse --verify "refs/remotes/origin/${EXPECTED_HEAD_REF}" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git rev-parse --verify "refs/remotes/origin/${EXPECTED_BASE_REF}" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ]] ||
   git config --local --get-regexp '^http\..*\.extraheader$' >/dev/null 2>&1 ||
   git config --local --get-regexp '^credential(\..*)?\.helper$' >/dev/null 2>&1; then
  echo "::error::Claude changed the credential-free origin."
  exit 1
fi

if ! current_pr="$(timeout 30s gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"; then
  echo "::error::Unable to refresh the current pull request."
  exit 1
fi

if [[ "${CLAUDE_REVIEW_MODE}" == "interactive" ]]; then
  if ! actor_permission="$(timeout 30s gh api \
    "repos/${GITHUB_REPOSITORY}/collaborators/${EXPECTED_TRIGGER_ACTOR}/permission" \
    --jq '.permission // ""')"; then
    echo "::error::Unable to refresh the trigger authorization."
    exit 1
  fi
  case "${actor_permission}" in
    admin|maintain|write) ;;
    *)
      echo "::error::Claude trigger actor lost repository write access."
      exit 1
      ;;
  esac
fi

current_state="$(jq -r '.state // ""' <<<"${current_pr}")"
current_draft="$(jq -r 'if .draft == null then "" else (.draft | tostring) end' <<<"${current_pr}")"
current_head_repo="$(jq -r '.head.repo.full_name // ""' <<<"${current_pr}")"
current_head_sha="$(jq -r '.head.sha // ""' <<<"${current_pr}")"
current_head_ref="$(jq -r '.head.ref // ""' <<<"${current_pr}")"
current_base_repo="$(jq -r '.base.repo.full_name // ""' <<<"${current_pr}")"
current_base_sha="$(jq -r '.base.sha // ""' <<<"${current_pr}")"
current_base_ref="$(jq -r '.base.ref // ""' <<<"${current_pr}")"
current_default_ref="$(jq -r '.base.repo.default_branch // ""' <<<"${current_pr}")"

if [[ "${current_state}" != "open" ||
      "${current_head_repo}" != "${GITHUB_REPOSITORY}" ||
      "${current_base_repo}" != "${GITHUB_REPOSITORY}" ||
      "${current_head_sha}" != "${EXPECTED_HEAD_SHA}" ||
      "${current_base_sha}" != "${EXPECTED_BASE_SHA}" ||
      "${current_head_ref}" != "${EXPECTED_HEAD_REF}" ||
      "${current_base_ref}" != "${EXPECTED_BASE_REF}" ||
      "${current_default_ref}" != "${TRUSTED_DEFAULT_REF}" ||
      "${current_base_ref}" != "${current_default_ref}" ||
      "${current_head_ref}" == "${current_default_ref}" ]] ||
   [[ "${CLAUDE_REVIEW_MODE}" == "automatic" && "${current_draft}" != "false" ]]; then
  echo "::error::Claude review is stale or the PR trust boundary changed."
  exit 1
fi

if ! review_comments="$(timeout 30s gh api --paginate --slurp \
  "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100")"; then
  echo "::error::Unable to verify Claude review publication."
  exit 1
fi
if ! jq -e --arg marker "${marker}" '
  [
    .[][]? |
    select(.user.login == "github-actions[bot]") |
    (.body // "" | sub("[\\r\\n]+$"; "")) as $body |
    select(
      ($body | endswith("\n" + $marker)) and
      (($body | rtrimstr("\n" + $marker) | gsub("[[:space:]]"; "") | length) > 0)
    )
  ] | length == 1
' <<<"${review_comments}" >/dev/null; then
  echo "::error::Claude did not publish exactly one substantive run-specific comment."
  exit 1
fi

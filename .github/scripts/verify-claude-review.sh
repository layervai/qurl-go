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
    snapshot_namespace="refs/automatic-review"
    ;;
  interactive)
    marker="${EXPECTED_RESULT_MARKER}"
    snapshot_namespace="refs/claude-command"
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

if [[ -z "${GITHUB_SERVER_URL:-}" || -z "${GITHUB_REPOSITORY:-}" ]]; then
  echo "::error::Runner-provided origin comparison targets are unavailable."
  exit 1
fi

if git config --local --get-regexp '^http\.(.*\.)?extraheader$' >/dev/null 2>&1 ||
   git config --local --get-regexp '^credential(\..*)?\.helper$' >/dev/null 2>&1; then
  echo "::error::The Claude run left a Git credential header or helper in the workspace."
  exit 1
fi

# The remote SET stays pinned: exactly one remote, named origin, with exactly
# one URL key and no pushurl. The URL itself is checked by destination below.
remote_keys="$(git config --local --name-only --get-regexp '^remote\..*\.(url|pushurl)$' || true)"
if [[ "$(git remote)" != "origin" || "${remote_keys}" != "remote.origin.url" ]]; then
  echo "::error::The Claude run added, removed, or reshaped a Git remote."
  exit 1
fi

# From v1.0.187 the action replaces origin, before the model's first token,
# with https://x-access-token:<token>@<server>/<owner>/<repo>.git, so the local
# pin no longer survives a run and asserting it would test the action's
# version, not what happened in the run. The property the pin carried is that
# origin addresses nothing but this repository; that is what is asserted here.
#
# origin_destination prints <scheme>://<host><path> with userinfo removed, or
# fails. The authority is everything up to the first "/", and userinfo is
# everything in it through the LAST "@": stripping to the first "@" of the
# whole URL would turn https://evil.example/@github.com/o/r.git into the
# allowed destination. Host and userinfo are then held to allowlists, because
# a URL client ends the host at "#", "?" or "\" as well: without that,
# https://evil.example#@github.com/o/r.git parses here as host github.com
# while git connects to evil.example. A shape outside the allowlists (an IPv6
# literal host, userinfo with other punctuation) fails closed.
origin_destination() {
  local url="$1" scheme rest authority host userinfo
  [[ "${url}" == *://* ]] || return 1
  scheme="${url%%://*}"
  rest="${url#*://}"
  authority="${rest%%/*}"
  host="${authority##*@}"
  if [[ "${authority}" == *@* ]]; then
    userinfo="${authority%@*}"
    [[ "${userinfo}" =~ ^[A-Za-z0-9._~%:_-]+$ ]] || return 1
  fi
  [[ "${scheme}" =~ ^[A-Za-z][A-Za-z0-9+.-]*$ &&
     "${host}" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || return 1
  printf '%s://%s%s' "${scheme}" "${host}" "${rest#"${authority}"}"
}

lowercase() {
  printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]'
}

# With or without ".git": both address the same repository. Owner, repository,
# and host names are case-insensitive on GitHub, so folding case cannot admit
# a different repository. `git remote get-url` applies url.*.insteadOf, so the
# value compared is the one Git would connect to.
repository_origin="$(lowercase "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}")"
if ! origin_fetch_url="$(git remote get-url --all origin 2>/dev/null)" ||
   ! origin_push_url="$(git remote get-url --push --all origin 2>/dev/null)"; then
  echo "::error::Unable to read the origin after the Claude run."
  exit 1
fi
for origin_candidate in "${origin_fetch_url}" "${origin_push_url}"; do
  # Never print origin_candidate: it may carry the token.
  if [[ -z "${origin_candidate}" || "${origin_candidate}" == *$'\n'* ]]; then
    echo "::error::Origin does not have exactly one fetch and one push URL."
    exit 1
  fi
  if [[ "${origin_candidate}" == "${EXPECTED_ORIGIN}" ]]; then
    continue
  fi
  if ! origin_dest="$(origin_destination "${origin_candidate}")"; then
    echo "::error::Origin is neither the local snapshot nor a recognizable URL of this repository."
    exit 1
  fi
  origin_dest="$(lowercase "${origin_dest}")"
  if [[ "${origin_dest}" != "${repository_origin}.git" &&
        "${origin_dest}" != "${repository_origin}" ]]; then
    # Print only scheme and host: the path of a hostile URL can carry anything,
    # including the token.
    origin_host="${origin_dest#*://}"
    echo "::error::Origin moved off this repository: got host '${origin_dest%%://*}://${origin_host%%/*}', want '${repository_origin}' (with or without .git) or the local snapshot."
    exit 1
  fi
done

if [[ "$(git config --local --get-all fetch.recurseSubmodules 2>/dev/null)" != "false" ]]; then
  echo "::error::The Claude run changed the submodule-safe fetch configuration."
  exit 1
fi

# refs/remotes/origin/* is deliberately absent: the action's own base-branch
# fetch may advance it when the base branch moves during a run. The snapshots
# are held by the local bare origin (which the action never addresses once it
# has re-pointed origin), the workspace branches, and the workflow-owned refs
# written by prepare-claude-origin.sh. A base branch that did move is caught
# by the live pull request comparison below.
if [[ "$(git rev-parse --verify HEAD 2>/dev/null)" != "${EXPECTED_LOCAL_SHA}" ||
      "$(git --git-dir="${EXPECTED_ORIGIN}" rev-parse --verify "refs/heads/${EXPECTED_HEAD_REF}" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git --git-dir="${EXPECTED_ORIGIN}" rev-parse --verify "refs/heads/${EXPECTED_BASE_REF}" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ||
      "$(git rev-parse --verify "refs/heads/${EXPECTED_HEAD_REF}" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git rev-parse --verify "refs/heads/${EXPECTED_BASE_REF}" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ||
      "$(git rev-parse --verify "${snapshot_namespace}/head" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git rev-parse --verify "${snapshot_namespace}/base" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ]]; then
  echo "::error::The Claude run changed the authorized local snapshots."
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

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

if ! validate_sha "${EXPECTED_HEAD_SHA}" ||
   ! validate_sha "${EXPECTED_BASE_SHA}" ||
   ! validate_sha "${EXPECTED_TRUSTED_SHA}" ||
   ! validate_ref "${EXPECTED_HEAD_REF}" ||
   ! validate_ref "${EXPECTED_BASE_REF}" ||
   ! validate_ref "${TRUSTED_DEFAULT_REF}" ||
   [[ "${EXPECTED_TRUSTED_SHA}" != "${EXPECTED_BASE_SHA}" ||
      "${EXPECTED_BASE_REF}" != "${TRUSTED_DEFAULT_REF}" ||
      "${EXPECTED_HEAD_REF}" == "${TRUSTED_DEFAULT_REF}" ]] ||
   [[ "${EXPECTED_HEAD_REF}" == "${EXPECTED_BASE_REF}" ||
      "${EXPECTED_HEAD_REF}" == "${EXPECTED_BASE_REF}/"* ||
      "${EXPECTED_BASE_REF}" == "${EXPECTED_HEAD_REF}/"* ]]; then
  echo "::error::Claude origin received invalid PR metadata."
  exit 1
fi

case "${CLAUDE_REVIEW_MODE}" in
  automatic)
    if [[ "${EXPECTED_STATE}" != "open" || "${EXPECTED_DRAFT}" != "false" ||
          "${EXPECTED_HEAD_REPO}" != "${GITHUB_REPOSITORY}" ||
          "${EXPECTED_BASE_REPO}" != "${GITHUB_REPOSITORY}" ||
          ! "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ||
          ! "${RUN_ID}" =~ ^[1-9][0-9]*$ ||
          ! "${RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]; then
      echo "::error::Claude review received unauthorized PR metadata."
      exit 1
    fi
    ;;
  interactive) ;;
  *)
    echo "::error::Unknown Claude review mode."
    exit 1
    ;;
esac

if ! trusted_sha="$(git rev-parse --verify HEAD 2>/dev/null)" ||
   ! validate_sha "${trusted_sha}" ||
   [[ "${trusted_sha}" != "${EXPECTED_TRUSTED_SHA}" ]] ||
   ! git cat-file -e "${EXPECTED_HEAD_SHA}^{commit}" 2>/dev/null ||
   ! git cat-file -e "${EXPECTED_BASE_SHA}^{commit}" 2>/dev/null; then
  echo "::error::Authorized Claude snapshots are unavailable from the trusted checkout."
  exit 1
fi
git checkout --detach --quiet "${trusted_sha}"

local_origin_parent="$(mktemp -d "${RUNNER_TEMP}/claude-origin.XXXXXX")"
local_origin="${local_origin_parent}/origin.git"
object_format="$(git rev-parse --show-object-format)"
git init --bare --quiet --object-format="${object_format}" "${local_origin}"
git push --quiet "${local_origin}" \
  "${EXPECTED_HEAD_SHA}:refs/heads/${EXPECTED_HEAD_REF}" \
  "${EXPECTED_BASE_SHA}:refs/heads/${EXPECTED_BASE_REF}"
git --git-dir="${local_origin}" symbolic-ref HEAD "refs/heads/${EXPECTED_BASE_REF}"
git remote set-url origin "${local_origin}"
git branch --force "${EXPECTED_HEAD_REF}" "${EXPECTED_HEAD_SHA}"
git branch --force "${EXPECTED_BASE_REF}" "${EXPECTED_BASE_SHA}"
git update-ref "refs/remotes/origin/${EXPECTED_HEAD_REF}" "${EXPECTED_HEAD_SHA}"
git update-ref "refs/remotes/origin/${EXPECTED_BASE_REF}" "${EXPECTED_BASE_SHA}"
git config --local fetch.recurseSubmodules false

check_origin() {
  remote_keys="$(git config --local --name-only --get-regexp '^remote\..*\.(url|pushurl)$' || true)"
  [[ "$(git remote)" == "origin" &&
     "${remote_keys}" == "remote.origin.url" &&
     "$(git remote get-url --all origin 2>/dev/null)" == "${local_origin}" &&
     "$(git remote get-url --push --all origin 2>/dev/null)" == "${local_origin}" &&
     "$(git config --local --get-all fetch.recurseSubmodules 2>/dev/null)" == "false" ]] &&
    ! git config --local --get-regexp '^http\..*\.extraheader$' >/dev/null 2>&1 &&
    ! git config --local --get-regexp '^credential(\..*)?\.helper$' >/dev/null 2>&1
}

if ! check_origin; then
  echo "::error::Claude origin retained a credential or unexpected remote."
  exit 1
fi

git fetch --quiet origin "${EXPECTED_BASE_REF}" --depth=1 --no-recurse-submodules
if ! check_origin ||
   [[ "$(git rev-parse --verify FETCH_HEAD 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ||
      "$(git rev-parse --verify "refs/heads/${EXPECTED_HEAD_REF}" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git rev-parse --verify "refs/heads/${EXPECTED_BASE_REF}" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ||
      "$(git rev-parse --verify "refs/remotes/origin/${EXPECTED_HEAD_REF}" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git rev-parse --verify "refs/remotes/origin/${EXPECTED_BASE_REF}" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ||
      "$(git --git-dir="${local_origin}" rev-parse --verify "refs/heads/${EXPECTED_HEAD_REF}" 2>/dev/null)" != "${EXPECTED_HEAD_SHA}" ||
      "$(git --git-dir="${local_origin}" rev-parse --verify "refs/heads/${EXPECTED_BASE_REF}" 2>/dev/null)" != "${EXPECTED_BASE_SHA}" ]]; then
  echo "::error::Claude origin did not preserve the authorized snapshots."
  exit 1
fi

{
  echo "path=${local_origin}"
  echo "trusted_sha=${trusted_sha}"
  if [[ "${CLAUDE_REVIEW_MODE}" == "automatic" ]]; then
    echo "review_marker=<!-- claude-review:${GITHUB_REPOSITORY}:pr-${PR_NUMBER}:run-${RUN_ID}:attempt-${RUN_ATTEMPT}:head-${EXPECTED_HEAD_SHA} -->"
  fi
  echo "ready=true"
} >> "${GITHUB_OUTPUT}"

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

if [[ ! "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]] ||
   ! pr="$(timeout 30s gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"; then
  echo "::error::Unable to resolve the Claude PR context."
  exit 1
fi

state="$(jq -r '.state // ""' <<<"${pr}")"
draft="$(jq -r 'if .draft == null then "" else (.draft | tostring) end' <<<"${pr}")"
head_repo="$(jq -r '.head.repo.full_name // ""' <<<"${pr}")"
head_sha="$(jq -r '.head.sha // ""' <<<"${pr}")"
head_ref="$(jq -r '.head.ref // ""' <<<"${pr}")"
base_repo="$(jq -r '.base.repo.full_name // ""' <<<"${pr}")"
base_sha="$(jq -r '.base.sha // ""' <<<"${pr}")"
base_ref="$(jq -r '.base.ref // ""' <<<"${pr}")"
default_ref="$(jq -r '.base.repo.default_branch // ""' <<<"${pr}")"

if [[ "${state}" != "open" ||
      "${head_repo}" != "${GITHUB_REPOSITORY}" ||
      "${base_repo}" != "${GITHUB_REPOSITORY}" ]] ||
   ! validate_sha "${head_sha}" ||
   ! validate_sha "${base_sha}" ||
   ! validate_sha "${EXPECTED_TRUSTED_SHA}" ||
   ! validate_ref "${head_ref}" ||
   ! validate_ref "${base_ref}" ||
   ! validate_ref "${default_ref}" ||
   ! validate_ref "${TRUSTED_DEFAULT_REF}" ||
   [[ "${base_sha}" != "${EXPECTED_TRUSTED_SHA}" ||
      "${default_ref}" != "${TRUSTED_DEFAULT_REF}" ||
      "${base_ref}" != "${default_ref}" ||
      "${head_ref}" == "${default_ref}" ]] ||
   [[ "${head_ref}" == "${base_ref}" ||
      "${head_ref}" == "${base_ref}/"* ||
      "${base_ref}" == "${head_ref}/"* ]]; then
  echo "::error::Claude requires a current open same-repository default-base PR with a non-default head."
  exit 1
fi

case "${CLAUDE_REVIEW_MODE}" in
  automatic)
    if [[ "${draft}" != "false" || "${state}" != "${EXPECTED_STATE}" ||
          "${draft}" != "${EXPECTED_DRAFT}" ||
          "${head_repo}" != "${EXPECTED_HEAD_REPO}" ||
          "${head_sha}" != "${EXPECTED_HEAD_SHA}" ||
          "${head_ref}" != "${EXPECTED_HEAD_REF}" ||
          "${base_repo}" != "${EXPECTED_BASE_REPO}" ||
          "${base_sha}" != "${EXPECTED_BASE_SHA}" ||
          "${base_ref}" != "${EXPECTED_BASE_REF}" ]]; then
      echo "::error::Claude review event metadata is stale."
      exit 1
    fi
    ;;
  interactive) ;;
  *)
    echo "::error::Unknown Claude review mode."
    exit 1
    ;;
esac

{
  echo "number=${PR_NUMBER}"
  echo "head_sha=${head_sha}"
  echo "head_ref=${head_ref}"
  echo "base_sha=${base_sha}"
  echo "base_ref=${base_ref}"
  echo "default_branch=${default_ref}"
} >> "${GITHUB_OUTPUT}"

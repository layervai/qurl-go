# OTP schema-v2 registration canary

This is the attended rollout procedure for proving that one real
`ConnectAgentRuntime` account enrollment, completed with an emailed one-time
code, writes the post-reset registered-agent schema and warm-opens
idempotently. It is deliberately not a general sandbox test and is not a
release gate by itself.

The qurl-go workflow performs no database access and has no direct writer. It
uses the same normal account credential, NHP registration writer, and mailbox
reader as the existing per-PR OTP gate. The pre-canary reset inventory is run
separately by qurl-service from its immutable API image, built from the same
qurl-service source as the final Authority writer image, and its protected AWS
lane. The Authority scratch image does not contain the inventory binary. That
separation keeps qurl-go from acquiring cross-repository or storage authority
merely to run one SDK canary.

## Protected execution boundary

The live GitHub Environment is `otp-schema-v2-canary` with these settings:

- required reviewer: `justin-layerv`;
- deployment branch policy: custom policy matching `main` only;
- administrator bypass: disabled;
- self-review: allowed because the sole reviewer is also the attended
  operator;
- Environment secrets: none. The workflow reuses the existing OTP harness's
  repository secrets after approval and never copies, prints, or rotates them.

The Environment is used only by a credential-free `authorize` job. That job has
`contents: read`, no `id-token: write`, and no secret references. The `canary`
job needs its success but does not declare an Environment, so GitHub preserves
the repository/ref OIDC subject rather than substituting an Environment
subject. Only that execution job has `id-token: write`, used for the existing
narrowly scoped mailbox-reader role. It emits no successful `go test -v`
transcript and never uses a cross-repository GitHub token. Its runner state,
state-encryption key, NHP device private key, emailed code, enrollment
credential, and AWS session are ephemeral. After the warm-open assertion, it
uploads one seven-day artifact containing only a linked SHA-256 commitment and
the public GitHub run tuple. No raw agent id, public key, device credential id,
or secret enters an artifact or log.

As of 2026-08-20, a read-only IAM inspection found that the existing qurl-go
mailbox role trusts `repo:layervai/qurl-go:pull_request` but not
`repo:layervai/qurl-go:ref:refs/heads/main`. That exact main subject must be
added through the separately reviewed owner of the existing role before this
canary can execute. This repository change does not broaden IAM, and the
workflow must not be dispatched while that prerequisite remains open.

The normal registration creates one durable server-side device credential.
The SDK has no sanctioned registration-revoke or agent-delete operation, so
the workflow does not invent one or write storage directly. `Destroy` wipes
the in-process binding; closing the sealed store reports any cleanup failure to
the test; and the hosted runner deletes the temporary state. The separately
governed reset/inventory lifecycle owns durable test records. If a run fails
after registration may have started, inventory the estate and use that
lifecycle before retrying instead of assuming the run was mutation-free.

## Required order

1. Finish the qurl-service producer. Retain both the final immutable
   `layerv/nhp-qurl@sha256:...` Authority writer digest and the same-source
   immutable API image/run that contains `qurl-agent-key-inventory`.
2. Run the exact current-main NHP pre-strict writer-convergence workflow across
   Control and both cells to terminal success. This must stop schema-v1 writers
   before reset. Retain its Actions run URL and exact 40-character NHP main
   commit.
3. Only after writer convergence, run the governed reset and the qurl-service
   inventory from the immutable API image produced from that same source. It
   must finish `PASS`; retain the API-image inventory run URL, reset-apply run
   URL, and reset manifest SHA-256. The Authority digest remains the
   writer-convergence receipt; it is not the inventory executable.
4. Confirm qurl-go `main` at the intended canary commit, then dispatch
   `otp-schema-v2-canary.yml` from `main` with all retained receipts and
   `receipts_reviewed=true`.
5. At the Environment approval prompt, inspect the private qurl-service and NHP
   runs. The qurl-go `github.token` cannot authenticate private sibling-repo
   conclusions, so the protected review is the explicit cross-repository trust
   decision, not a machine-verification claim.
6. Approve only while all receipts still apply. The credential-free Environment
   job immediately re-fetches qurl-go `origin/main` after approval and requires
   dispatch SHA, reviewed SHA, checkout, and current main to be identical. The
   separate canary job checks out that authorized SHA and re-fetches current
   main again before OIDC, secret references, or registration.
7. Retain the successful qurl-go run id and attempt. The qurl-service
   reset/inventory workflow maintainers, owned by the Connector rollout
   coordinator, must then run the separately protected read-only post-canary
   verifier from the same immutable API image that supplies
   `qurl-agent-key-inventory`. Do not dispatch the canary until that companion
   verifier is available.

   The verifier must require repository `layervai/qurl-go`, workflow
   `.github/workflows/otp-schema-v2-canary.yml`, event `workflow_dispatch`,
   `head_branch=main`, the exact then-current remote qurl-go main SHA, and a
   completed successful run at the operator-supplied run id and attempt. The
   protected verifier input also includes `canary_binding_sha256`. The reviewer
   must authenticate that hash against the qurl-go run summary or its retained
   artifact; the qurl-service `github.token` cannot be relied on to list or
   download a sibling repository's artifacts. The verifier treats that
   review as the cross-repository trust decision, validates the public run
   metadata and tuple, and locally constructs the canonical receipt with exact
   key order and no extra or duplicate keys:

   ```json
   {"schema_version":1,"binding_sha256":"<64-lowercase-hex>","github_run_id":123,"github_run_attempt":1}
   ```

   The qurl-go artifact remains retained source evidence. It is named
   `otp-schema-v2-canary-commitment-<run_id>-<run_attempt>` and contains only
   `canary-binding-commitment.json`; it is not a hidden machine-readable
   dependency for the qurl-service workflow.

   It must scan and correlate one complete linked triple across the schema-v2
   registration, owner claim, active API agent-key row, and active Authority
   device-credential head, then recompute the same commitment and require
   exactly one match. Production strong readers must revalidate that match.

   The shared sandbox can receive sanctioned browser enrollments and claims can
   expire between snapshots, so the verifier must not report an invented global
   `0 -> 1` or mechanically diff every counter against reset evidence. It must
   retain the actual post-canary counts and require a full strict inventory
   `PASS`: every registered agent is schema v2 and claimed; unsupported,
   malformed, unclaimed, and cross-owner counters are `0`; and the exact canary
   binding is unique and active. A strict-inventory or exact-binding failure is
   a failed rollout receipt. Until the verifier produces its protected PASS
   receipt, rollout remains blocked.

The canary's successful test asserts that registration returns a non-empty
device API key id and that a second `ConnectAgentRuntime` call against the same
sealed state returns the same device key id, agent id, public key, and
registration timestamp without requesting a second emailed code. That proves
the client behavior only. The governed post-canary verifier above closes the
server-side schema claim.

## Linked commitment contract

The commitment is byte-exact and domain separated. Compute SHA-256 over:

1. ASCII `layerv:qurl-go:otp-schema-v2-canary:binding:v1`;
2. one `0x00` byte;
3. for each value in this order — final canonical `agent_id`, the 44-byte
   canonical padded standard-base64 text encoding of the 32-byte X25519
   `public_key`, returned canonical `device_api_key_id` — a four-byte unsigned
   big-endian UTF-8 byte length followed by the raw UTF-8 bytes. Frame the
   public key's base64 text, not its 32 decoded bytes.

Encode the digest as 64 lowercase hexadecimal characters. The frozen
cross-repository known-answer vector is:

- agent id: `agent-canary-01`;
- public key: `AjPwBu9L7RROoKW7RscGfHwqzsX4zIEfPfWf3NWsdhQ=`;
- device API key id: `key_Durable12345`;
- digest: `88e8071c4c5e1e5222dda436d6f6f93f6654120d68190206bad3fce1a63189bc`.

The live test computes this linked digest only after the warm replay succeeds,
writes the canonical commitment file with mode `0600` and an exclusive create,
and fsyncs it. The workflow checks regular-file type, mode, exact schema,
canonical serialization, hash syntax, and run tuple before uploading exactly
that file. An `always()` cleanup step removes it from the runner and fails the
job if removal does not hold. The artifact never contains the raw triple.

## Dispatch shape

Do not dispatch until the reset and NHP prerequisites above are terminal and
reviewed. Substitute exact non-secret receipts; never put a credential in a
workflow input.

```bash
gh workflow run otp-schema-v2-canary.yml \
  --repo layervai/qurl-go \
  --ref main \
  -f expected_qurl_go_main_sha=<40-hex-qurl-go-main> \
  -f authority_image_digest=sha256:<64-hex-image-digest> \
  -f nhp_writer_convergence_run_url=https://github.com/layervai/nhp/actions/runs/<run-id> \
  -f nhp_writer_convergence_main_sha=<40-hex-nhp-main> \
  -f reset_inventory_pass_run_url=https://github.com/layervai/qurl-service/actions/runs/<run-id> \
  -f reset_manifest_sha256=<64-hex-manifest-sha256> \
  -F receipts_reviewed=true
```

This creates a run waiting on `otp-schema-v2-canary` approval. Dispatch is not
proof, approval is not proof, and a green qurl-go job alone is not proof. The
protected qurl-service verifier's PASS receipt is the final server-side rollout
receipt.

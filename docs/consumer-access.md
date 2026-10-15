# Private consumer access

Use `WithConsumerAccess(ConsumerAccessPolicy{Mode: "invite_only", Version: 1})`
when creating a resource with `ProtectURL` or qURL Connector. Modes are `keys`,
`invite_only`, `email_capture`, `review` and `contract`. Public resources continue
to use their existing flow. Change an existing private policy with
`UpdateConsumerAccess`, the current version, and the next policy version.

Publisher methods are `InviteConsumer`, `ListConsumerInvitations`,
`ResendConsumerInvitation`, `RevokeConsumerInvitation`, `ListConsumerGrants`,
`ApproveConsumerGrant`, `DenyConsumerGrant` and `RevokeConsumerGrant`. Lists return
`NextCursor`. Decisions require the version read from the grant or invitation.
Contract approval requires a trusted publisher backend entitlement receipt and
expiry. The SDK does not verify payment. Contract grant replies omit consumer
email and global credentials.

Consumers use `NewConsumerEnrollmentClient` with an independently obtained CRID,
a locally held Noise peer key, and trusted deployment configuration. `Info`
checks support before `Exchange` sends a mailbox code, invitation token or proof.
Use `ConsumerProofChallenge` for a passkey challenge. Email modes require a
verified mailbox and explicit consent to disclose it to the publisher. Mailbox
proof does not prove a person's legal identity.

`MintAdmission` takes the enrollment reference and a consumer-generated leaf
private key. It verifies the signed resource against the held CRID and verifies
the leaf key before it returns `ConsumerAdmission`. Reuse `Open` on that object
for session renewal. JSON and formatted output omit its keys and capability.
Keep peer keys, leaf keys and enrollment references in protected local state;
do not copy them to assistant notes or publisher API requests.

A removal reply can report `session_cleanup: pending`. Access is revoked, but
active connection cleanup is not yet confirmed. Retry the same removal and
version until `complete`. Do not report active connections stopped from a
`pending` receipt. Features remain disabled by default during integration.

Email access is always available as a backup to passkeys. The recipient selects
**Email me an access link** and verifies the mailbox. Publishers cannot disable
this option. Invitations, approval, entitlement, expiry, and revocation still
apply. A new email login keeps that mailbox's existing resource grant.

# Security policy

Only the explicitly maintained experimental branch is considered for fixes.
There is no production-support or response-time guarantee.

Do not put suspected vulnerabilities, tokens, account data, license information,
raw protocol payloads or crash dumps in public issues. After maintainers enable
GitHub private vulnerability reporting, use the repository's Security tab and
Report a vulnerability. A SECURITY.md file alone does not enable this feature.
If that private channel is unavailable, do not publish sensitive details; wait
for the owner to provide an approved private contact. No unverified email
address or response SLA is promised.

For an exposed real credential, revoke/rotate it through the issuer; deleting a
Git commit or making a repository private cannot retract existing clones.
Send only a minimal synthetic reproduction and affected revisions. Never send
live credentials or license/key material to maintainers.

Authentication must retain normal TLS validation and real account/license
checks. We do not accept bypasses, identity spoofing, leaked SDK code or game
redistribution. Use hosted, disposable CI with read-only default permissions;
no desktop keychain, game installs or production secrets on untrusted PR jobs.

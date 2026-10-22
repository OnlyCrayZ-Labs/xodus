# Contributing

Thank you for helping improve this experimental project. Open an issue before
large architectural changes. Include the source revision, Linux distribution,
GPU/driver versions, precise reproduction steps and expected/actual behavior.
Report only what you tested. Use synthetic minimal examples where possible.

Never upload game content, account identifiers, tokens, signatures, license
material, Wine prefixes, memory dumps, HAR files or raw network captures. Do
not attach private diagnostic logs without reviewing every field. Screenshots
must remove account/profile details and have appropriate sharing rights.

Fork the relevant code repository, use a topic branch, and submit a pull
request. Keep changes focused, preserve copyright/license notices, identify
upstream-derived code and provide its exact public source and license. Code
must not come from NDA SDKs, leaked sources or extracted proprietary game code.
Public interface documentation is not permission to copy a proprietary SDK.

Run the checks appropriate to the component. Service tests must use a new
CARGO_TARGET_DIR; runtime tests use synthetic fixtures and disposable prefixes.
Do not launch the real game, access the desktop keychain or run account tests
in CI. Document manual tests separately from automated evidence.

Contributions use the receiving files' existing licenses. Certify your right
to submit them using a DCO-style Signed-off-by line (`git commit -s`); this
records your chosen public identity and does not transfer ownership. No blanket
relicensing or claim to ownership of upstream work is accepted.

OnlyCrayZ reviews/merges official changes and controls official tags/releases.
Public contributions use PRs; no direct release-branch write access is implied.
An additional reviewer is preferred when available, but a one-maintainer team
must not configure an impossible requirement for its owner to approve their
own PR. Ownership and official release authority do not restrict license rights.

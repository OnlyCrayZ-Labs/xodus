# MSFS 2024 source candidate

Upstream: https://github.com/xodus-gaming/xodus
Upstream source revision: `53ea781dcd073e31d7ea68e894134e9c959bff04`.
License scope: GPL-3.0 (existing file grants control). Original copyright and license notices are retained.

This is a sanitized source snapshot with a new root. Upstream Git history is
not included because a captured documentation credential example is unresolved.
The captured device-flow example is replaced by a description without values.
Upstream authorship remains intact; this project does not claim authorship of
upstream code.

Local compatibility changes are derived from the private experimental milestone.
They use the existing component licensing and retain original notices. Public
interface contracts are references, not redistributed proprietary SDK files.
No libHttpClient C++ threading implementation is imported by this candidate.
No game files, private runtime binaries, captured credentials or backups are included.

The recorded successful flight applies to the preserved private runtime. This
source candidate has not yet reproduced that runtime from a clean checkout.

The service endpoint fixture is a projection of the pre-existing upstream
crates/xodus/src/api/xbox/title.rs test JSON: EndPoints and SignaturePolicies
are unchanged; Certs and RootCerts were omitted. It contains public endpoint
metadata, not an account capture.

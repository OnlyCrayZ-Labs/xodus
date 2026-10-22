# Device provisioning flow

This source snapshot omits captured authentication examples. Device member names
and passwords generated during provisioning are credential material, even when
random. Never publish them, device identifiers, signatures or license blocks.

Xodus provisions a device using its normal authenticated service flow and keeps
the resulting credentials in private local storage. The implementation is in
`crates/xodus/src/tokens/device.rs`; see also [CLEP](clep.md).

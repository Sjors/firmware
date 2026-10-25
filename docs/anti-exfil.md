# Experimental interactive Taproot anti-exfil

This branch implements the draft BIP-EXFIL protocol for BIP86 key-path inputs.
It supports PSBT versions 0 and 2 and SIGHASH_DEFAULT or SIGHASH_ALL. It does
not implement this protocol for MuSig2, script paths, registered Miniscript
wallets, or Taproot outputs with a script-tree commitment.

The host first adds a proprietary per-input key
`fc02616500 || output_key32` with a 32-byte host commitment. On approval,
the firmware adds `fc02616501 || output_key32` containing its full compressed
33-byte nonce point, and returns a PSBT without signatures. A retry of this
same request derives the same point, including its parity.

The host records that point before revealing its 32-byte nonzero scalar in
`fc02616502 || output_key32`. In the second invocation the firmware rederives
and checks both previous fields, adds the host contribution to its nonce,
verifies the resulting BIP340 signature, and returns the normal Taproot key
signature. The current UI requests transaction approval in both invocations.
No secret nonce state needs to survive between invocations.

The host must verify the original nonce relation and the signature before
using either. A bridge that only preserves unknown PSBT fields does not provide
this protection. Transcript fields remain in the response until the host
verifies it; the host must remove them before exporting the completed PSBT.
They must not be included in routine diagnostic logs. Automatic retries after
a nonce commitment must reuse the original transcript, rather than obtain new
host randomness.

Protected requests reject incomplete or noncanonical fields, more than one
signing key per input, mixed rounds, fields outside input maps, existing target
signatures/finalization, other sighashes, and unsupported spending paths. Only
targeted inputs receive new signatures. Input ownership, change checking,
transaction approval, and normal Taproot key-tweak checks still apply.

The native primitive comes from the linked experimental `Sjors/libngu` branch
`2026/10/taproot-anti-exfil`. Its nested libsecp256k1 version is unchanged.
`BIP-EXFIL/host` and `BIP-EXFIL/nonce` remain provisional domains; assigning a
BIP number requires coordinated vector regeneration and implementation changes.
This implementation has not received cryptographic review.

Tests for a native simulator build:

```
unix/coldcard-mpy external/libngu/ngu/ngu_tests/test_anti_exfil.py
env MICROPYPATH=shared unix/coldcard-mpy testing/devtest/anti_exfil_fields.py
```

HWI's corresponding branch includes device tests for both rounds, reconnecting,
firmware rejection of a bad reveal or nonce, both PSBT versions and supported
sighashes, and finalization, mempool acceptance, broadcast and confirmation.

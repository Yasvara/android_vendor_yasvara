# Boot digest SSOT regression checks

The boot digest is a measurement, not a PIF setting. `system_server` publishes
`ro.yasvara.boot.digest` (64/128 lowercase hex) and `ro.yasvara.boot.source`
once per boot, after the property and/or an original hardware attestation is
available. Conflicting bootloader/TEE measurements are not published. An old
persistent profile digest, a random value, or a device-specific signing-key
constant must never become a fallback.

The verified-boot state is spoofed deliberately: when the canonical digest is
present and agrees with the original hardware RootOfTrust, Java and Rust
re-sign a target app's attestation chain with the installed keybox and set
`deviceLocked = TRUE` plus `verifiedBootState = Verified(0)` inside the record.
The original `verifiedBootKey`, `verifiedBootHash`, challenge, and both KeyMint
security levels are preserved; an all-zero boot key is replaced because it
contradicts a Verified state.

That original hardware RootOfTrust is the only anchor for the spoof. Java and
Rust leave the original chain unchanged when the canonical value is missing,
disagrees with its `verifiedBootHash`, or the RootOfTrust itself is missing,
malformed, software-enforced, or duplicated. libc aliases the public runtime
digest to the same immutable measurement, with no process-local digest cache.
App processes read a green/locked verified-boot state and a user build story
(`ro.secure=1`, `ro.debuggable=0`, `ro.adb.secure=1`, `user`/`release-keys`,
normalized `.build.flavor`) from the libc hook while the spoof is enabled;
system processes keep the real state. The canonical public
properties are not secrets and must remain readable across processes.

The RKP request surface tells the same story. rkpd joins GMS and Play Store as a
PIF spoof target, and while the spoof toggles are on (`persist.sys.yasvara.trickystore`
umbrella plus `persist.sys.yasvara.rkp_spoof`) and the canonical digest is
readable, it appends unverified `vb_state`/`bootloader_state`/`vbmeta_digest`
claims to the CSR's unverified device info map (`YasvaraRkpClaims`). Missing
toggles or an unreadable digest leave that map byte-identical to the stock
behavior. The TEE-signed DeviceInfo is never edited by this path; the fully
forged-chain variant stays a separately gated lab probe.

## Host checks (from the source root)

```sh
python3 vendor/yasvara/tests/integrity/boot_digest_host_test.py
python3 vendor/yasvara/tests/integrity/leaf_patcher_host_test.py
python3 vendor/yasvara/tests/integrity/keybox_provider_host_test.py
python3 vendor/yasvara/tests/integrity/keybox_ssot_contract_test.py
mkdir -p /tmp/keybox-store && javac -d /tmp/keybox-store frameworks/base/services/core/java/com/android/server/yasvara/YasvaraKeyboxStore.java vendor/yasvara/tests/integrity/KeyboxStoreHostTest.java && java -cp /tmp/keybox-store com.android.server.yasvara.KeyboxStoreHostTest "$(mktemp -d)"
rustc --edition=2021 --test -D warnings system/security/keystore2/src/yasvara/attestation.rs -o /tmp/yasvara-attestation-tests
/tmp/yasvara-attestation-tests
python3 bionic/tests/yasvara_prop_host_test.py
python3 bionic/tests/yasvara_prop_host_test.py --sanitize thread
mkdir -p /tmp/rkp-claims && javac -d /tmp/rkp-claims packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/YasvaraRkpClaims.java vendor/yasvara/tests/integrity/rkp_claims_host_stubs/android/os/SystemProperties.java vendor/yasvara/tests/integrity/RkpClaimsHostTest.java && java -cp /tmp/rkp-claims com.android.rkpdapp.utils.RkpClaimsHostTest
```

The codec test requires a JDK. The signing round-trip test also needs the existing
built `framework.jar` identified by its runner; it uses fresh in-memory test keys,
not the installed keybox. Native sanitizer tests require the host compiler supported
by their runner. These tests do not contact Google or access the phone/keybox.
The Java runner also checks source-level contract drift; those checks are not a
substitute for an Android build or actual publisher lifecycle testing.

## Device validation after a coherent build/reboot

Read `ro.yasvara.boot.source`, `ro.yasvara.boot.digest`, and
`ro.boot.vbmeta.digest`; compare with a newly generated original hardware
attestation on the same build/slot. Also verify an early-boot unavailable source
leaves certificates unchanged and a user-0 unlock retries the measurement.
`prop_hook_smoke.sh` checks app/native reader behavior but requires a deliberately
authorized rooted-debugging environment; it is not run by the host checks.

Modern property callbacks support the full SHA-512 value. Deprecated fixed-size
`__system_property_get/read` buffers cannot represent 128 hex characters; they
return empty rather than a silently truncated digest. SHA-256 fits both paths.
Static libc and the linker retain their original property behavior.

These checks verify data consistency and memory safety, not a Google Play
Integrity verdict. The spoof is scoped to the verified-boot fields the
re-signer and libc hook own; any unlocked-boot, root, or injection signal on
surfaces they never touch remains a real finding. A green/locked spoof alone
does not establish the Strong Integrity verdict either — that ultimately depends
on acceptance of the keybox chain, which these host checks cannot decide.

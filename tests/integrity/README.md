# Yasvara Integrity SSOT Regression Checks

All integrity, attestation, boot-digest, PIF normalization, CBOR RKP provisioning parsing,
per-app patch-override resolution, X.509/DER codecs, and Bionic property-hiding policy share
one Rust Single Source of Truth under `vendor/yasvara/integrity/`:

- `crates/integrity-core`: `#![no_std]`, `#![forbid(unsafe_code)]`, zero external crates.
- `crates/integrity-bionic`: `#![no_std]`, zero-alloc, zero-TLS, lock-free Rust linked directly
  into Bionic `libc.so` (`libc_system_property_api_yasvara`).
- `crates/integrity-attest`: shared BoringSSL X.509/keybox/leaf/`PURPOSE_ATTEST_KEY` engine
  linked by both `keystore2` and `libyasvara_integrity_jni`.
- `crates/integrity-jni`: thin JNI bridge loaded once inside `system_server`.
- `crates/integrity-codegen`: build-time Soong `genrule` emitting `YasvaraIntegrityContract.java`
  and `yasvara_integrity_bionic.h`.

## Host checks (from the AOSP source root `src/`)

```sh
(cd vendor/yasvara/integrity && cargo test && cargo check -p yasvara-integrity-core --no-default-features && cargo check -p yasvara-integrity-bionic)
python3 -B bionic/tests/yasvara_prop_host_test.py
python3 -B bionic/tests/yasvara_prop_host_test.py --sanitize thread
python3 -B vendor/yasvara/tests/integrity/boot_digest_host_test.py
python3 -B vendor/yasvara/tests/integrity/keybox_ssot_contract_test.py
python3 -B vendor/yasvara/tests/integrity/build_props_contract_test.py
mkdir -p /tmp/keybox-store && javac -d /tmp/keybox-store frameworks/base/services/core/java/com/android/server/yasvara/YasvaraKeyboxStore.java vendor/yasvara/tests/integrity/KeyboxStoreHostTest.java && java -cp /tmp/keybox-store com.android.server.yasvara.KeyboxStoreHostTest "$(mktemp -d)"
mkdir -p /tmp/rkp-claims && javac -d /tmp/rkp-claims packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/YasvaraRkpClaims.java vendor/yasvara/tests/integrity/rkp_claims_host_stubs/android/os/SystemProperties.java vendor/yasvara/tests/integrity/RkpClaimsHostTest.java && java -cp /tmp/rkp-claims com.android.rkpdapp.utils.RkpClaimsHostTest
```

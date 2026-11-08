## Unreleased

- Re-exports `CompactToken` from package cb2, the experimental compact
  claims tokens cb3.local and cb3.public. The native library on every
  platform is built from bindings/c/src/cb2_c.cpp, so it carries the new
  `cb2_compact_*` functions without a vendored copy to refresh.
- A host test of a compact token round trip and its key digest.
- Re-exports `ClaimTable` and the `table:` option of `CompactToken`, over
  the `cb2_claim_table_*` and `cb2_compact_*_with_table` functions, which
  the native library on every platform carries for the same reason.
- A host test of a compact token under a claim table, and an example app
  step that opens one.
- Android support for arm64-v8a, armeabi-v7a and x86_64 from API 24.
  `tool/build_android_deps.sh` builds libsodium, BLAKE3 and liboqs with
  the NDK from the same hash-pinned releases as the Apple build, and the
  Gradle build points CMake at them through `CB2_DEPS_ROOT`. OpenSSL is
  not used on Android, so `CB2_OPENSSL_CHACHA` defaults to off there.
- The example app runs on Android, and a profile mode integration test
  times every token format on the device with the Dart benchmark cases.

## 0.2.0

- iOS and macOS ship `cb2_c.framework`, a dynamic framework built by
  `tool/build_xcframework.sh` from hash-pinned libsodium, BLAKE3 and
  liboqs, in place of a static library that needed `-force_load`.
- Swift Package Manager support next to CocoaPods.
- `Cb2Flutter.ensureInitialized` prefers the bundled library to one
  named by `CB2_C_LIBRARY`, so an app's environment cannot swap it.
- An example app for iOS and macOS with widget, host and integration
  tests.
- `very_good_analysis` with strict casts, inference and raw types; the
  plugin class moves to `lib/src`.
- Depends on package cb2 0.2.0, where the holder proof rules move to
  `HolderRules`.

## 0.1.0

- First packaging of the cb2 C ABI for Flutter: native builds for Android,
  Linux and Windows from bindings/c, prebuilt XCFramework for iOS and
  macOS, Dart API re-exported from package cb2.

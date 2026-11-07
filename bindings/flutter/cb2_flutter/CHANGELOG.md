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

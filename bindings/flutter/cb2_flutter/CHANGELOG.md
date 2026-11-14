## 0.4.0

- A web platform: `Cb2FlutterWeb` is the plugin class Flutter registers
  in a browser build (it registers nothing), and package cb2 0.3.0 runs
  there over its WebAssembly engine, which Flutter serves from cb2's
  assets at `assets/packages/cb2/js/`.
- `Cb2Flutter.load()`: `ensureInitialized`, then `Cb2Library.load()`.
  In a browser it must be awaited before the first cb2 call; natively
  it opens the library early.
- The example app runs in a browser: `main` awaits `Cb2Flutter.load()`,
  the demo runs through `compute` instead of `Isolate.run`, and
  `example/web` is the Flutter web shell. Built with `flutter build web`
  and run in Chrome.
- The host tests are marked for the VM.
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
- The example app runs on Android, and a profile mode integration test
  times every token format on the device with the Dart benchmark cases.

## 0.3.0

- Android links no OpenSSL by default: `CB2_OPENSSL_CHACHA` is off on
  Android, and `crypto` leaves the default libraries whenever it is off.
- Android links libc++ statically and exports exactly the `cb2_*`
  functions of `cb2_c.h` (a version script made from the header,
  `--exclude-libs,ALL`, `--gc-sections`), so the app needs no
  `libc++_shared.so` and the library no longer exports its
  dependencies. LOAD segments stay aligned to 16 KB.
- Android builds for the ABIs in `CB2_ANDROID_ABIS` (default
  `arm64-v8a,armeabi-v7a,x86_64`), and the build stops with the missing
  directory named when `CB2_DEPS_ROOT` has no prefix for an ABI, instead
  of falling back to the root.
- `tool/build_android_deps.sh` builds hash-pinned libsodium, BLAKE3 and
  liboqs for each ABI into `build/android-deps`, the default
  `CB2_DEPS_ROOT` on Android; `tool/check_android_library.sh` checks the
  exports, the needed libraries and the page alignment of each ABI.
- `cb2_c.framework` exports the list of `cb2_*` names read from
  `cb2_c.h`, is stripped of local symbols, and the build stops when a
  slice exports anything else.
- cb2.local falls back to libsodium's ChaCha20 when the linked OpenSSL
  has none, instead of failing with `internal` for messages of 512
  bytes or more.
- The README gives the tested Android recipe.

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

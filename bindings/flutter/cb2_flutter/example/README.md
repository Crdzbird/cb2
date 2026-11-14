# cb2_flutter example

One page that runs the cb2 token demo in the native library, off the UI
isolate, and lists every step:

- seal a cb2.local token and open it;
- open it again, refused as `replayed`;
- open a tampered copy, refused as `invalid`;
- seal the same claims as a compact cb3.local token and open it;
- open a compact token made under a claim table, with the same table;
- sign a cb2.public token and verify it with the public key;
- verify it for another audience, refused as `audience_mismatch`.

## Run

Build the XCFramework once from the plugin directory, then run the app:

    ../tool/build_xcframework.sh
    flutter run -d macos
    flutter run -d "iPhone 18 Pro"

## Test

    flutter test integration_test -d macos
    CB2_C_LIBRARY=/path/to/build/bindings/c/libcb2_c.dylib flutter test

The integration test drives the app on a device against the bundled
library. The host tests check the step tile, and run the whole demo when
`CB2_C_LIBRARY` names a host build of the C library.

## Layout

- `lib/src/demo`: the demo in plain Dart, without Flutter imports; each
  step reports what the library returned or why it refused.
- `lib/src/view`: the page, its state, and one widget per tile.
- `lib/src/app`: the `MaterialApp`.

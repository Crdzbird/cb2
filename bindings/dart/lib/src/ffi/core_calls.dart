import 'dart:ffi';

import 'package:cb2/src/ffi/key_signatures.dart';

/// The library-wide entry points of cb2_c.h: version, build features,
/// error names and the release of buffers the library hands out.
final class CoreCalls {
  /// The calls of [library].
  CoreCalls(this.library);

  /// The opened cb2 C library.
  final DynamicLibrary library;

  /// cb2_version.
  late final Pointer<Char> Function() version = library
      .lookupFunction<Pointer<Char> Function(), Pointer<Char> Function()>(
        'cb2_version',
      );

  /// cb2_has_public.
  late final int Function() hasPublic = library
      .lookupFunction<Int Function(), int Function()>('cb2_has_public');

  /// cb2_has_seal.
  late final int Function() hasSeal = library
      .lookupFunction<Int Function(), int Function()>('cb2_has_seal');

  /// cb2_error_name.
  late final Pointer<Char> Function(int) errorName = library
      .lookupFunction<Pointer<Char> Function(Int), Pointer<Char> Function(int)>(
        'cb2_error_name',
      );

  /// cb2_free.
  late final VoidOfDart free = library.lookupFunction<VoidOfNative, VoidOfDart>(
    'cb2_free',
  );

  /// cb2_free_secret.
  late final void Function(Pointer<Char>) freeSecret = library
      .lookupFunction<
        Void Function(Pointer<Char>),
        void Function(Pointer<Char>)
      >('cb2_free_secret');
}

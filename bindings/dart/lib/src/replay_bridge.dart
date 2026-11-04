import 'dart:convert';
import 'dart:ffi';

import 'bindings.dart';
import 'replay_check.dart';

/// Hands a Dart [ReplayCheck] to the library as a C function pointer for
/// the duration of one call. The native callable is isolate-local, so the
/// library must call it on the calling thread, which cb2_c does. An
/// exception inside the check refuses the id.
final class ReplayBridge {
  ReplayBridge._(this._callable);

  /// A bridge for [check]; a null check yields the null pointer.
  static ReplayBridge of(ReplayCheck? check) {
    if (check == null) {
      return ReplayBridge._(null);
    }
    int trampoline(Pointer<Void> user, Pointer<Char> jti, int len) {
      try {
        final id = utf8.decode(jti.cast<Uint8>().asTypedList(len));
        return check(id) ? 1 : 0;
      } on Object {
        return 0;
      }
    }

    final callable = NativeCallable<ReplayNative>.isolateLocal(
      trampoline,
      exceptionalReturn: 0,
    );
    return ReplayBridge._(callable);
  }

  final NativeCallable<ReplayNative>? _callable;

  /// The function pointer to pass to the library.
  Pointer<NativeFunction<ReplayNative>> get pointer =>
      _callable?.nativeFunction ?? nullptr;

  /// Releases the native callable; the pointer is invalid afterwards.
  void close() => _callable?.close();
}

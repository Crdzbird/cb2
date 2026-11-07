import 'dart:ffi';

import 'package:cb2/src/ffi/key_signatures.dart';
import 'package:cb2/src/ffi/table_signatures.dart';

/// The claim table entry points of cb2_c.h: the table handle and the
/// compact token calls that take one.
final class TableCalls {
  /// The calls of [library].
  TableCalls(this.library);

  /// The opened cb2 C library.
  final DynamicLibrary library;

  /// cb2_claim_table_from_json.
  late final FromTextDart fromJson = library
      .lookupFunction<FromTextNative, FromTextDart>(
        'cb2_claim_table_from_json',
      );

  /// cb2_claim_table_digest.
  late final TableDigestDart digest = library
      .lookupFunction<TableDigestNative, TableDigestDart>(
        'cb2_claim_table_digest',
      );

  /// cb2_claim_table_free as a pointer, for a [NativeFinalizer].
  late final Pointer<NativeFunction<VoidOfNative>> freePointer = library.lookup(
    'cb2_claim_table_free',
  );

  /// cb2_claim_table_free.
  late final VoidOfDart free = freePointer.asFunction<VoidOfDart>();

  /// cb2_compact_seal_with_table.
  late final TableSealDart seal = library
      .lookupFunction<TableSealNative, TableSealDart>(
        'cb2_compact_seal_with_table',
      );

  /// cb2_compact_sign_with_table.
  late final TableSealDart sign = library
      .lookupFunction<TableSealNative, TableSealDart>(
        'cb2_compact_sign_with_table',
      );

  /// cb2_compact_open_with_table.
  late final TableOpenDart open = library
      .lookupFunction<TableOpenNative, TableOpenDart>(
        'cb2_compact_open_with_table',
      );

  /// cb2_compact_verify_with_table.
  late final TableOpenDart verify = library
      .lookupFunction<TableOpenNative, TableOpenDart>(
        'cb2_compact_verify_with_table',
      );
}

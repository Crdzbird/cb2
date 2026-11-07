import 'package:cb2/src/claim_table.dart';
import 'package:cb2/src/ffi/claims_signatures.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/ffi/table_signatures.dart';

/// [call] with [table] bound after the key, as an issuing call.
TokenSealDart tabledIssue(TableSealDart call, ClaimTable table) =>
    (key, claims, claimsLen, implicit, implicitLen, outToken, outLen) => call(
      key,
      table.handle,
      claims,
      claimsLen,
      implicit,
      implicitLen,
      outToken,
      outLen,
    );

/// [call] with [table] bound after the key, as a checking call.
TokenOpenDart tabledCheck(TableOpenDart call, ClaimTable table) =>
    (
      key,
      token,
      tokenLen,
      rules,
      rulesLen,
      implicit,
      implicitLen,
      replay,
      proofReplay,
      user,
      outClaims,
      outLen,
    ) => call(
      key,
      table.handle,
      token,
      tokenLen,
      rules,
      rulesLen,
      implicit,
      implicitLen,
      replay,
      proofReplay,
      user,
      outClaims,
      outLen,
    );

/// The cb3.local issuing call, under [table] when one is given.
TokenSealDart compactSeal(ClaimTable? table) => table == null
    ? bindings.compact.seal
    : tabledIssue(bindings.tables.seal, table);

/// The cb3.public issuing call, under [table] when one is given.
TokenSealDart compactSign(ClaimTable? table) => table == null
    ? bindings.compact.sign
    : tabledIssue(bindings.tables.sign, table);

/// The cb3.local checking call, under [table] when one is given.
TokenOpenDart compactOpen(ClaimTable? table) => table == null
    ? bindings.compact.open
    : tabledCheck(bindings.tables.open, table);

/// The cb3.public checking call, under [table] when one is given.
TokenOpenDart compactVerify(ClaimTable? table) => table == null
    ? bindings.compact.verify
    : tabledCheck(bindings.tables.verify, table);

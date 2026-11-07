import 'package:cb2_benchmark/src/bench_settings.dart';
import 'package:cb2_benchmark/src/claims.dart';
import 'package:cb2_benchmark/src/format_result.dart';
import 'package:cb2_benchmark/src/paseto_claims.dart';
import 'package:cb2_benchmark/src/timing.dart';
import 'package:paseto_dart/paseto_dart.dart';

const _library = 'paseto_dart 2.1.0 (pure Dart)';

/// PASETO v4.local: encrypt, then decrypt and validate the claims.
Future<FormatResult> benchPasetoLocal(BenchSettings settings) async {
  final key = Paseto.generateSymmetricKey();
  final claims = textClaims();
  Future<String> issue() => Paseto.encryptLocal(payload: claims, key: key);
  Future<void> check(String token) async =>
      checkPasetoClaims(await Paseto.decryptLocal(token: token, key: key));
  final token = await issue();
  await check(token);
  final result = FormatResult(
    format: 'PASETO v4.local',
    library: _library,
    issueMicros: await timeAsync(settings, issue),
    checkMicros: await timeAsync(settings, () => check(token)),
    bytes: token.length,
  );
  key.dispose();
  return result;
}

/// PASETO v4.public: sign, then verify and validate the claims.
Future<FormatResult> benchPasetoPublic(BenchSettings settings) async {
  final pair = await Paseto.generateKeyPair();
  final claims = textClaims();
  Future<String> issue() =>
      Paseto.signPublicToken(payload: claims, keyPair: pair);
  Future<void> check(String token) async => checkPasetoClaims(
    await Paseto.verifyPublicToken(token: token, publicKey: pair.publicKey),
  );
  final token = await issue();
  await check(token);
  final result = FormatResult(
    format: 'PASETO v4.public',
    library: _library,
    issueMicros: await timeAsync(settings, issue),
    checkMicros: await timeAsync(settings, () => check(token)),
    bytes: token.length,
  );
  pair.dispose();
  return result;
}

@TestOn('browser')
library;

import 'dart:convert';

import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'support/native.dart';
import 'support/proof_vector.dart';
import 'support/served_engine.dart';

/// The holder proof vectors of tests/vectors/proofs.json, which the C++
/// reference generated, decided in the browser: every proof, local and
/// public, gives the verdict the reference recorded, and every target
/// normalizes as the reference does. The native side reads the file.
void main() {
  late Map<String, Object?> doc;

  setUpAll(() async {
    await loadServedEngine();
    final text = await askNative(const {'op': 'vectors'});
    doc = jsonDecode(text! as String) as Map<String, Object?>;
  });

  test('every holder proof vector gives its recorded verdict', () {
    final tests = (doc['tests']! as List).cast<Map<String, Object?>>();
    final local = tests.where(
      (t) => (t['proof']! as String).startsWith('cb2.holder-local.'),
    );
    expect(tests, hasLength(greaterThanOrEqualTo(50)));
    expect(local, hasLength(greaterThanOrEqualTo(20)));
    for (final t in tests) {
      expect(proofVectorVerdict(doc, t), t['expect'], reason: '${t['name']}');
    }
  });

  test('every target normalizes as the reference recorded', () {
    final cases = (doc['normalisation']! as List).cast<Map<String, Object?>>();
    expect(cases, isNotEmpty);
    for (final c in cases) {
      final input = c['input']! as String;
      final output = c['output'] as String?;
      if (output == null) {
        expect(
          () => Holder.normalizeTarget(input),
          throwsA(
            isA<Cb2Exception>().having((e) => e.name, 'name', 'argument'),
          ),
          reason: input,
        );
        continue;
      }
      expect(Holder.normalizeTarget(input), output, reason: input);
    }
  });
}

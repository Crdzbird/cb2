import 'package:cb2/cb2.dart';
import 'package:cb2_benchmark/src/bench_settings.dart';
import 'package:cb2_benchmark/src/cb2_cases.dart';
import 'package:cb2_benchmark/src/compact_cases.dart';
import 'package:cb2_benchmark/src/format_result.dart';
import 'package:cb2_benchmark/src/jwt_cases.dart';
import 'package:cb2_benchmark/src/paseto_cases.dart';

/// Times every format on the same claims, local formats first, and
/// returns one result per format. The public cb2 formats are left out
/// when the library was built without cb2.public.
Future<List<FormatResult>> runBenchmarks(BenchSettings settings) async {
  final results = <FormatResult>[
    benchCb2Local(settings),
    benchCompactLocal(settings),
    benchCompactTableLocal(settings),
    benchJwtHs256(settings),
    await benchPasetoLocal(settings),
  ];
  if (hasPublic()) {
    results
      ..add(benchCb2Public(settings))
      ..add(benchCompactPublic(settings));
  }
  results
    ..add(benchJwtEdDsa(settings))
    ..add(benchJwtEs256(settings))
    ..add(await benchPasetoPublic(settings));
  return results;
}

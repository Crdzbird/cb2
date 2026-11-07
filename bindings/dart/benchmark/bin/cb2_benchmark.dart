import 'dart:io';

import 'package:cb2/cb2.dart';
import 'package:cb2_benchmark/src/bench_settings.dart';
import 'package:cb2_benchmark/src/cb2_cases.dart';
import 'package:cb2_benchmark/src/compact_cases.dart';
import 'package:cb2_benchmark/src/format_result.dart';
import 'package:cb2_benchmark/src/jwt_cases.dart';
import 'package:cb2_benchmark/src/paseto_cases.dart';

/// Times every format on the same claims and prints a Markdown table.
/// Pass --quick for a short smoke run whose numbers mean nothing.
Future<void> main(List<String> args) async {
  final settings = args.contains('--quick')
      ? BenchSettings.quick
      : BenchSettings.full;
  stdout
    ..writeln('Dart ${Platform.version}')
    ..writeln(
      '${Platform.operatingSystemVersion}, '
      '${Platform.numberOfProcessors} cores',
    )
    ..writeln('cb2 ${version()}, public ${hasPublic()}');
  final results = <FormatResult>[
    benchCb2Local(settings),
    benchCompactLocal(settings),
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
  stdout
    ..writeln()
    ..writeln('| format | library | issue (us) | check (us) | bytes |')
    ..writeln('| --- | --- | ---: | ---: | ---: |');
  for (final result in results) {
    stdout.writeln(result.toRow());
  }
}

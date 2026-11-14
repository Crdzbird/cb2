import 'dart:io';

import 'package:cb2/cb2.dart';
import 'package:cb2_benchmark/cb2_benchmark.dart';

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
  final results = await runBenchmarks(settings);
  stdout
    ..writeln()
    ..writeln('| format | library | issue (us) | check (us) | bytes |')
    ..writeln('| --- | --- | ---: | ---: | ---: |');
  for (final result in results) {
    stdout.writeln(result.toRow());
  }
}

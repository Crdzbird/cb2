import 'package:cb2_benchmark/src/bench_settings.dart';

/// The median microseconds per call of the synchronous [op].
double timeSync(BenchSettings settings, void Function() op) {
  final warm = Stopwatch()..start();
  while (warm.elapsed < settings.warmup) {
    op();
  }
  final perCall = <double>[];
  for (var s = 0; s < settings.samples; s++) {
    final watch = Stopwatch()..start();
    var calls = 0;
    while (watch.elapsed < settings.sampleTime) {
      op();
      calls++;
    }
    perCall.add(watch.elapsedMicroseconds / calls);
  }
  return median(perCall);
}

/// The median microseconds per call of the asynchronous [op], each call
/// awaited before the next.
Future<double> timeAsync(
  BenchSettings settings,
  Future<void> Function() op,
) async {
  final warm = Stopwatch()..start();
  while (warm.elapsed < settings.warmup) {
    await op();
  }
  final perCall = <double>[];
  for (var s = 0; s < settings.samples; s++) {
    final watch = Stopwatch()..start();
    var calls = 0;
    while (watch.elapsed < settings.sampleTime) {
      await op();
      calls++;
    }
    perCall.add(watch.elapsedMicroseconds / calls);
  }
  return median(perCall);
}

/// The median of [values], which must not be empty.
double median(List<double> values) {
  final sorted = [...values]..sort();
  final mid = sorted.length ~/ 2;
  if (sorted.length.isOdd) {
    return sorted[mid];
  }
  return (sorted[mid - 1] + sorted[mid]) / 2;
}

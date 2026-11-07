/// How long and how often each operation is timed.
final class BenchSettings {
  /// [samples] samples of at least [sampleTime] each, after [warmup].
  const factory BenchSettings({
    required Duration warmup,
    required Duration sampleTime,
    required int samples,
  }) = BenchSettings._;

  const BenchSettings._({
    required this.warmup,
    required this.sampleTime,
    required this.samples,
  });

  /// The full run: 300 ms of warmup, then 21 samples of 25 ms.
  static const full = BenchSettings(
    warmup: Duration(milliseconds: 300),
    sampleTime: Duration(milliseconds: 25),
    samples: 21,
  );

  /// A smoke run for CI, too short for numbers worth reading.
  static const quick = BenchSettings(
    warmup: Duration(milliseconds: 10),
    sampleTime: Duration(milliseconds: 2),
    samples: 3,
  );

  /// Time spent running the operation before any sample.
  final Duration warmup;

  /// The least time one sample runs the operation for.
  final Duration sampleTime;

  /// How many samples the median is taken over.
  final int samples;
}

/// What one token format costs: the median time to issue a token, to
/// check it with its claims validated, and the token size.
final class FormatResult {
  /// The result for [format] made by [library].
  const factory FormatResult({
    required String format,
    required String library,
    required double issueMicros,
    required double checkMicros,
    required int bytes,
  }) = FormatResult._;

  const FormatResult._({
    required this.format,
    required this.library,
    required this.issueMicros,
    required this.checkMicros,
    required this.bytes,
  });

  /// The token format, such as cb2.local or JWT HS256.
  final String format;

  /// The package and version that made and checked the tokens.
  final String library;

  /// Median microseconds to issue one token.
  final double issueMicros;

  /// Median microseconds to check one token and validate its claims.
  final double checkMicros;

  /// The size of the token text in bytes.
  final int bytes;

  /// The row of the results table.
  String toRow() =>
      '| $format | $library | ${_us(issueMicros)} | ${_us(checkMicros)} '
      '| $bytes |';

  static String _us(double micros) =>
      micros < 100 ? micros.toStringAsFixed(1) : micros.toStringAsFixed(0);
}

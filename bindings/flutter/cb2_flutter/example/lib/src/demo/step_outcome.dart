/// What happened at one step of the demo.
enum StepOutcome {
  /// The library accepted what it should accept.
  accepted,

  /// The library refused what it should refuse.
  refused,

  /// The step was not run, such as cb2.public in a build without liboqs.
  skipped,

  /// The library did the opposite of what it should, or failed.
  failed,
}

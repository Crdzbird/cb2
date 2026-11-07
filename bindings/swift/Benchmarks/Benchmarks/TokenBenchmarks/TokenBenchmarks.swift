import Benchmark
import TokenFixtures

/// Issue and verify for every format, on the same claims. Keys and the
/// token to verify are made before `startMeasurement`; a sample is 1000
/// issues or verifies with them, and the reported time is per operation.
let benchmarks: @Sendable () -> Void = {
    Benchmark.defaultConfiguration = .init(
        metrics: [.wallClock, .throughput],
        timeUnits: .microseconds,
        warmupIterations: 3,
        scalingFactor: .kilo,
        maxDuration: .seconds(10),
        maxIterations: 200
    )

    for entry in Formats.all {
        Benchmark("\(entry.name) issue") { benchmark in
            let format = try await entry.make()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(try await format.issue())
            }
        }
        Benchmark("\(entry.name) verify") { benchmark in
            let format = try await entry.make()
            let token = try await format.issue()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try await format.verify(token)
            }
        }
    }
}

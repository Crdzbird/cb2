import Cb2Walkthrough
import Observation

/// Runs the walkthrough off the main actor and publishes its steps.
@MainActor
@Observable
final class WalkthroughModel {
    private(set) var steps: [Step] = []
    private(set) var isRunning = false

    var passed: Int {
        steps.filter(\.passed).count
    }

    var sections: [String] {
        steps.reduce(into: [String]()) { names, step in
            if names.last != step.section {
                names.append(step.section)
            }
        }
    }

    func steps(in section: String) -> [Step] {
        steps.filter { $0.section == section }
    }

    func run() async {
        isRunning = true
        steps = await Self.walk()
        isRunning = false
    }

    private nonisolated static func walk() async -> [Step] {
        Walkthrough().run()
    }
}

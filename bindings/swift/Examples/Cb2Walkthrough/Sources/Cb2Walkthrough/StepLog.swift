import Cb2

/// Collects steps as the walkthrough runs them.
struct StepLog {
    private(set) var steps: [Step] = []

    mutating func record(_ section: String, _ title: String, detail: String, verdict: String, expected: String) {
        steps.append(
            Step(
                id: steps.count, section: section, title: title, detail: detail, verdict: verdict,
                expected: expected))
    }

    /// Runs a call that must succeed and records what it returned.
    mutating func accept(_ section: String, _ title: String, _ body: () throws(Cb2Error) -> String) {
        do throws(Cb2Error) {
            let detail = try body()
            record(section, title, detail: detail, verdict: Step.accepted, expected: Step.accepted)
        } catch {
            record(section, title, detail: error.description, verdict: error.name, expected: Step.accepted)
        }
    }

    /// Runs a call the library must refuse with `expected`.
    mutating func refuse(
        _ section: String,
        _ title: String,
        expected: Cb2Error,
        _ body: () throws(Cb2Error) -> Void
    ) {
        do throws(Cb2Error) {
            try body()
            record(section, title, detail: "the call was accepted", verdict: Step.accepted, expected: expected.name)
        } catch {
            record(section, title, detail: "refused as \(error.name)", verdict: error.name, expected: expected.name)
        }
    }
}

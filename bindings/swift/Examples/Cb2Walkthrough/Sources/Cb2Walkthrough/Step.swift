/// One step of the walkthrough: what was tried, what came back, and what
/// the library should have answered.
public struct Step: Identifiable, Hashable, Sendable {
    /// The verdict of a call that succeeded.
    public static let accepted = "accepted"

    /// The position of the step in the walkthrough.
    public let id: Int
    /// The section the step belongs to, such as `"cb2.local"`.
    public let section: String
    /// What the step does.
    public let title: String
    /// What came back: a token prefix, claims, or the refusal.
    public let detail: String
    /// ``accepted`` or the name of the refusal, such as `"expired"`.
    public let verdict: String
    /// The verdict the library should give.
    public let expected: String

    /// Whether the library answered as it should.
    public var passed: Bool {
        verdict == expected
    }

    /// Whether the step shows a refusal rather than an accepted call.
    public var isRefusal: Bool {
        expected != Self.accepted
    }
}

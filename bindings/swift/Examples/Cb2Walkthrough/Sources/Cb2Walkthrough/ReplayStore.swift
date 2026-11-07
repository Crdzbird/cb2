import Foundation

/// An in-memory replay store: accepts each id once. A server keeps ids
/// until the token or proof expires, in a store shared by every handler.
///
/// `@unchecked Sendable` because every access to the set goes through the
/// lock; the replay checks of `Rules` may run on any thread.
public final class ReplayStore: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: Set<String> = []

    /// An empty store.
    public init() {}

    /// Accepts an id the first time and refuses it after.
    public func accept(_ id: String) -> Bool {
        lock.withLock { seen.insert(id).inserted }
    }
}

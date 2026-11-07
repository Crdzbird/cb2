import Foundation
import TokenFixtures

var failures = 0
print("| format | token bytes | verifies | tampered copy refused |")
print("|---|---:|---|---|")
for entry in Formats.all {
    let format = try await entry.make()
    let token = try await format.issue()
    let verifies = (try? await format.verify(token)) != nil
    let tampered = String(token.dropLast(4)) + (token.hasSuffix("AAAA") ? "BBBB" : "AAAA")
    let refused = (try? await format.verify(tampered)) == nil
    if !verifies || !refused {
        failures += 1
    }
    print("| \(entry.name) | \(token.utf8.count) | \(verifies ? "yes" : "NO") | \(refused ? "yes" : "NO") |")
}
exit(failures == 0 ? 0 : 1)

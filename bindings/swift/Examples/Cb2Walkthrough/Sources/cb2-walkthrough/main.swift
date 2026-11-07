import Cb2
import Cb2Walkthrough
import Foundation

print("cb2 \(Library.version) (cb2.public: \(Library.hasPublic), kcb2.seal: \(Library.hasSeal))")
let steps = Walkthrough().run()
var section = ""
for step in steps {
    if step.section != section {
        section = step.section
        print("\n\(section)")
    }
    let mark = step.passed ? (step.isRefusal ? "refused" : "ok") : "FAILED"
    print("  [\(mark)] \(step.title): \(step.detail)")
}
let passed = steps.filter(\.passed).count
print("\n\(passed) of \(steps.count) steps answered as expected")
exit(passed == steps.count ? 0 : 1)

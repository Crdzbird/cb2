import Cb2Walkthrough
import SwiftUI

/// The walkthrough's steps, one list section per walkthrough section.
struct WalkthroughSections: View {
    let model: WalkthroughModel

    var body: some View {
        Section("Walkthrough") {
            if model.isRunning {
                ProgressView("Running")
            } else {
                Text("\(model.passed) of \(model.steps.count) steps answered as expected")
                    .font(.headline)
            }
        }
        ForEach(model.sections, id: \.self) { section in
            Section(section) {
                ForEach(model.steps(in: section)) { StepRow(step: $0) }
            }
        }
    }
}

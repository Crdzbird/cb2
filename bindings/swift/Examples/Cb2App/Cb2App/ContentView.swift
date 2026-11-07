import Cb2
import SwiftUI

/// The one screen: the build, the token playground and the walkthrough.
struct ContentView: View {
    @State private var walkthrough = WalkthroughModel()
    @State private var playground = TokenPlayground()

    var body: some View {
        NavigationStack {
            List {
                Section("Library") {
                    LabeledContent("Version", value: Library.version)
                    LabeledContent("cb2.public", value: Library.hasPublic ? "available" : "not in this build")
                    LabeledContent("kcb2.seal", value: Library.hasSeal ? "available" : "not in this build")
                }
                PlaygroundSection(playground: playground)
                WalkthroughSections(model: walkthrough)
            }
            .navigationTitle("cb2")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Run again") {
                        Task { await walkthrough.run() }
                    }
                    .disabled(walkthrough.isRunning)
                }
            }
            .task { await walkthrough.run() }
        }
    }
}

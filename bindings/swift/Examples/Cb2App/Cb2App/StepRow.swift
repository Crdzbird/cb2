import Cb2Walkthrough
import SwiftUI

/// One walkthrough step: an accepted call, an expected refusal, or a step
/// the library answered differently than it should have.
struct StepRow: View {
    let step: Step

    var body: some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(step.title)
                Text(step.detail)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
            }
        } icon: {
            Image(systemName: symbol)
                .foregroundStyle(tint)
        }
    }

    private var symbol: String {
        guard step.passed else {
            return "exclamationmark.triangle.fill"
        }
        return step.isRefusal ? "hand.raised.fill" : "checkmark.seal.fill"
    }

    private var tint: Color {
        guard step.passed else {
            return .red
        }
        return step.isRefusal ? .orange : .green
    }
}

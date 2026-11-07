import SwiftUI

/// Issue a token for a subject and audience, optionally tamper with it, and
/// see whether a verifier for the `api` audience accepts it.
struct PlaygroundSection: View {
    @Bindable var playground: TokenPlayground

    var body: some View {
        Section("Try a cb2.local token") {
            TextField("Subject", text: $playground.subject)
                .autocorrectionDisabled()
            Picker("Audience", selection: $playground.audience) {
                ForEach(TokenPlayground.audiences, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            Toggle("Tamper with the token", isOn: $playground.tamper)
            Button("Issue and open") { playground.issueAndOpen() }
            if !playground.token.isEmpty {
                Text(playground.token)
                    .font(.caption.monospaced())
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
            switch playground.outcome {
            case .accepted(let summary):
                Label("Accepted: \(summary)", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
            case .refused(let error):
                Label("Refused: \(error.name)", systemImage: "hand.raised.fill")
                    .foregroundStyle(.orange)
            case nil:
                EmptyView()
            }
        }
    }
}

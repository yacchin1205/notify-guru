import SwiftUI

struct MacJoinView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var link = ""
    @State private var joining = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Add Session")
                .font(.title2.weight(.semibold))
            Text("Paste the one-shot link shown by notifyg.")
                .foregroundStyle(.secondary)
            TextField("https://notify.guru/…#…", text: $link)
                .textFieldStyle(.roundedBorder)
                .onSubmit { beginJoin() }
            if let error = model.errorMessage {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Continue") { beginJoin() }
                    .buttonStyle(.borderedProminent)
                    .disabled(joining || link.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 480)
    }

    private func beginJoin() {
        guard !joining else { return }
        joining = true
        Task {
            if await model.join(link: link) {
                dismiss()
            }
            joining = false
        }
    }
}

import Observation
import SwiftUI

@MainActor
@Observable
final class ProfilesViewState {
    var showAddSheet = false
    var showImportSheet = false
    var draft = Profile()
    var importLinkText = ""
}

struct ProfilesView: View {
    @Bindable var bridge: CoreBridge
    @Bindable var ui: ProfilesViewState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Server Nodes")
                            .font(.title.bold())
                        Text("Compatible with SUDOKU-ASCII/sudoku servers & sudoku:// share links")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Import sudoku://") {
                        ui.importLinkText = ""
                        ui.showImportSheet = true
                    }
                    .buttonStyle(.bordered)

                    Button {
                        ui.draft = Profile()
                        ui.showAddSheet = true
                    } label: {
                        Label("Add Node", systemImage: "plus")
                    }
                    .buttonStyle(.borderedProminent)
                }

                if bridge.appState.profiles.isEmpty {
                    ContentUnavailableView(
                        "No Sudoku Nodes Yet",
                        systemImage: "server.rack",
                        description: Text("Add a Sudoku server, import a sudoku:// link, or click Quick Local Demo on the Dashboard.")
                    )
                    .padding(.top, 50)
                } else {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 14)], spacing: 14) {
                        ForEach(bridge.appState.profiles) { profile in
                            ProfileCard(
                                profile: profile,
                                isActive: profile.id == bridge.appState.activeProfileID,
                                isConnected: bridge.status.connected && bridge.status.activeProfile?.id == profile.id,
                                onConnect: { Task { await bridge.connect(profileID: profile.id) } },
                                onPing: { Task { await bridge.pingProfile(profile.id) } },
                                onShare: {
                                    Task {
                                        if let link = await bridge.exportLink(profile.id) {
                                            bridge.copyToClipboard(link)
                                        }
                                    }
                                },
                                onEdit: {
                                    ui.draft = profile
                                    ui.showAddSheet = true
                                },
                                onDelete: { Task { await bridge.deleteProfile(profile.id) } }
                            )
                        }
                    }
                }
            }
            .padding(22)
        }
        .sheet(isPresented: $ui.showAddSheet) {
            ProfileEditorSheet(ui: ui) { saved in
                Task { await bridge.saveProfile(saved) }
            }
        }
        .sheet(isPresented: $ui.showImportSheet) {
            VStack(alignment: .leading, spacing: 14) {
                Text("Import sudoku:// Short Link")
                    .font(.headline)
                TextEditor(text: $ui.importLinkText)
                    .font(.system(.body, design: .monospaced))
                    .frame(height: 110)
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.3)))
                HStack {
                    Spacer()
                    Button("Cancel") { ui.showImportSheet = false }
                    Button("Import") {
                        let txt = ui.importLinkText.trimmingCharacters(in: .whitespacesAndNewlines)
                        ui.showImportSheet = false
                        Task { await bridge.importLink(txt) }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(ui.importLinkText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .padding(20)
            .frame(width: 480)
        }
    }
}

struct ProfileCard: View {
    let profile: Profile
    let isActive: Bool
    let isConnected: Bool
    let onConnect: () -> Void
    let onPing: () -> Void
    let onShare: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(profile.name)
                        .font(.headline)
                    Text(profile.serverAddress)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if let ms = profile.lastLatencyMs, ms > 0 {
                    Text("\(ms) ms")
                        .font(.system(.caption, design: .monospaced).bold())
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color.green.opacity(0.16), in: Capsule())
                        .foregroundStyle(.green)
                }
            }

            HStack(spacing: 6) {
                TagPill(text: profile.ascii)
                TagPill(text: profile.aead)
                TagPill(text: profile.httpmask.disable ? "raw-tcp" : "http:\(profile.httpmask.mode)")
            }

            HStack(spacing: 6) {
                Button(isConnected ? "Reconnect" : "Connect", action: onConnect)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                Button("Ping", action: onPing)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                Button("Copy Link", action: onShare)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                Spacer()
                Button(action: onEdit) { Image(systemName: "pencil") }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                Button(role: .destructive, action: onDelete) { Image(systemName: "trash") }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
        }
        .padding(14)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(isActive ? Color.accentColor : Color.clear, lineWidth: 1.5)
        )
    }
}

struct ProfileEditorSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var ui: ProfilesViewState
    let onSave: (Profile) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(ui.draft.id.isEmpty ? "Add Sudoku Node" : "Edit Sudoku Node")
                .font(.title3.bold())

            Form {
                TextField("Node Name", text: $ui.draft.name)
                TextField("Server Address (host:port)", text: $ui.draft.serverAddress)
                TextField("Available Private Key / PSK", text: $ui.draft.key)
                Picker("Sudoku Mode", selection: $ui.draft.ascii) {
                    Text("prefer_entropy").tag("prefer_entropy")
                    Text("prefer_ascii").tag("prefer_ascii")
                    Text("up_ascii_down_entropy").tag("up_ascii_down_entropy")
                    Text("up_entropy_down_ascii").tag("up_entropy_down_ascii")
                }
                Picker("AEAD Cipher", selection: $ui.draft.aead) {
                    Text("chacha20-poly1305").tag("chacha20-poly1305")
                    Text("aes-128-gcm").tag("aes-128-gcm")
                    Text("none").tag("none")
                }
                Picker("HTTPMask Mode", selection: $ui.draft.httpmask.mode) {
                    Text("auto").tag("auto")
                    Text("ws").tag("ws")
                    Text("stream").tag("stream")
                    Text("poll").tag("poll")
                    Text("legacy").tag("legacy")
                }
                Toggle("Pure Sudoku Downlink", isOn: $ui.draft.enablePureDownlink)
                Toggle("HTTPMask TLS (HTTPS)", isOn: $ui.draft.httpmask.tls)
                Toggle("Disable HTTPMask (Raw TCP)", isOn: $ui.draft.httpmask.disable)
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save Node") {
                    onSave(ui.draft)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(ui.draft.serverAddress.isEmpty || ui.draft.key.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 480, height: 470)
    }
}

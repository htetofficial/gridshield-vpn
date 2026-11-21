import Observation
import SwiftUI

@MainActor
@Observable
final class ServerToolsUIState {
    var selectedTab = 0
    var serverDraft = ServerConfig()
    var loadedServer = false
    var pubKey = ""
    var availKey = ""
    var masterKey = ""
    var benchASCII = "prefer_ascii"
    var benchAEAD = "chacha20-poly1305"
    var benchHTTP = "auto"
    var benchOutput = "Ready to benchmark 512 KB end-to-end 4×4 Sudoku tunnel..."
    var benchRunning = false
}

struct ServerToolsView: View {
    @Bindable var bridge: CoreBridge
    @Bindable var ui: ServerToolsUIState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Server & Crypto Tools")
                        .font(.title.bold())
                    Text("Run a built-in wire-compatible Sudoku server, generate Ed25519 keys, or benchmark live wire obfuscation")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Picker("Tool Section", selection: $ui.selectedTab) {
                    Text("Built-in Server").tag(0)
                    Text("Ed25519 KeyGen").tag(1)
                    Text("Tunnel Self-Test").tag(2)
                }
                .pickerStyle(.segmented)
                .labelsHidden()

                switch ui.selectedTab {
                case 0:
                    serverSection
                case 1:
                    keygenSection
                default:
                    benchmarkSection
                }
            }
            .padding(22)
        }
        .onAppear {
            if !ui.loadedServer {
                ui.serverDraft = bridge.appState.server
                ui.loadedServer = true
            }
        }
    }

    private var serverSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(bridge.status.serverRunning
                         ? "Sudoku Server Running on \(bridge.status.serverAddr ?? ":\(ui.serverDraft.listenPort)")"
                         : "Sudoku Server Stopped")
                        .font(.headline)
                    Text(bridge.status.serverRunning
                         ? "Active clients: \(bridge.status.serverClients) · Total handled: \(bridge.status.serverHandled)"
                         : "Leave Master Public Key blank to auto-generate an Ed25519 key pair.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Start Server") {
                    Task {
                        if let started = await bridge.startServer(ui.serverDraft) {
                            ui.serverDraft = started
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(bridge.status.serverRunning)

                Button("Stop Server", role: .destructive) {
                    Task { await bridge.stopServer() }
                }
                .buttonStyle(.bordered)
                .disabled(!bridge.status.serverRunning)
            }

            Divider()

            Form {
                TextField("Listen Port", value: $ui.serverDraft.listenPort, format: .number)
                Picker("Sudoku Mode", selection: $ui.serverDraft.ascii) {
                    Text("prefer_entropy (Hamming ~3.0)").tag("prefer_entropy")
                    Text("prefer_ascii (>98% ASCII)").tag("prefer_ascii")
                    Text("up_ascii_down_entropy").tag("up_ascii_down_entropy")
                    Text("up_entropy_down_ascii").tag("up_entropy_down_ascii")
                }
                Picker("AEAD Cipher", selection: $ui.serverDraft.aead) {
                    Text("chacha20-poly1305").tag("chacha20-poly1305")
                    Text("aes-128-gcm").tag("aes-128-gcm")
                    Text("none").tag("none")
                }
                Picker("HTTPMask Mode", selection: $ui.serverDraft.httpmask.mode) {
                    Text("auto").tag("auto")
                    Text("ws").tag("ws")
                    Text("stream").tag("stream")
                    Text("poll").tag("poll")
                    Text("legacy").tag("legacy")
                }
                TextField("Master Public Key (auto if empty)", text: $ui.serverDraft.key)
                Toggle("Pure Sudoku Downlink", isOn: $ui.serverDraft.enablePureDownlink)
            }
            .formStyle(.grouped)

            if let ck = ui.serverDraft.clientKey, !ck.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("Generated Client Available Private Key")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Copy") { bridge.copyToClipboard(ck) }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                    }
                    Text(ck)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
        .padding(18)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    private var keygenSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Button("Generate New Ed25519 KeyPair") {
                    Task {
                        if let keys = await bridge.generateKeys() {
                            ui.pubKey = keys.masterPublicKey
                            ui.availKey = keys.availablePrivateKey
                            ui.masterKey = keys.masterPrivateKey
                            bridge.showToast("Generated Ed25519 Master + Split keys")
                        }
                    }
                }
                .buttonStyle(.borderedProminent)

                Button("Derive Additional Split Client Key") {
                    Task {
                        let base = ui.masterKey.isEmpty ? ui.availKey : ui.masterKey
                        guard !base.isEmpty else {
                            bridge.showToast("Generate a Master Key first", isError: true)
                            return
                        }
                        if let split = await bridge.splitKey(from: base) {
                            ui.availKey = split
                            bridge.showToast("Derived new split private key")
                        }
                    }
                }
                .buttonStyle(.bordered)
            }

            KeyFieldRow(label: "Master Public Key (Server)", value: ui.pubKey, onCopy: bridge.copyToClipboard)
            KeyFieldRow(label: "Available Private Key (Client)", value: ui.availKey, onCopy: bridge.copyToClipboard)
            KeyFieldRow(label: "Master Private Key (Secret)", value: ui.masterKey, onCopy: bridge.copyToClipboard)
        }
        .padding(18)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    private var benchmarkSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Picker("Sudoku", selection: $ui.benchASCII) {
                    Text("prefer_ascii").tag("prefer_ascii")
                    Text("prefer_entropy").tag("prefer_entropy")
                }
                Picker("AEAD", selection: $ui.benchAEAD) {
                    Text("chacha20-poly1305").tag("chacha20-poly1305")
                    Text("aes-128-gcm").tag("aes-128-gcm")
                }
                Picker("HTTPMask", selection: $ui.benchHTTP) {
                    Text("auto").tag("auto")
                    Text("ws").tag("ws")
                    Text("legacy").tag("legacy")
                    Text("none").tag("none")
                }
            }

            Button {
                ui.benchRunning = true
                ui.benchOutput = "Running 512 KB end-to-end encrypted Sudoku 4×4 tunnel test..."
                Task {
                    defer { ui.benchRunning = false }
                    if let res = await bridge.runSelfTest(ascii: ui.benchASCII, aead: ui.benchAEAD, httpMask: ui.benchHTTP) {
                        ui.benchOutput = """
                        STATUS:      \(res.ok ? "PASS" : "FAIL")
                        Handshake:   \(res.handshakeMs) ms (Ed25519 + X25519 PFS)
                        Verified:    \(formatBytes(Int64(res.bytesEchoed))) bit-for-bit
                        Throughput:  \(String(format: "%.1f Mbps", res.throughputMbps))
                        Protocol:    \(res.ascii) | \(res.aead) | httpmask:\(res.httpMaskMode)
                        Wire Sample: \(res.wireSample)
                        """
                    }
                }
            } label: {
                Label(ui.benchRunning ? "Running..." : "Run End-to-End Self-Test", systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .disabled(ui.benchRunning)

            Text(ui.benchOutput)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.black.opacity(0.82), in: RoundedRectangle(cornerRadius: 10))
                .foregroundStyle(Color(red: 0.85, green: 0.92, blue: 1.0))
        }
        .padding(18)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
    }
}

struct KeyFieldRow: View {
    let label: String
    let value: String
    let onCopy: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(label)
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)
                Spacer()
                if !value.isEmpty {
                    Button("Copy") { onCopy(value) }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                }
            }
            Text(value.isEmpty ? "—" : value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(9)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
        }
    }
}

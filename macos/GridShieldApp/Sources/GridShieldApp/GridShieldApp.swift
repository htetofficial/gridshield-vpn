import AppKit
import Observation
import SwiftUI

enum NavSection: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case profiles = "Nodes & Links"
    case server = "Server & Tools"
    case logs = "Traffic & Logs"

    var id: String { rawValue }
    var icon: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled"
        case .profiles: return "server.rack"
        case .server: return "cpu"
        case .logs: return "waveform.path.ecg"
        }
    }
}

@MainActor
@Observable
final class AppShellState {
    var selection: NavSection = .dashboard
    let profilesUI = ProfilesViewState()
    let serverUI = ServerToolsUIState()
}

final class AppLifecycleDelegate: NSObject, NSApplicationDelegate {
    var onTerminate: (() -> Void)?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        onTerminate?()
    }
}

@main
struct GridShieldVPNApp: App {
    @NSApplicationDelegateAdaptor(AppLifecycleDelegate.self) var appDelegate
    private let bridge = CoreBridge()
    private let shell = AppShellState()

    var body: some Scene {
        WindowGroup("GridShield VPN") {
            MainContentView(bridge: bridge, shell: shell)
                .frame(minWidth: 900, minHeight: 620)
                .onAppear {
                    appDelegate.onTerminate = {
                        bridge.shutdown()
                    }
                    bridge.start()
                }
        }
        .defaultSize(width: 1040, height: 680)

        MenuBarExtra {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Image(systemName: bridge.status.connected ? "checkmark.shield.fill" : "shield.slash")
                        .foregroundStyle(bridge.status.connected ? .green : .secondary)
                    Text(bridge.status.connected ? "Sudoku VPN Connected" : "Disconnected")
                        .font(.headline)
                }
                if let prof = bridge.status.activeProfile {
                    Text("\(prof.name) · \(prof.ascii)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text("↓ \(formatSpeed(bridge.status.traffic.downBps))   ↑ \(formatSpeed(bridge.status.traffic.upBps))")
                    .font(.system(.caption, design: .monospaced))
            }
            .padding(.vertical, 4)

            Divider()

            Button(bridge.status.connected ? "Disconnect" : "Connect") {
                Task { await bridge.toggleConnect() }
            }
            Button("⚡ Quick Local Demo") {
                Task { await bridge.startLocalDemo() }
            }

            Divider()

            Menu("Routing Mode: \(bridge.status.routingMode.uppercased())") {
                ForEach(["rule", "global", "direct"], id: \.self) { m in
                    Button(m.capitalized) {
                        Task { await bridge.setRoutingMode(m) }
                    }
                }
            }

            Toggle("OS System Proxy", isOn: Binding(
                get: { bridge.status.systemProxy.enabled },
                set: { val in Task { await bridge.toggleSysProxy(val) } }
            ))

            Divider()

            Button("Open Web Dashboard (127.0.0.1:9099)") {
                bridge.openWebDashboard()
            }
            Button("Quit GridShield VPN") {
                bridge.shutdown()
                NSApplication.shared.terminate(nil)
            }
        } label: {
            Image(systemName: bridge.status.connected ? "checkmark.shield.fill" : "shield")
        }
    }
}

struct MainContentView: View {
    @Bindable var bridge: CoreBridge
    @Bindable var shell: AppShellState

    var body: some View {
        NavigationSplitView {
            List(NavSection.allCases, selection: $shell.selection) { section in
                Label(section.rawValue, systemImage: section.icon)
                    .tag(section)
            }
            .listStyle(.sidebar)
            .safeAreaInset(edge: .top) {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 9)
                            .fill(Color.accentColor)
                            .frame(width: 34, height: 34)
                        Image(systemName: "square.grid.3x3.fill")
                            .foregroundStyle(.white)
                            .font(.system(size: 16, weight: .bold))
                    }
                    VStack(alignment: .leading, spacing: 1) {
                        Text("GridShield")
                            .font(.headline)
                        Text("Sudoku 4×4 VPN")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(.horizontal, 14)
                .padding(.top, 12)
                .padding(.bottom, 6)
            }
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 6) {
                    Divider()
                    HStack {
                        Circle()
                            .fill(bridge.coreReady ? Color.green : Color.orange)
                            .frame(width: 8, height: 8)
                        Text(bridge.coreReady ? "Go Core Online" : "Starting Core...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Button {
                        bridge.openWebDashboard()
                    } label: {
                        Label("Web Dashboard", systemImage: "globe")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                .padding(12)
            }
            .navigationSplitViewColumnWidth(min: 205, ideal: 225, max: 250)
        } detail: {
            ZStack(alignment: .bottomTrailing) {
                Group {
                    switch shell.selection {
                    case .dashboard:
                        DashboardView(bridge: bridge)
                    case .profiles:
                        ProfilesView(bridge: bridge, ui: shell.profilesUI)
                    case .server:
                        ServerToolsView(bridge: bridge, ui: shell.serverUI)
                    case .logs:
                        LogsView(bridge: bridge)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                if let toast = bridge.toastMessage {
                    Text(toast)
                        .font(.callout)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 9)
                        .background(.ultraThickMaterial, in: RoundedRectangle(cornerRadius: 10))
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(bridge.toastIsError ? Color.red : Color.accentColor, lineWidth: 1)
                        )
                        .padding(18)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
        }
    }
}

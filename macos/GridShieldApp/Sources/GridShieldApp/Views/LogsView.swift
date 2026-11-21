import SwiftUI

struct LogsView: View {
    @Bindable var bridge: CoreBridge

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Live Traffic & Logs")
                        .font(.title.bold())
                    Text("Active TCP/UDP-over-TCP streams and real-time Go engine telemetry")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Open Web Dashboard") {
                    bridge.openWebDashboard()
                }
                .buttonStyle(.bordered)
            }

            // Active Connections Table
            VStack(alignment: .leading, spacing: 8) {
                Text("Active Connections (\(bridge.connections.count))")
                    .font(.headline)

                if bridge.connections.isEmpty {
                    Text("No active connections right now.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 12)
                } else {
                    Table(bridge.connections) {
                        TableColumn("Target") { conn in
                            Text(conn.target)
                                .font(.system(.caption, design: .monospaced))
                        }
                        TableColumn("Proto") { conn in
                            Text(conn.network.uppercased())
                                .font(.caption.bold())
                        }
                        .width(56)
                        TableColumn("Route") { conn in
                            TagPill(text: conn.route)
                        }
                        .width(86)
                        TableColumn("Up") { conn in
                            Text(formatBytes(conn.upload))
                                .font(.system(.caption, design: .monospaced))
                        }
                        .width(80)
                        TableColumn("Down") { conn in
                            Text(formatBytes(conn.download))
                                .font(.system(.caption, design: .monospaced))
                        }
                        .width(80)
                        TableColumn("Close") { conn in
                            Button("Close", role: .destructive) {
                                Task { await bridge.closeConnection(conn.id) }
                            }
                            .controlSize(.mini)
                        }
                        .width(64)
                    }
                    .frame(minHeight: 160, maxHeight: 220)
                }
            }
            .padding(14)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))

            // Real-time Logs
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Engine Logs")
                        .font(.headline)
                    Spacer()
                    Button("Clear") { bridge.logs.removeAll() }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                }

                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 3) {
                            ForEach(bridge.logs) { entry in
                                HStack(alignment: .top, spacing: 8) {
                                    Text(formatLogTime(entry.ts))
                                        .foregroundStyle(Color.gray)
                                    Text(entry.level)
                                        .foregroundStyle(levelColor(entry.level))
                                        .fontWeight(.semibold)
                                        .frame(width: 44, alignment: .leading)
                                    Text("[\(entry.tag)]")
                                        .foregroundStyle(Color.purple.opacity(0.9))
                                    Text(entry.message)
                                        .foregroundStyle(Color(red: 0.86, green: 0.92, blue: 1.0))
                                        .textSelection(.enabled)
                                }
                                .font(.system(.caption, design: .monospaced))
                                .id(entry.id)
                            }
                        }
                        .padding(10)
                    }
                    .background(Color.black.opacity(0.84), in: RoundedRectangle(cornerRadius: 10))
                    .onChange(of: bridge.logs.last?.id) { _, newID in
                        if let id = newID {
                            proxy.scrollTo(id, anchor: .bottom)
                        }
                    }
                }
            }
            .padding(14)
            .frame(maxHeight: .infinity)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
        }
        .padding(22)
    }

    private func formatLogTime(_ ts: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ts))
        return date.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute().second())
    }

    private func levelColor(_ level: String) -> Color {
        switch level {
        case "ERROR": return .red
        case "WARN": return .yellow
        default: return .cyan
        }
    }
}

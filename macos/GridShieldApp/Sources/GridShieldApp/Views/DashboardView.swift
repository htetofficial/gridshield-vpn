import SwiftUI

struct DashboardView: View {
    @Bindable var bridge: CoreBridge

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Tunnel Overview")
                            .font(.title.bold())
                        Text("4×4 Sudoku O(1) Steganography + X25519 PFS + AEAD")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        Task { await bridge.startLocalDemo() }
                    } label: {
                        Label("Quick Local Demo", systemImage: "bolt.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(bridge.busy)
                }

                // Hero Power + Controls
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 16) {
                        HStack(spacing: 18) {
                            Button {
                                Task { await bridge.toggleConnect() }
                            } label: {
                                ZStack {
                                    Circle()
                                        .fill(bridge.status.connected ? Color.green.opacity(0.18) : Color.secondary.opacity(0.12))
                                        .frame(width: 104, height: 104)
                                    Circle()
                                        .stroke(bridge.status.connected ? Color.green : Color.accentColor, lineWidth: 3)
                                        .frame(width: 92, height: 92)
                                    VStack(spacing: 4) {
                                        Image(systemName: "power")
                                            .font(.system(size: 24, weight: .bold))
                                        Text(bridge.status.connected ? "STOP" : "START")
                                            .font(.caption.bold())
                                    }
                                    .foregroundStyle(bridge.status.connected ? Color.green : Color.primary)
                                }
                            }
                            .buttonStyle(.plain)
                            .disabled(bridge.busy)

                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(bridge.status.connected ? Color.green : Color.secondary)
                                        .frame(width: 9, height: 9)
                                    Text(bridge.status.connected ? "Protected · Sudoku Active" : "Disconnected")
                                        .font(.headline)
                                }
                                if let p = bridge.status.activeProfile ?? bridge.appState.profiles.first {
                                    Text("\(p.name)")
                                        .font(.subheadline.weight(.semibold))
                                    Text(p.serverAddress)
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                    HStack(spacing: 6) {
                                        TagPill(text: p.ascii)
                                        TagPill(text: p.aead)
                                        TagPill(text: p.httpmask.disable ? "raw-tcp" : "http:\(p.httpmask.mode)")
                                    }
                                } else {
                                    Text("No node configured — click Quick Local Demo or add a node.")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }

                        Divider()

                        VStack(alignment: .leading, spacing: 8) {
                            Text("Routing Mode")
                                .font(.subheadline.weight(.semibold))
                            Picker("Routing Mode", selection: Binding(
                                get: { bridge.status.routingMode },
                                set: { mode in Task { await bridge.setRoutingMode(mode) } }
                            )) {
                                Text("Rule").tag("rule")
                                Text("Global").tag("global")
                                Text("Direct").tag("direct")
                            }
                            .pickerStyle(.segmented)
                            .labelsHidden()
                        }

                        Toggle(isOn: Binding(
                            get: { bridge.status.systemProxy.enabled },
                            set: { val in Task { await bridge.toggleSysProxy(val) } }
                        )) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("OS System Proxy")
                                    .font(.subheadline.weight(.semibold))
                                Text(bridge.status.systemProxy.enabled
                                     ? "Active on \(bridge.status.mixedProxyAddr ?? "127.0.0.1:10808")"
                                     : "One-click SOCKS5 + HTTP (no root required)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)

                        Toggle(isOn: Binding(
                            get: { bridge.status.tun.enabled },
                            set: { val in Task { await bridge.toggleTUN(val) } }
                        )) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Full-Device TUN Mode (utun)")
                                    .font(.subheadline.weight(.semibold))
                                Text(bridge.status.tun.enabled
                                     ? "Active on \(bridge.status.tun.interfaceName ?? "utun") (\(bridge.status.tun.localIP ?? "198.18.0.1"))"
                                     : (bridge.status.isRoot ? "Ready (root active)" : "Run core with sudo for full-device TUN"))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)
                    }
                    .padding(18)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))

                    // Telemetry & Live Chart
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 12) {
                            MetricTile(
                                title: "Download",
                                value: formatSpeed(bridge.status.traffic.downBps),
                                sub: "Total: \(formatBytes(bridge.status.traffic.downTotal))",
                                color: .green
                            )
                            MetricTile(
                                title: "Upload",
                                value: formatSpeed(bridge.status.traffic.upBps),
                                sub: "Total: \(formatBytes(bridge.status.traffic.upTotal))",
                                color: .blue
                            )
                            MetricTile(
                                title: "Streams",
                                value: "\(bridge.status.activeConns)",
                                sub: bridge.status.mixedProxyAddr ?? "Idle",
                                color: .purple
                            )
                        }

                        LiveSpeedChart(samples: bridge.history)
                            .frame(height: 190)
                            .padding(10)
                            .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 12))
                    }
                    .padding(18)
                    .frame(maxWidth: .infinity)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
                }
            }
            .padding(22)
        }
    }
}

struct TagPill: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.system(.caption2, design: .monospaced).weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(Color.accentColor.opacity(0.14), in: Capsule())
            .foregroundStyle(Color.accentColor)
    }
}

struct MetricTile: View {
    let title: String
    let value: String
    let sub: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.title3, design: .monospaced).bold())
                .foregroundStyle(color)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
            Text(sub)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct LiveSpeedChart: View {
    let samples: [TrafficSample]

    var body: some View {
        Canvas { ctx, size in
            let pts = Array(samples.suffix(60))
            let maxBps = max(64 * 1024, pts.map { max($0.downBps, $0.upBps) }.max() ?? 0)

            // Horizontal guide lines
            for i in 1...3 {
                let y = size.height * CGFloat(i) / 4.0
                var grid = Path()
                grid.move(to: CGPoint(x: 0, y: y))
                grid.addLine(to: CGPoint(x: size.width, y: y))
                ctx.stroke(grid, with: .color(.secondary.opacity(0.2)), lineWidth: 1)
            }

            func drawSeries(_ values: [Int64], color: Color) {
                guard values.count >= 2 else { return }
                let step = size.width / 59.0
                let offset = CGFloat(60 - values.count) * step
                var line = Path()
                var fill = Path()
                for (idx, v) in values.enumerated() {
                    let x = offset + CGFloat(idx) * step
                    let ratio = CGFloat(v) / CGFloat(maxBps)
                    let y = size.height - 6 - ratio * (size.height - 20)
                    let pt = CGPoint(x: x, y: y)
                    if idx == 0 {
                        line.move(to: pt)
                        fill.move(to: CGPoint(x: x, y: size.height))
                        fill.addLine(to: pt)
                    } else {
                        line.addLine(to: pt)
                        fill.addLine(to: pt)
                    }
                }
                let lastX = offset + CGFloat(values.count - 1) * step
                fill.addLine(to: CGPoint(x: lastX, y: size.height))
                fill.closeSubpath()

                ctx.fill(fill, with: .color(color.opacity(0.15)))
                ctx.stroke(line, with: .color(color), lineWidth: 2)
            }

            drawSeries(pts.map(\.downBps), color: .green)
            drawSeries(pts.map(\.upBps), color: .blue)
        }
    }
}

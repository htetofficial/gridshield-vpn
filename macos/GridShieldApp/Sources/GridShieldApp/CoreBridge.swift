import AppKit
import Foundation
import Observation

@MainActor
@Observable
final class CoreBridge {
    let baseURL = URL(string: "http://127.0.0.1:9099")!

    var status = StatusSnapshot()
    var appState = AppState()
    var history: [TrafficSample] = []
    var connections: [ActiveConn] = []
    var logs: [LogEntry] = []

    var coreReady = false
    var busy = false
    var toastMessage: String? = nil
    var toastIsError = false

    private var daemonProcess: Process?
    private var sseTask: Task<Void, Never>?
    private var toastTask: Task<Void, Never>?

    func start() {
        Task {
            await ensureCoreRunning()
            await refreshAll()
            startSSELoop()
        }
    }

    func shutdown() {
        sseTask?.cancel()
        if let proc = daemonProcess, proc.isRunning {
            proc.interrupt()
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.6) {
                if proc.isRunning { proc.terminate() }
            }
        }
    }

    func showToast(_ message: String, isError: Bool = false) {
        toastMessage = message
        toastIsError = isError
        toastTask?.cancel()
        toastTask = Task {
            try? await Task.sleep(for: .seconds(4))
            if !Task.isCancelled {
                toastMessage = nil
            }
        }
    }

    private func ensureCoreRunning() async {
        if await pingAPI() {
            coreReady = true
            return
        }
        guard let corePath = locateCoreBinary() else {
            showToast("Core binary 'gridshield' not found. Build with 'make build-core'.", isError: true)
            return
        }
        let proc = Process()
        proc.executableURL = corePath
        proc.arguments = ["daemon", "--addr", "127.0.0.1:9099"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            daemonProcess = proc
            for _ in 0..<25 {
                try? await Task.sleep(for: .milliseconds(120))
                if await pingAPI() {
                    coreReady = true
                    return
                }
            }
            showToast("Core daemon started but API did not respond on :9099", isError: true)
        } catch {
            showToast("Failed to launch core daemon: \(error.localizedDescription)", isError: true)
        }
    }

    private func locateCoreBinary() -> URL? {
        let fm = FileManager.default
        var candidates: [URL] = []

        if let res = Bundle.main.resourceURL {
            candidates.append(res.appendingPathComponent("gridshield"))
        }
        let execDir = Bundle.main.executableURL?.deletingLastPathComponent()
        if let execDir {
            candidates.append(execDir.appendingPathComponent("gridshield"))
            candidates.append(execDir.appendingPathComponent("../Resources/gridshield").standardizedFileURL)
        }
        let cwd = URL(fileURLWithPath: fm.currentDirectoryPath)
        candidates.append(cwd.appendingPathComponent("dist/gridshield"))
        candidates.append(cwd.appendingPathComponent("../../dist/gridshield").standardizedFileURL)

        for url in candidates where fm.isExecutableFile(atPath: url.path) {
            return url
        }
        return nil
    }

    private func pingAPI() async -> Bool {
        var req = URLRequest(url: baseURL.appendingPathComponent("api/status"))
        req.timeoutInterval = 1.0
        do {
            let (_, resp) = try await URLSession.shared.data(for: req)
            return (resp as? HTTPURLResponse)?.statusCode == 200
        } catch {
            return false
        }
    }

    private func startSSELoop() {
        sseTask?.cancel()
        sseTask = Task {
            while !Task.isCancelled {
                do {
                    let req = URLRequest(url: baseURL.appendingPathComponent("api/events"))
                    let (bytes, resp) = try await URLSession.shared.bytes(for: req)
                    guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
                        try await Task.sleep(for: .seconds(1))
                        continue
                    }
                    coreReady = true
                    var currentEvent = ""
                    for try await line in bytes.lines {
                        if Task.isCancelled { break }
                        if line.hasPrefix("event:") {
                            currentEvent = line.dropFirst(6).trimmingCharacters(in: .whitespaces)
                        } else if line.hasPrefix("data:") {
                            let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                            handleSSE(event: currentEvent, data: payload)
                        }
                    }
                } catch {
                    if Task.isCancelled { break }
                    coreReady = false
                    try? await Task.sleep(for: .seconds(1))
                }
            }
        }
    }

    private func handleSSE(event: String, data: String) {
        guard let raw = data.data(using: .utf8) else { return }
        let dec = JSONDecoder()
        switch event {
        case "status":
            if let snap = try? dec.decode(StatusSnapshot.self, from: raw) {
                status = snap
                history.append(snap.traffic)
                if history.count > 60 {
                    history.removeFirst(history.count - 60)
                }
            }
        case "connections":
            if let list = try? dec.decode([ActiveConn].self, from: raw) {
                connections = list
            }
        case "log":
            if let entry = try? dec.decode(LogEntry.self, from: raw) {
                logs.append(entry)
                if logs.count > 250 {
                    logs.removeFirst(logs.count - 250)
                }
            }
        default:
            break
        }
    }

    // MARK: - Typed REST Helpers

    private func request<T: Decodable>(_ path: String, method: String = "GET", body: Data? = nil) async throws -> T {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 500
        if code >= 400 {
            if let apiErr = try? JSONDecoder().decode(APIErrorPayload.self, from: data) {
                throw NSError(domain: "GridShield", code: code, userInfo: [NSLocalizedDescriptionKey: apiErr.error])
            }
            throw NSError(domain: "GridShield", code: code, userInfo: [NSLocalizedDescriptionKey: "HTTP \(code)"])
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func requestVoid(_ path: String, method: String = "POST", body: Data? = nil) async throws {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 500
        if code >= 400 {
            if let apiErr = try? JSONDecoder().decode(APIErrorPayload.self, from: data) {
                throw NSError(domain: "GridShield", code: code, userInfo: [NSLocalizedDescriptionKey: apiErr.error])
            }
            throw NSError(domain: "GridShield", code: code, userInfo: [NSLocalizedDescriptionKey: "HTTP \(code)"])
        }
    }

    func refreshAll() async {
        do {
            async let st: StatusSnapshot = request("api/status")
            async let stateRes: AppState = request("api/state")
            async let hist: [TrafficSample] = request("api/traffic/history")
            async let recentLogs: [LogEntry] = request("api/logs")
            status = try await st
            appState = try await stateRes
            history = try await hist
            logs = try await recentLogs
            coreReady = true
        } catch {
            // Will retry via SSE
        }
    }

    func toggleConnect() async {
        busy = true
        defer { busy = false }
        do {
            if status.connected {
                status = try await request("api/disconnect", method: "POST")
                showToast("Disconnected")
            } else {
                let body = try JSONEncoder().encode(["profile_id": appState.activeProfileID])
                status = try await request("api/connect", method: "POST", body: body)
                showToast("Connected to Sudoku VPN")
            }
            await refreshAll()
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func connect(profileID: String) async {
        busy = true
        defer { busy = false }
        do {
            let body = try JSONEncoder().encode(["profile_id": profileID])
            status = try await request("api/connect", method: "POST", body: body)
            await refreshAll()
            showToast("Connected to \(status.activeProfile?.name ?? "Sudoku node")")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func startLocalDemo() async {
        busy = true
        defer { busy = false }
        struct DemoResp: Codable {
            var profile: Profile
            var status: StatusSnapshot
        }
        do {
            let res: DemoResp = try await request("api/demo", method: "POST")
            status = res.status
            await refreshAll()
            showToast("Local Sudoku Server + Client connected (\(res.profile.lastLatencyMs ?? 1) ms)!")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func setRoutingMode(_ mode: String) async {
        do {
            let body = try JSONEncoder().encode(["mode": mode])
            status = try await request("api/routing", method: "POST", body: body)
            showToast("Routing mode: \(mode.uppercased())")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func toggleSysProxy(_ enabled: Bool) async {
        do {
            let body = try JSONEncoder().encode(["enabled": enabled])
            status = try await request("api/sysproxy", method: "POST", body: body)
            showToast(enabled ? "OS System Proxy enabled" : "OS System Proxy disabled")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func toggleTUN(_ enabled: Bool) async {
        do {
            let body = try JSONEncoder().encode(["enabled": enabled])
            status = try await request("api/tun", method: "POST", body: body)
            showToast(enabled ? "Full-Device TUN active" : "TUN mode disabled")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func saveProfile(_ profile: Profile) async {
        do {
            let body = try JSONEncoder().encode(profile)
            let _: Profile = try await request("api/profiles", method: "POST", body: body)
            await refreshAll()
            showToast("Saved node \(profile.name)")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func deleteProfile(_ id: String) async {
        do {
            try await requestVoid("api/profiles/\(id)", method: "DELETE")
            await refreshAll()
            showToast("Deleted node")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func pingProfile(_ id: String) async {
        struct PingResp: Codable { var latency_ms: Int }
        do {
            let res: PingResp = try await request("api/profiles/\(id)/ping", method: "POST")
            await refreshAll()
            showToast("Handshake RTT: \(res.latency_ms) ms")
        } catch {
            showToast("Ping failed: \(error.localizedDescription)", isError: true)
        }
    }

    func importLink(_ link: String) async {
        do {
            let body = try JSONEncoder().encode(["link": link])
            let prof: Profile = try await request("api/profiles/import", method: "POST", body: body)
            await refreshAll()
            showToast("Imported \(prof.name)")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func exportLink(_ id: String) async -> String? {
        struct LinkResp: Codable { var link: String }
        do {
            let res: LinkResp = try await request("api/profiles/\(id)/link")
            return res.link
        } catch {
            showToast(error.localizedDescription, isError: true)
            return nil
        }
    }

    func generateKeys() async -> KeyBundle? {
        do {
            return try await request("api/keygen", method: "POST", body: Data("{}".utf8))
        } catch {
            showToast(error.localizedDescription, isError: true)
            return nil
        }
    }

    func splitKey(from masterOrSplit: String) async -> String? {
        struct SplitResp: Codable { var split_private_key: String }
        do {
            let body = try JSONEncoder().encode(["more": masterOrSplit])
            let res: SplitResp = try await request("api/keygen", method: "POST", body: body)
            return res.split_private_key
        } catch {
            showToast(error.localizedDescription, isError: true)
            return nil
        }
    }

    func startServer(_ cfg: ServerConfig) async -> ServerConfig? {
        struct StartResp: Codable {
            var server: ServerConfig
            var status: StatusSnapshot
        }
        do {
            let body = try JSONEncoder().encode(cfg)
            let res: StartResp = try await request("api/server/start", method: "POST", body: body)
            status = res.status
            await refreshAll()
            showToast("Sudoku Server listening on :\(res.server.listenPort)")
            return res.server
        } catch {
            showToast(error.localizedDescription, isError: true)
            return nil
        }
    }

    func stopServer() async {
        do {
            status = try await request("api/server/stop", method: "POST")
            showToast("Sudoku Server stopped")
        } catch {
            showToast(error.localizedDescription, isError: true)
        }
    }

    func runSelfTest(ascii: String, aead: String, httpMask: String) async -> SelfTestResult? {
        do {
            let body = try JSONEncoder().encode([
                "ascii": ascii,
                "aead": aead,
                "httpmask_mode": httpMask,
            ])
            return try await request("api/selftest", method: "POST", body: body)
        } catch {
            showToast(error.localizedDescription, isError: true)
            return nil
        }
    }

    func closeConnection(_ id: UInt64) async {
        try? await requestVoid("api/connections/\(id)", method: "DELETE")
    }

    func openWebDashboard() {
        NSWorkspace.shared.open(baseURL)
    }

    func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        showToast("Copied to clipboard")
    }
}

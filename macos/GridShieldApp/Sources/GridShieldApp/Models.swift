import Foundation

struct HTTPMaskConfig: Codable, Hashable, Sendable {
    var disable: Bool = false
    var mode: String = "auto"
    var tls: Bool = false
    var host: String? = nil
    var pathRoot: String? = nil

    enum CodingKeys: String, CodingKey {
        case disable, mode, tls, host
        case pathRoot = "path_root"
    }
}

struct Profile: Codable, Identifiable, Hashable, Sendable {
    var id: String = ""
    var name: String = ""
    var serverAddress: String = ""
    var key: String = ""
    var aead: String = "chacha20-poly1305"
    var ascii: String = "prefer_entropy"
    var paddingMin: Int = 5
    var paddingMax: Int = 15
    var enablePureDownlink: Bool = true
    var customTable: String? = nil
    var multiplex: String = "auto"
    var httpmask: HTTPMaskConfig = HTTPMaskConfig()
    var lastLatencyMs: Int? = nil

    enum CodingKeys: String, CodingKey {
        case id, name, key, aead, ascii, multiplex, httpmask
        case serverAddress = "server_address"
        case paddingMin = "padding_min"
        case paddingMax = "padding_max"
        case enablePureDownlink = "enable_pure_downlink"
        case customTable = "custom_table"
        case lastLatencyMs = "last_latency_ms"
    }
}

struct ServerConfig: Codable, Hashable, Sendable {
    var listenPort: Int = 8443
    var key: String = ""
    var masterPrivateKey: String? = nil
    var clientKey: String? = nil
    var aead: String = "chacha20-poly1305"
    var ascii: String = "prefer_entropy"
    var paddingMin: Int = 5
    var paddingMax: Int = 15
    var enablePureDownlink: Bool = true
    var suspiciousAction: String = "silent"
    var fallbackAddress: String? = nil
    var httpmask: HTTPMaskConfig = HTTPMaskConfig()

    enum CodingKeys: String, CodingKey {
        case key, aead, ascii, httpmask
        case listenPort = "listen_port"
        case masterPrivateKey = "master_private_key"
        case clientKey = "client_key"
        case paddingMin = "padding_min"
        case paddingMax = "padding_max"
        case enablePureDownlink = "enable_pure_downlink"
        case suspiciousAction = "suspicious_action"
        case fallbackAddress = "fallback_address"
    }
}

struct AppSettings: Codable, Hashable, Sendable {
    var mixedPort: Int = 10808
    var dashboardAddr: String = "127.0.0.1:9099"
    var routingMode: String = "rule"
    var autoSystemProxy: Bool = true
    var tunEnabled: Bool = false
    var tunInterface: String = ""
    var tunMTU: Int = 1500

    enum CodingKeys: String, CodingKey {
        case mixedPort = "mixed_port"
        case dashboardAddr = "dashboard_addr"
        case routingMode = "routing_mode"
        case autoSystemProxy = "auto_system_proxy"
        case tunEnabled = "tun_enabled"
        case tunInterface = "tun_interface"
        case tunMTU = "tun_mtu"
    }
}

struct AppState: Codable, Sendable {
    var activeProfileID: String = ""
    var profiles: [Profile] = []
    var settings: AppSettings = AppSettings()
    var server: ServerConfig = ServerConfig()

    enum CodingKeys: String, CodingKey {
        case profiles, settings, server
        case activeProfileID = "active_profile_id"
    }
}

struct SysProxyStatus: Codable, Sendable {
    var enabled: Bool = false
    var host: String? = nil
    var port: Int? = nil
    var services: [String]? = nil
}

struct TUNStatus: Codable, Sendable {
    var enabled: Bool = false
    var interfaceName: String? = nil
    var localIP: String? = nil
    var mtu: Int? = nil
    var error: String? = nil

    enum CodingKeys: String, CodingKey {
        case enabled, mtu, error
        case interfaceName = "interface"
        case localIP = "local_ip"
    }
}

struct TrafficSample: Codable, Identifiable, Sendable {
    var id: Int64 { ts }
    var ts: Int64 = 0
    var upBps: Int64 = 0
    var downBps: Int64 = 0
    var upTotal: Int64 = 0
    var downTotal: Int64 = 0

    enum CodingKeys: String, CodingKey {
        case ts
        case upBps = "up_bps"
        case downBps = "down_bps"
        case upTotal = "up_total"
        case downTotal = "down_total"
    }
}

struct StatusSnapshot: Codable, Sendable {
    var version: String = "1.0.0"
    var os: String = "darwin"
    var arch: String = "arm64"
    var isRoot: Bool = false
    var connected: Bool = false
    var connectedSince: Int64? = nil
    var activeProfile: Profile? = nil
    var mixedProxyAddr: String? = nil
    var routingMode: String = "rule"
    var systemProxy: SysProxyStatus = SysProxyStatus()
    var tun: TUNStatus = TUNStatus()
    var traffic: TrafficSample = TrafficSample()
    var activeConns: Int = 0
    var serverRunning: Bool = false
    var serverAddr: String? = nil
    var serverClients: Int64 = 0
    var serverHandled: Int64 = 0

    enum CodingKeys: String, CodingKey {
        case version, os, arch, connected, tun, traffic
        case isRoot = "is_root"
        case connectedSince = "connected_since"
        case activeProfile = "active_profile"
        case mixedProxyAddr = "mixed_proxy_addr"
        case routingMode = "routing_mode"
        case systemProxy = "system_proxy"
        case activeConns = "active_conns"
        case serverRunning = "server_running"
        case serverAddr = "server_addr"
        case serverClients = "server_clients"
        case serverHandled = "server_handled"
    }
}

struct ActiveConn: Codable, Identifiable, Sendable {
    var id: UInt64
    var network: String
    var target: String
    var route: String
    var source: String
    var startedAt: Int64
    var upload: Int64
    var download: Int64

    enum CodingKeys: String, CodingKey {
        case id, network, target, route, source, upload, download
        case startedAt = "started_at"
    }
}

struct LogEntry: Codable, Identifiable, Sendable {
    var id: UInt64
    var ts: Int64
    var level: String
    var tag: String
    var message: String
}

struct KeyBundle: Codable, Sendable {
    var availablePrivateKey: String
    var masterPrivateKey: String
    var masterPublicKey: String

    enum CodingKeys: String, CodingKey {
        case availablePrivateKey = "available_private_key"
        case masterPrivateKey = "master_private_key"
        case masterPublicKey = "master_public_key"
    }
}

struct SelfTestResult: Codable, Sendable {
    var ok: Bool
    var handshakeMs: Int
    var throughputMbps: Double
    var bytesEchoed: Int
    var wireSample: String
    var ascii: String
    var aead: String
    var httpMaskMode: String
    var error: String?

    enum CodingKeys: String, CodingKey {
        case ok, ascii, aead, error
        case handshakeMs = "handshake_ms"
        case throughputMbps = "throughput_mbps"
        case bytesEchoed = "bytes_echoed"
        case wireSample = "wire_sample"
        case httpMaskMode = "httpmask_mode"
    }
}

struct APIErrorPayload: Codable {
    var error: String
}

func formatBytes(_ bytes: Int64) -> String {
    guard bytes > 0 else { return "0 B" }
    let units = ["B", "KB", "MB", "GB", "TB"]
    var val = Double(bytes)
    var idx = 0
    while val >= 1024 && idx < units.count - 1 {
        val /= 1024
        idx += 1
    }
    if val < 10 && idx > 0 {
        return String(format: "%.2f %@", val, units[idx])
    }
    return String(format: "%.1f %@", val, units[idx])
}

func formatSpeed(_ bps: Int64) -> String {
    "\(formatBytes(bps))/s"
}

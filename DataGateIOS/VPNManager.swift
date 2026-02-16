//
//  VPNManager.swift
//  DataGateIOS
//

import Foundation
import NetworkExtension

/// Manages VPN connections using Network Extension framework
@MainActor
final class VPNManager {
    static let shared = VPNManager()
    
    private let vpnBundleIdentifier = "imkolganov.DataGateIOS.VPNExtension"
    
    private init() {}
    
    /// Current VPN connection status
    var connectionStatus: NEVPNStatus {
        get async {
            guard let manager = await loadVPNManager() else {
                return .invalid
            }
            return manager.connection.status
        }
    }
    
    /// Check if VPN is currently connected
    var isConnected: Bool {
        get async {
            let status = await connectionStatus
            return status == .connected
        }
    }
    
    /// Load or create VPN manager
    private func loadVPNManager() async -> NETunnelProviderManager? {
        let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
        // Find our VPN configuration by bundle identifier
        let ourManager = managers?.first { manager in
            if let protocolConfig = manager.protocolConfiguration as? NETunnelProviderProtocol {
                return protocolConfig.providerBundleIdentifier == vpnBundleIdentifier
            }
            return false
        }
        return ourManager ?? managers?.first { $0.protocolConfiguration?.serverAddress != nil }
    }
    
    /// Create and configure VPN manager with OpenVPN server configuration
    /// Uses certificate-based authentication (certificates are in .ovpn config file)
    func configureVPN(
        serverAddress: String,
        serverPort: Int,
        protocolType: String = "udp",
        ovpnConfigContent: String
    ) async throws {
        // Remove only OUR VPN configurations (DataGate VPN) to avoid duplicates
        // This does NOT remove other VPN apps' configurations
        let existingManagers = try? await NETunnelProviderManager.loadAllFromPreferences()
        if let managers = existingManagers, !managers.isEmpty {
            var removedCount = 0
            for manager in managers {
                let isOurConfig = manager.localizedDescription == "DataGate VPN" || 
                                 (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == vpnBundleIdentifier
                if isOurConfig {
                    try? await manager.removeFromPreferences()
                    removedCount += 1
                }
            }
            // Wait a bit for removal to complete
            if removedCount > 0 {
                try? await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
            }
        }
        
        // Create new manager
        let manager = NETunnelProviderManager()
        
        // Configure protocol
        let protocolConfig = NETunnelProviderProtocol()
        protocolConfig.providerBundleIdentifier = vpnBundleIdentifier
        protocolConfig.serverAddress = "\(serverAddress):\(serverPort)"
        // No username/password needed - certificates are in .ovpn file
        
        // Store OpenVPN config in provider configuration
        var providerConfig = [String: Any]()
        providerConfig["config"] = ovpnConfigContent  // Full .ovpn file content with certificates
        providerConfig["server"] = serverAddress
        providerConfig["port"] = serverPort
        providerConfig["protocol"] = protocolType
        
        protocolConfig.providerConfiguration = providerConfig
        
        manager.protocolConfiguration = protocolConfig
        manager.localizedDescription = "DataGate VPN"
        manager.isEnabled = true
        
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
    }
    
    /// Connect to VPN
    func connect() async throws {
        guard let manager = await loadVPNManager() else {
            throw VPNError.managerNotFound
        }
        
        if !manager.isEnabled {
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        }
        
        guard manager.isEnabled else {
            throw VPNError.notEnabled
        }
        
        do {
            // Verify Extension is installed before starting
            if let extensionURL = Bundle.main.builtInPlugInsURL?.appendingPathComponent("DataGateVPNExtension.appex"),
               !FileManager.default.fileExists(atPath: extensionURL.path) {
                throw VPNError.connectionFailed(NSError(domain: "VPNManager", code: -1, userInfo: [NSLocalizedDescriptionKey: "Extension not installed. Check Xcode scheme settings."]))
            }
            
            do {
                try manager.connection.startVPNTunnel(options: nil)
                try? await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
                
                if let session = manager.connection as? NETunnelProviderSession {
                    do {
                        let request = ["command": "getLogs"]
                        let requestData = try JSONSerialization.data(withJSONObject: request)
                        
                        // Use completion handler style (sendProviderMessage doesn't support async/await directly)
                        try session.sendProviderMessage(requestData) { _ in }
                    } catch {
                        // Extension might not be ready yet
                    }
                }
            } catch {
                throw VPNError.connectionFailed(error)
            }
            
            // Wait and check status multiple times, also check for Extension errors
            var extensionError: String? = nil
            for i in 1...10 {
                try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
                let status = manager.connection.status
                
                if i % 2 == 0, let session = manager.connection as? NETunnelProviderSession {
                    do {
                        let pingData = try JSONSerialization.data(withJSONObject: ["command": "ping"])
                        try session.sendProviderMessage(pingData) { _ in }
                    } catch { }
                    do {
                        let requestData = try JSONSerialization.data(withJSONObject: ["command": "getError"])
                        try session.sendProviderMessage(requestData) { responseData in
                            if let data = responseData,
                               let errorDict = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                               let errorDescription = errorDict["description"] as? String {
                                extensionError = errorDescription
                            }
                        }
                    } catch { }
                }
                
                if status == .connected {
                    extensionError = nil
                    break
                } else if status == .disconnected && i >= 3 {
                    // If disconnected after 3 seconds, check Extension for errors
                    if let session = manager.connection as? NETunnelProviderSession {
                        do {
                            let request = ["command": "getError"]
                            let requestData = try JSONSerialization.data(withJSONObject: request)
                            try session.sendProviderMessage(requestData) { responseData in
                                if let data = responseData,
                                   let errorDict = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                                   let errorDescription = errorDict["description"] as? String {
                                    extensionError = errorDescription
                                }
                            }
                        } catch { }
                    }
                    if extensionError != nil { break }
                } else if status == .invalid {
                    break
                }
            }
            
            // If we have an Extension error, throw it
            if let error = extensionError {
                throw VPNError.connectionFailed(NSError(domain: "PacketTunnelProvider", code: -1, userInfo: [NSLocalizedDescriptionKey: error]))
            }
        } catch {
            throw VPNError.connectionFailed(error)
        }
    }
    
    private func statusDescription(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "Invalid"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reasserting: return "Reasserting"
        case .disconnecting: return "Disconnecting"
        @unknown default: return "Unknown"
        }
    }
    
    /// Disconnect from VPN
    func disconnect() async throws {
        guard let manager = await loadVPNManager() else {
            throw VPNError.managerNotFound
        }
        
        manager.connection.stopVPNTunnel()
    }
    
    /// Remove VPN configuration
    func removeConfiguration() async throws {
        guard let manager = await loadVPNManager() else {
            return
        }
        
        manager.removeFromPreferences { _ in }
    }
    
    /// Get connection statistics
    func getStatistics() async -> VPNStatistics? {
        guard let manager = await loadVPNManager(),
              let session = manager.connection as? NETunnelProviderSession else {
            return nil
        }
        
        return await withCheckedContinuation { continuation in
            do {
                // Convert dictionary to Data
                let messageDict: [String: String] = ["command": "getStatistics"]
                let messageData = try JSONSerialization.data(withJSONObject: messageDict)
                
                try session.sendProviderMessage(messageData) { responseData in
                    guard let data = responseData else {
                        continuation.resume(returning: nil)
                        return
                    }
                    
                    guard let stats = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                        continuation.resume(returning: nil)
                        return
                    }
                    
                    let statistics = VPNStatistics(
                        bytesIn: stats["bytesIn"] as? Int64 ?? 0,
                        bytesOut: stats["bytesOut"] as? Int64 ?? 0,
                        connectedSince: stats["connectedSince"] as? Date
                    )
                    
                    continuation.resume(returning: statistics)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }
    
    /// Get logs from Extension (optionally only new logs after lastTimestamp)
    /// Returns: (logs, maxTimestamp, lastAppliedSettings) — lastAppliedSettings is set after tunnel connects (gateway, IP, DNS).
    func getExtensionLogs(since lastTimestamp: TimeInterval = 0) async -> ([String]?, TimeInterval, [String: String]?) {
        guard let manager = await loadVPNManager(),
              let session = manager.connection as? NETunnelProviderSession else {
            return (nil, lastTimestamp, nil)
        }
        
        return await withCheckedContinuation { continuation in
            do {
                let message = try JSONSerialization.data(withJSONObject: ["command": "getLogs"])
                try session.sendProviderMessage(message) { responseData in
                    guard let data = responseData,
                          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                        continuation.resume(returning: (nil, lastTimestamp, nil))
                        return
                    }
                    
                    let lastAppliedSettings = json["lastAppliedSettings"] as? [String: String]
                    var logs: [String] = []
                    var newLogs: [String] = [] // Only new logs
                    var maxTimestamp: TimeInterval = lastTimestamp
                    
                    // Get current logs
                    if let logEntries = json["logs"] as? [[String: Any]] {
                        for entry in logEntries {
                            if let timestamp = entry["timestamp"] as? TimeInterval,
                               let level = entry["level"] as? String,
                               let message = entry["message"] as? String,
                               Self.shouldShowLogMessage(message) {
                                let date = Date(timeIntervalSince1970: timestamp)
                                let formatter = DateFormatter()
                                formatter.dateFormat = "HH:mm:ss.SSS"
                                let logString = "[\(formatter.string(from: date))] [\(level)] \(message)"
                                
                                logs.append(logString)
                                
                                if timestamp > lastTimestamp {
                                    newLogs.append(logString)
                                }
                                
                                if timestamp > maxTimestamp {
                                    maxTimestamp = timestamp
                                }
                            }
                        }
                    }
                    
                    // Get saved logs (from UserDefaults) - merge with current logs, avoiding duplicates
                    if let savedLogs = json["savedLogs"] as? [[String: Any]] {
                        // Create set of existing log keys to avoid duplicates
                        var existingKeys = Set<String>()
                        for log in logs {
                            existingKeys.insert(log)
                        }
                        
                        for entry in savedLogs {
                            if let timestamp = entry["timestamp"] as? TimeInterval,
                               let level = entry["level"] as? String,
                               let message = entry["message"] as? String,
                               Self.shouldShowLogMessage(message) {
                                let date = Date(timeIntervalSince1970: timestamp)
                                let formatter = DateFormatter()
                                formatter.dateFormat = "HH:mm:ss.SSS"
                                let logString = "[\(formatter.string(from: date))] [\(level)] \(message)"
                                
                                if !existingKeys.contains(logString) {
                                    logs.append(logString)
                                    existingKeys.insert(logString)
                                    
                                    if timestamp > lastTimestamp {
                                        newLogs.append(logString)
                                    }
                                }
                                
                                if timestamp > maxTimestamp {
                                    maxTimestamp = timestamp
                                }
                            }
                        }
                    }
                    
                    // Sort logs by timestamp (extract from log string)
                    logs.sort { log1, log2 in
                        // Extract timestamp from log string format: "[HH:mm:ss.SSS] [LEVEL] message"
                        if let time1 = VPNManager.extractTime(from: log1), let time2 = VPNManager.extractTime(from: log2) {
                            return time1 < time2
                        }
                        return false
                    }
                    
                    // Sort new logs too
                    newLogs.sort { log1, log2 in
                        if let time1 = VPNManager.extractTime(from: log1), let time2 = VPNManager.extractTime(from: log2) {
                            return time1 < time2
                        }
                        return false
                    }
                    
                    // Return only new logs if lastTimestamp was provided, otherwise return all
                    let resultLogs = lastTimestamp > 0 ? newLogs : logs
                    continuation.resume(returning: (resultLogs.isEmpty ? nil : resultLogs, maxTimestamp, lastAppliedSettings))
                }
            } catch {
                continuation.resume(returning: (nil, lastTimestamp, nil))
            }
        }
    }
    
    /// Filter out certificate dumps and verbose debug from extension logs
    private static func shouldShowLogMessage(_ message: String) -> Bool {
        // Never show log lines that could contain certificate or key data (security)
        if message.contains("-----BEGIN ") || message.contains("-----END ") {
            return false
        }
        if message.contains("CERTIFICATE-----") || message.contains("PRIVATE KEY-----") {
            return false
        }
        // Skip noisy/debug substrings
        let skipSubstrings = [
            " (hex)", " (text)", " bytes DER", "Got DER buffer", "METHOD CALLED",
            "CLEANING CA", "CLEANING CERTIFICATE", "[load_ca]", "PEM marker search",
            "END marker at", "BEGIN marker at", "No bytes after END", "Verified: c_str()",
            "Memory check passed", "Attempting PEM", "About to call load_ca", "opt.cat(",
            "Received CA text", "Original length", "trailing bytes", "Parsing ca certificate",
            "Parsing cert certificate", "About to call c->parse", "About to call mbedtls_x509",
            "First 50 bytes", "Last 50 bytes", "First 100 bytes", "Base64 content",
            "DER starts with", "Security Framework validation result",
            "validateCertificateWithSecurityFramework returned", "Calling mbedtls_pem_read_buffer",
            "mbedtls_pem_read_buffer returned", "hex):", "text):", "mbedtls_x509_crt_parse",
            "CA cert full content", "CA section full content", "cert first 50", "cert length"
        ]
        for s in skipSubstrings {
            if message.contains(s) { return false }
        }
        return true
    }
    
    /// Extract time from log string format: "[HH:mm:ss.SSS] [LEVEL] message"
    private static func extractTime(from logString: String) -> String? {
        let pattern = #"\[(\d{2}:\d{2}:\d{2}\.\d{3})\]"#
        if let regex = try? NSRegularExpression(pattern: pattern),
           let match = regex.firstMatch(in: logString, range: NSRange(logString.startIndex..., in: logString)),
           let timeRange = Range(match.range(at: 1), in: logString) {
            return String(logString[timeRange])
        }
        return nil
    }
    
    /// Get error from Extension
    func getExtensionError() async -> String? {
        guard let manager = await loadVPNManager(),
              let session = manager.connection as? NETunnelProviderSession else {
            return nil
        }
        
        return await withCheckedContinuation { continuation in
            do {
                let messageDict: [String: String] = ["command": "getError"]
                let messageData = try JSONSerialization.data(withJSONObject: messageDict)
                
                try session.sendProviderMessage(messageData) { responseData in
                    guard let data = responseData,
                          let errorDict = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                          let description = errorDict["description"] as? String else {
                        continuation.resume(returning: nil)
                        return
                    }
                    
                    continuation.resume(returning: description)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }
}

// MARK: - Supporting Types

struct VPNStatistics {
    let bytesIn: Int64
    let bytesOut: Int64
    let connectedSince: Date?
}

enum VPNError: LocalizedError {
    case managerNotFound
    case notEnabled
    case connectionFailed(Error)
    case configurationFailed
    
    var errorDescription: String? {
        switch self {
        case .managerNotFound:
            return "VPN manager not found"
        case .notEnabled:
            return "VPN is not enabled"
        case .connectionFailed(let error):
            return "Connection failed: \(error.localizedDescription)"
        case .configurationFailed:
            return "Failed to configure VPN"
        }
    }
}

//
//  VPNConnectionViewModel.swift
//  DataGateIOS
//

import Foundation
import NetworkExtension

/// ViewModel for managing VPN connections in UI
@Observable
@MainActor
final class VPNConnectionViewModel {
    private let openVpnService = OpenVpnService.shared
    
    var connectionStatus: NEVPNStatus = .invalid
    var isConnecting = false
    var connectionError: String?
    var statistics: VPNStatistics?
    var extensionLogs: [String] = []
    var showLogs = false
    /// Last tunnel settings applied by extension (gateway, IP, DNS) — set after connect when logs are fetched.
    var lastAppliedTunnelSettings: String?
    private var lastLogTimestamp: TimeInterval = 0 // Track last loaded log timestamp
    
    /// Start observing VPN status changes
    func startObserving() {
        print("👀 [VPNViewModel] Starting to observe VPN status...")
        Task { @MainActor in
            await updateConnectionStatus()
            
            // Periodically check status
            while true {
                try? await Task.sleep(nanoseconds: 2_000_000_000) // Check every 2 seconds
                await updateConnectionStatus()
                
                // Refresh logs periodically if they are visible (only new logs)
                if showLogs {
                    await refreshLogs() // This will only fetch new logs
                }
            }
        }
    }
    
    /// Connect to VPN server using .ovpn config (certificate-based)
    func connect(
        server: OpenVpnServerDto,
        ovpnConfigContent: String
    ) async {
        isConnecting = true
        connectionError = nil
        extensionLogs = [] // Clear logs on new connection attempt
        lastAppliedTunnelSettings = nil
        lastLogTimestamp = 0 // Reset timestamp
        
        do {
            try await openVpnService.connectToServer(
                server,
                ovpnConfigContent: ovpnConfigContent
            )
            await updateConnectionStatus()
            
            // Fetch logs after connection attempt
            await loadAllLogs()
        } catch {
            connectionError = error.localizedDescription
            
            // Fetch logs on error
            await loadAllLogs()
        }
        
        isConnecting = false
    }
    
    /// Connect to VPN server - loads .ovpn config from API first
    func connectWithConfigLoad(
        server: OpenVpnServerDto,
        authToken: String,
        appState: AppState? = nil
    ) async {
        isConnecting = true
        connectionError = nil
        
        await withCheckedContinuation { continuation in
            openVpnService.getOVPNConfig(
                serverId: server.id,
                authToken: authToken,
                appState: appState
            ) { [weak self] result in
                Task { @MainActor in
                    switch result {
                    case .success(let configContent):
                        do {
                            try await self?.openVpnService.connectToServer(
                                server,
                                ovpnConfigContent: configContent
                            )
                            await self?.updateConnectionStatus()
                        } catch {
                            self?.connectionError = error.localizedDescription
                        }
                    case .failure(let error):
                        self?.connectionError = error.localizedDescription
                    }
                    self?.isConnecting = false
                    continuation.resume()
                }
            }
        }
    }
    
    /// Connect using test config from file (test-config.ovpn in app bundle)
    /// TODO: Remove after testing
    func connectWithTestConfig() async {
        print("🎯 [VPNViewModel] Connect button pressed")
        isConnecting = true
        connectionError = nil
        extensionLogs = [] // Clear logs on new connection attempt
        lastAppliedTunnelSettings = nil
        
        do {
            print("🔄 [VPNViewModel] Calling connectWithTestConfig...")
            try await openVpnService.connectWithTestConfig()
            
            print("⏳ [VPNViewModel] Waiting before status check...")
            try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
            
            await updateConnectionStatus()
            let status = connectionStatus
            print("📊 [VPNViewModel] Final status: \(status.rawValue)")
            
            // Always fetch logs after connection attempt (load all for first time)
            await loadAllLogs()
            
            if status == .connected {
                // Проверка доступности интернета через туннель — результат в лог
                await checkConnectivityAndLog()
            } else {
                print("⚠️ [VPNViewModel] Status is not connected: \(status.rawValue)")
                
                // Try to get error from Extension
                print("📋 [VPNViewModel] Attempting to get Extension error...")
                if let extensionError = await getExtensionError() {
                    print("❌ [VPNViewModel] Extension error retrieved: \(extensionError)")
                    connectionError = extensionError
                } else {
                    print("⚠️ [VPNViewModel] No Extension error available")
                    connectionError = "Connection failed. Status: \(statusDescription)"
                }
            }
        } catch {
            print("❌ [VPNViewModel] Error: \(error.localizedDescription)")
            connectionError = error.localizedDescription
            
            // Fetch logs on error (load all)
            print("📋 [VPNViewModel] Fetching logs after error...")
            await loadAllLogs()
            
            // Also try to get error from Extension for more details
            if let extensionError = await getExtensionError() {
                connectionError = "\(error.localizedDescription)\nExtension error: \(extensionError)"
            }
        }
        
        isConnecting = false
        print("🏁 [VPNViewModel] Connect process finished")
    }
    
    /// Проверка доступности интернета после коннекта (трафик через VPN). Результат — в консоль (Xcode).
    private func checkConnectivityAndLog() async {
        print("🌐 [Connectivity] Checking internet after VPN connect...")
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 12
        let session = URLSession(configuration: config)
        let urls = ["https://www.apple.com", "https://cloudflare.com"]
        for urlString in urls {
            guard let url = URL(string: urlString) else { continue }
            let start = CFAbsoluteTimeGetCurrent()
            var result = "FAIL"
            do {
                let (_, response) = try await session.data(from: url)
                if let http = response as? HTTPURLResponse, (200...399).contains(http.statusCode) {
                    result = "OK \(http.statusCode)"
                } else {
                    result = "unexpected response"
                }
            } catch {
                result = error.localizedDescription
            }
            let elapsed = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
            print("🌐 [Connectivity] \(urlString): \(result) (\(elapsed)ms)")
        }
        print("🌐 [Connectivity] Done.")
    }
    
    /// Get error from Extension via app message
    private func getExtensionError() async -> String? {
        return await openVpnService.getExtensionError()
    }
    
    /// Disconnect from VPN
    func disconnect() async {
        do {
            try await openVpnService.disconnect()
            await updateConnectionStatus()
        } catch {
            connectionError = error.localizedDescription
        }
    }
    
    /// Update connection status
    func updateConnectionStatus() async {
        let status = await openVpnService.getConnectionStatus()
        print("📡 [VPNViewModel] Status updated: \(status.rawValue)")
        connectionStatus = status
    }
    
    /// Update statistics
    func updateStatistics() async {
        statistics = await openVpnService.getStatistics()
    }
    
    /// Start periodic statistics updates
    func startStatisticsUpdates() {
        Task {
            while true {
                await updateStatistics()
                try? await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
            }
        }
    }
    
    /// Get status description
    var statusDescription: String {
        switch connectionStatus {
        case .invalid:
            return "Invalid"
        case .disconnected:
            return "Disconnected"
        case .connecting:
            return "Connecting..."
        case .connected:
            return "Connected"
        case .reasserting:
            return "Reconnecting..."
        case .disconnecting:
            return "Disconnecting..."
        @unknown default:
            return "Unknown"
        }
    }
    
    /// Check if VPN is connected
    var isConnected: Bool {
        connectionStatus == .connected
    }
    
    /// Refresh Extension logs (only new ones)
    func refreshLogs() async {
        print("🔄 [VPNViewModel] Refreshing Extension logs (since timestamp: \(lastLogTimestamp))...")
        let (newLogs, maxTimestamp, lastSettings) = await openVpnService.getExtensionLogs(since: lastLogTimestamp)
        
        if let settings = lastSettings, !settings.isEmpty {
            lastAppliedTunnelSettings = "Gateway: \(settings["tunnelRemote"] ?? "?"), IP: \(settings["IPv4"] ?? "?"), DNS: \(settings["dns"] ?? "?")"
        }
        if let logs = newLogs, !logs.isEmpty {
            // Append only new logs
            extensionLogs.append(contentsOf: logs)
            
            // Update last timestamp
            lastLogTimestamp = maxTimestamp
            
            // Keep only last 100 entries
            if extensionLogs.count > 100 {
                extensionLogs.removeFirst(extensionLogs.count - 100)
            }
            
            print("📋 [VPNViewModel] ✅ Added \(logs.count) new log entries, total: \(extensionLogs.count)")
        } else {
            print("📋 [VPNViewModel] No new logs available")
        }
    }
    
    
    /// Load all logs (reset and load everything)
    func loadAllLogs() async {
        lastLogTimestamp = 0 // Reset timestamp to load all
        let (logs, maxTimestamp, lastSettings) = await openVpnService.getExtensionLogs(since: 0)
        
        if let settings = lastSettings, !settings.isEmpty {
            lastAppliedTunnelSettings = "Gateway: \(settings["tunnelRemote"] ?? "?"), IP: \(settings["IPv4"] ?? "?"), DNS: \(settings["dns"] ?? "?")"
        } else {
            lastAppliedTunnelSettings = nil
        }
        if let logEntries = logs, !logEntries.isEmpty {
            extensionLogs = Array(logEntries.suffix(100))
            lastLogTimestamp = maxTimestamp
            
            print("📋 [VPNViewModel] ✅ Loaded all logs: \(logEntries.count) entries, extensionLogs.count = \(extensionLogs.count)")
            // Note: Logs are already printed to console by VPNManager
        } else {
            extensionLogs = []
            print("⚠️ [VPNViewModel] No logs available")
        }
    }
    
    /// Toggle logs visibility
    func toggleLogs() {
        showLogs.toggle()
    }
}

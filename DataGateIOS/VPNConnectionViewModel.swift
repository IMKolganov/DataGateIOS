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
    
    /// Connect using config from server: getBest → ensureAndDownloadDeviceFile (by CN) → connect with WSS.
    func connectWithServerConfig(appState: AppState) async {
        guard !isConnecting else { return }
        isConnecting = true
        connectionError = nil
        extensionLogs = []
        lastAppliedTunnelSettings = nil
        lastLogTimestamp = 0
        
        defer { isConnecting = false }
        
        guard let token = appState.bearerToken else {
            connectionError = "Not authorized"
            return
        }
        guard let externalId = appState.externalId, !externalId.isEmpty else {
            connectionError = "ExternalId is not available (missing in token)"
            return
        }
        let installationHash = InstallationIdManager.shared.installationHash()
        let issuedTo = "datagate ios user \(externalId) device \(installationHash)"
        print("[VPN] connectWithServerConfig: externalId=\(externalId), issuedTo=\(issuedTo)")
        
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            OpenVpnService.shared.getBest(authToken: token, appState: appState) { [weak self] result in
                Task { @MainActor in
                    switch result {
                    case .success(let best):
                        print("[VPN] getBest OK: serverId=\(best.serverId), name=\(best.name ?? "?")")
                        let commonName = InstallationIdManager.shared.fullInstallationId(serverId: best.serverId, googleUserId: externalId)
                        print("[VPN] ensureAndDownloadDeviceFile: vpnServerId=\(best.serverId), commonName=\(commonName)")
                        OpenVpnService.shared.ensureAndDownloadDeviceFile(
                            vpnServerId: best.serverId,
                            commonName: commonName,
                            externalId: externalId,
                            issuedTo: issuedTo,
                            authToken: token,
                            appState: appState
                        ) { [weak self] fileResult in
                            Task { @MainActor in
                                switch fileResult {
                                case .success(let downloaded):
                                    print("[VPN] ensureAndDownloadDeviceFile OK: fileName=\(downloaded.fileName), content size=\(downloaded.content.count) bytes")
                                    do {
                                        try await OpenVpnService.shared.connectWithDownloadedConfig(best: best, ovpnContent: downloaded.content)
                                        await self?.updateConnectionStatus()
                                        await self?.loadAllLogs()
                                        print("[VPN] connectWithDownloadedConfig completed without throw")
                                        // Keep showing "Connecting..." until tunnel reaches a terminal state or timeout
                                        let timeoutSeconds = 15
                                        for i in 0..<timeoutSeconds {
                                            try? await Task.sleep(nanoseconds: 1_000_000_000)
                                            await self?.updateConnectionStatus()
                                            if i % 2 == 1 { await self?.refreshLogs() }
                                            let status = await OpenVpnService.shared.getConnectionStatus()
                                            if status == .connected {
                                                print("[VPN] Tunnel connected")
                                                break
                                            }
                                            if status == .disconnected || status == .invalid {
                                                print("[VPN] Tunnel did not connect: status=\(status.rawValue)")
                                                if status == .disconnected {
                                                    self?.connectionError = "Connection failed or was disconnected"
                                                }
                                                break
                                            }
                                        }
                                        // If we exited the loop without connecting, show timeout or extension error
                                        if await OpenVpnService.shared.getConnectionStatus() != .connected {
                                            let extError = await self?.getExtensionError()
                                            self?.connectionError = extError ?? "Connection timed out. Try again or check extension logs."
                                            if extError != nil { await self?.loadAllLogs() }
                                        }
                                    } catch {
                                        print("[VPN] connectWithDownloadedConfig error: \(error)")
                                        self?.connectionError = error.localizedDescription
                                        await self?.loadAllLogs()
                                    }
                                case .failure(let error):
                                    print("[VPN] ensureAndDownloadDeviceFile failed: \(error)")
                                    self?.connectionError = error.localizedDescription
                                }
                                continuation.resume()
                            }
                        }
                    case .failure(let error):
                        print("[VPN] getBest failed: \(error)")
                        self?.connectionError = error.localizedDescription
                        continuation.resume()
                    }
                }
            }
        }
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
        connectionStatus = await openVpnService.getConnectionStatus()
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
        let (newLogs, maxTimestamp, lastSettings) = await openVpnService.getExtensionLogs(since: lastLogTimestamp)
        if let settings = lastSettings, !settings.isEmpty {
            lastAppliedTunnelSettings = "Gateway: \(settings["tunnelRemote"] ?? "?"), IP: \(settings["IPv4"] ?? "?"), DNS: \(settings["dns"] ?? "?")"
        }
        if let logs = newLogs, !logs.isEmpty {
            extensionLogs.append(contentsOf: logs)
            lastLogTimestamp = maxTimestamp
            if extensionLogs.count > 100 {
                extensionLogs.removeFirst(extensionLogs.count - 100)
            }
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
        } else {
            extensionLogs = []
        }
    }
    
    /// Toggle logs visibility
    func toggleLogs() {
        showLogs.toggle()
    }
}

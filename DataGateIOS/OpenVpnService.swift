//
//  OpenVpnService.swift
//  DataGateIOS
//

import Foundation
import NetworkExtension

final class OpenVpnService {
    static let shared = OpenVpnService()
    private let client = APIClient.shared
    private let vpnManager = VPNManager.shared

    private init() {}

    func getAllServersWithStatus(
        authToken: String,
        appState: AppState? = nil,
        completion: @escaping (Result<OpenVpnServerWithStatusesResponse, Error>) -> Void
    ) {
        // Ensure token is valid before making request
        if let appState = appState {
            appState.ensureValidToken { [weak self] isValid in
                guard isValid, let token = appState.bearerToken else {
                    completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid or expired token"])))
                    return
                }
                self?.performRequest(token: token, appState: appState, completion: completion)
            }
        } else {
            performRequest(token: authToken, appState: nil, completion: completion)
        }
    }
    
    private func performRequest(
        token: String,
        appState: AppState?,
        completion: @escaping (Result<OpenVpnServerWithStatusesResponse, Error>) -> Void
    ) {
        client.request(
            path: "/api/open-vpn-servers/get-all-with-status",
            method: "GET",
            body: nil as (any Encodable)?,
            authToken: token,
            completion: { [weak self] (result: Result<OpenVpnServerWithStatusesResponse, Error>) in
                switch result {
                case .success(let response):
                    completion(.success(response))
                case .failure(let error):
                    // If 401 and we have AppState, try to refresh and retry
                    if let nsError = error as NSError?,
                       nsError.code == 401,
                       let appState = appState {
                        appState.refreshAccessToken { success in
                            if success, let newToken = appState.bearerToken {
                                // Retry request with new token
                                self?.performRequest(token: newToken, appState: appState, completion: completion)
                            } else {
                                completion(.failure(error))
                            }
                        }
                    } else {
                        completion(.failure(error))
                    }
                }
            }
        )
    }
    
    // MARK: - VPN Connection Management
    
    /// Get OpenVPN configuration file (.ovpn) from server
    func getOVPNConfig(
        serverId: Int,
        authToken: String,
        appState: AppState? = nil,
        completion: @escaping (Result<String, Error>) -> Void
    ) {
        // Ensure token is valid before making request
        if let appState = appState {
            appState.ensureValidToken { [weak self] isValid in
                guard isValid, let token = appState.bearerToken else {
                    completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid or expired token"])))
                    return
                }
                self?.performConfigRequest(serverId: serverId, token: token, appState: appState, completion: completion)
            }
        } else {
            performConfigRequest(serverId: serverId, token: authToken, appState: nil, completion: completion)
        }
    }
    
    private func performConfigRequest(
        serverId: Int,
        token: String,
        appState: AppState?,
        completion: @escaping (Result<String, Error>) -> Void
    ) {
        // Get .ovpn config file as plain text
        // TODO: Update path to match your API endpoint
        // Example: /api/open-vpn-servers/{serverId}/config
        guard let url = URL(string: "/api/open-vpn-servers/\(serverId)/config", relativeTo: APIConfig.baseURL) else {
            completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("text/plain", forHTTPHeaderField: "Accept") // Accept .ovpn file as text
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }
            
            // Handle 401 Unauthorized
            if httpResponse.statusCode == 401, let appState = appState {
                Task { @MainActor in
                    appState.refreshAccessToken { success in
                        Task { @MainActor in
                            if success, let newToken = appState.bearerToken {
                                // Retry request with new token
                                self.performConfigRequest(serverId: serverId, token: newToken, appState: appState, completion: completion)
                            } else {
                                completion(.failure(NSError(domain: "OpenVpnService", code: 401, userInfo: [NSLocalizedDescriptionKey: "Unauthorized"])))
                            }
                        }
                    }
                }
                return
            }
            
            guard (200...299).contains(httpResponse.statusCode) else {
                let errorMsg = "HTTP \(httpResponse.statusCode)"
                completion(.failure(NSError(domain: "OpenVpnService", code: httpResponse.statusCode, userInfo: [NSLocalizedDescriptionKey: errorMsg])))
                return
            }
            
            guard let data = data,
                  let configContent = String(data: data, encoding: .utf8) else {
                completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to decode config"])))
                return
            }
            
            completion(.success(configContent))
        }.resume()
    }
    
    /// Connect to OpenVPN server using .ovpn config file (certificate-based)
    func connectToServer(
        _ server: OpenVpnServerDto,
        ovpnConfigContent: String
    ) async throws {
        // Extract server address and port from apiUrl or use defaults
        let serverAddress = extractServerAddress(from: server.apiUrl) ?? server.apiUrl
        let serverPort = extractServerPort(from: server.apiUrl) ?? 1194
        
        // Configure and connect VPN (no credentials needed - certificates in .ovpn file)
        try await vpnManager.configureVPN(
            serverAddress: serverAddress,
            serverPort: serverPort,
            protocolType: "udp",
            ovpnConfigContent: ovpnConfigContent
        )
        
        try await vpnManager.connect()
    }
    
    /// Connect using test config loaded from external file (test-config.ovpn in app bundle)
    func connectWithTestConfig() async throws {
        print("🧪 [OpenVpnService] Loading test config from file...")
        let loaded = try VPNTestConfig.loadTestConfig()
        print("🧪 [OpenVpnService] Using test config: \(loaded.serverAddress):\(loaded.serverPort) \(loaded.protocolType)")

        do {
            try await vpnManager.configureVPN(
                serverAddress: loaded.serverAddress,
                serverPort: loaded.serverPort,
                protocolType: loaded.protocolType,
                ovpnConfigContent: loaded.content
            )
            
            print("⏳ [OpenVpnService] Waiting before connect...")
            try await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
            
            try await vpnManager.connect()
            print("✅ [OpenVpnService] Connect command completed")
        } catch {
            print("❌ [OpenVpnService] Error: \(error.localizedDescription)")
            if let nsError = error as NSError? {
                print("   Domain: \(nsError.domain)")
                print("   Code: \(nsError.code)")
                print("   UserInfo: \(nsError.userInfo)")
            }
            throw error
        }
    }
    
    /// Disconnect from VPN
    func disconnect() async throws {
        try await vpnManager.disconnect()
    }
    
    /// Get current VPN connection status
    func getConnectionStatus() async -> NEVPNStatus {
        await vpnManager.connectionStatus
    }
    
    /// Check if VPN is connected
    func isConnected() async -> Bool {
        await vpnManager.isConnected
    }
    
    /// Get VPN connection statistics
    func getStatistics() async -> VPNStatistics? {
        await vpnManager.getStatistics()
    }
    
    /// Get logs from Extension
    func getExtensionLogs(since lastTimestamp: TimeInterval = 0) async -> ([String]?, TimeInterval) {
        await vpnManager.getExtensionLogs(since: lastTimestamp)
    }
    
    /// Get error from Extension
    func getExtensionError() async -> String? {
        await vpnManager.getExtensionError()
    }
    
    // MARK: - Helper Methods
    
    private func extractServerAddress(from urlString: String) -> String? {
        guard let url = URL(string: urlString),
              let host = url.host else {
            // Try to extract IP address or domain from string
            return urlString.components(separatedBy: ":").first
        }
        return host
    }
    
    private func extractServerPort(from urlString: String) -> Int? {
        guard let url = URL(string: urlString),
              let port = url.port else {
            // Try to extract port from string format like "server:port"
            let components = urlString.components(separatedBy: ":")
            if components.count > 1,
               let portString = components.last,
               let port = Int(portString) {
                return port
            }
            return nil
        }
        return port
    }
}

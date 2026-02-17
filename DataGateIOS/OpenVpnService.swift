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
    
    /// Picks best server locally from get-all-with-status: min countConnectedClients among online WSS servers (matches Android).
    func getBest(
        authToken: String,
        appState: AppState? = nil,
        completion: @escaping (Result<BestServerResult, Error>) -> Void
    ) {
        getAllServersWithStatus(authToken: authToken, appState: appState) { result in
            switch result {
            case .success(let response):
                let candidates = response.openVpnServerWithStatuses.compactMap { BestServerResult.from($0) }
                print("[VPN] getBest: \(candidates.count) WSS server(s), choosing by min countConnectedClients")
                if let best = candidates.min(by: { $0.countConnectedClients < $1.countConnectedClients }) {
                    print("[VPN] Best server selected: id=\(best.serverId), name=\(best.name ?? "?"), apiUrl=\(best.apiUrl ?? "?"), countConnectedClients=\(best.countConnectedClients)")
                    completion(.success(best))
                } else {
                    completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "No servers with WSS available. The app connects only to servers that have WSS (nginx) enabled. Enable WSS on at least one server in the backend."])))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    // MARK: - OVPN file by CN (matches Android: download-file-by-cn, add-with-token)
    
    private static let pathDownloadFileByCn = "/api/open-vpn-files/download-file-by-cn"
    private static let pathAddWithToken = "/api/open-vpn-files/add-with-token"
    
    /// Ensures device config exists: try download by CN; if missing, create via add-with-token then download again. Matches Android ensureAndDownloadDeviceFile.
    func ensureAndDownloadDeviceFile(
        vpnServerId: Int,
        commonName: String,
        externalId: String,
        issuedTo: String,
        authToken: String,
        appState: AppState? = nil,
        completion: @escaping (Result<OvpnDownloadResult, Error>) -> Void
    ) {
        func run(with token: String) {
            tryDownloadFileByCn(vpnServerId: vpnServerId, commonName: commonName, token: token) { [weak self] result in
                switch result {
                case .success(let optionalFile):
                    if let file = optionalFile {
                        print("[VPN] ensureAndDownloadDeviceFile: config found on first download")
                        completion(.success(file))
                        return
                    }
                    print("[VPN] ensureAndDownloadDeviceFile: config not found (404), creating via add-with-token...")
                    self?.createFileOnServer(vpnServerId: vpnServerId, commonName: commonName, externalId: externalId, issuedTo: issuedTo, token: token, appState: appState) { createResult in
                        switch createResult {
                        case .success:
                            print("[VPN] ensureAndDownloadDeviceFile: create OK, downloading again...")
                            self?.tryDownloadFileByCn(vpnServerId: vpnServerId, commonName: commonName, token: token) { secondResult in
                                switch secondResult {
                                case .success(let file?):
                                    print("[VPN] ensureAndDownloadDeviceFile: second download OK")
                                    completion(.success(file))
                                case .success(nil):
                                    print("[VPN] ensureAndDownloadDeviceFile: second download still 404")
                                    completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "File still not found after create"])))
                                case .failure(let err):
                                    completion(.failure(err))
                                }
                            }
                        case .failure(let err):
                            print("[VPN] ensureAndDownloadDeviceFile: create failed: \(err)")
                            completion(.failure(err))
                        }
                    }
                case .failure(let err):
                    completion(.failure(err))
                }
            }
        }
        if let appState = appState {
            appState.ensureValidToken { isValid in
                guard isValid, let token = appState.bearerToken else {
                    completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid or expired token"])))
                    return
                }
                run(with: token)
            }
        } else {
            run(with: authToken)
        }
    }
    
    /// POST download-file-by-cn. Success(nil) = file not found (404 or 400 "not found").
    private func tryDownloadFileByCn(
        vpnServerId: Int,
        commonName: String,
        token: String,
        completion: @escaping (Result<OvpnDownloadResult?, Error>) -> Void
    ) {
        struct Body: Encodable {
            let vpnServerId: Int
            let commonName: String
        }
        guard let url = URL(string: Self.pathDownloadFileByCn, relativeTo: APIConfig.baseURL) else {
            completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        do {
            request.httpBody = try JSONEncoder().encode(Body(vpnServerId: vpnServerId, commonName: commonName))
        } catch {
            completion(.failure(error))
            return
        }
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let http = response as? HTTPURLResponse else {
                completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }
            if http.statusCode == 404 {
                print("[VPN] tryDownloadFileByCn: HTTP 404 (file not found for this CN)")
                completion(.success(nil))
                return
            }
            if http.statusCode == 400, let data = data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let msg = (json["message"] as? String)?.lowercased(), msg.contains("not found") {
                completion(.success(nil))
                return
            }
            guard (200...299).contains(http.statusCode), let data = data else {
                print("[VPN] tryDownloadFileByCn: HTTP \(http.statusCode)")
                completion(.failure(NSError(domain: "OpenVpnService", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "Download failed: HTTP \(http.statusCode)"])))
                return
            }
            print("[VPN] tryDownloadFileByCn: HTTP 200, decoding config")
            let dataToDecode = data
            let contentType = http.value(forHTTPHeaderField: "Content-Type")
            Task { @MainActor in
                do {
                    let apiResp = try JSONDecoder().decode(ApiResponse<DownloadFileByCnData>.self, from: dataToDecode)
                    guard let payload = apiResp.data else {
                        completion(.success(nil))
                        return
                    }
                    guard let decoded = Data(base64Encoded: payload.content) else {
                        completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid base64 content"])))
                        return
                    }
                    let fileName = payload.issuedOvpn?.fileName ?? "client.ovpn"
                    completion(.success(OvpnDownloadResult(fileName: fileName, content: decoded, contentType: contentType)))
                } catch {
                    completion(.failure(error))
                }
            }
        }.resume()
    }
    
    private func createFileOnServer(
        vpnServerId: Int,
        commonName: String,
        externalId: String,
        issuedTo: String,
        token: String,
        appState: AppState?,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        struct Body: Encodable {
            let vpnServerId: Int
            let commonName: String
            let externalId: String
            let issuedTo: String
        }
        guard let url = URL(string: Self.pathAddWithToken, relativeTo: APIConfig.baseURL) else {
            completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        do {
            request.httpBody = try JSONEncoder().encode(Body(vpnServerId: vpnServerId, commonName: commonName, externalId: externalId, issuedTo: issuedTo))
        } catch {
            completion(.failure(error))
            return
        }
        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let http = response as? HTTPURLResponse else {
                completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }
            if http.statusCode == 401, let appState = appState {
                let service = self
                Task { @MainActor in
                    appState.refreshAccessToken { success in
                        Task { @MainActor in
                            guard success, let newToken = appState.bearerToken else {
                                completion(.failure(NSError(domain: "OpenVpnService", code: 401, userInfo: [NSLocalizedDescriptionKey: "Unauthorized"])))
                                return
                            }
                            service?.createFileOnServer(vpnServerId: vpnServerId, commonName: commonName, externalId: externalId, issuedTo: issuedTo, token: newToken, appState: appState, completion: completion)
                        }
                    }
                }
                return
            }
            guard (200...299).contains(http.statusCode) else {
                completion(.failure(NSError(domain: "OpenVpnService", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "Create failed: HTTP \(http.statusCode)"])))
                return
            }
            completion(.success(()))
        }.resume()
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
    
    /// Port for WSS bridge: TCP server in extension listens here; OpenVPN config uses remote 127.0.0.1 thisPort. Must match Android BRIDGE_PORT (41194).
    private static let wssBridgePort = 41194

    /// Connect using config obtained from server (getBest + ensureAndDownloadDeviceFile).
    /// Patches config for WSS (remote 127.0.0.1:bridgePort, proto tcp-client) and passes wssUrl to extension.
    func connectWithDownloadedConfig(best: BestServerResult, ovpnContent: Data) async throws {
        guard let apiUrl = best.apiUrl, !apiUrl.isEmpty else {
            print("[VPN] connectWithDownloadedConfig failed: best server has no apiUrl")
            throw NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Best server has no apiUrl"])
        }
        let wssUrl = httpsToWssProxy(apiUrl)
        print("[VPN] WSS proxy URL: \(wssUrl) (from apiUrl: \(apiUrl))")
        let configText = String(data: ovpnContent, encoding: .utf8) ?? ""
        let patchedConfig = forceWssConfig(original: configText)
        let bridgePort = Self.wssBridgePort
        print("[VPN] Config patched for WSS: remote 127.0.0.1:\(bridgePort), proto tcp-client. Config size: \(patchedConfig.count) chars")
        print("[VPN] Configuring VPN (extension) with wssUrl...")
        try await vpnManager.configureVPN(
            serverAddress: "127.0.0.1",
            serverPort: bridgePort,
            protocolType: "tcp-client",
            ovpnConfigContent: patchedConfig,
            wssUrl: wssUrl
        )
        print("[VPN] Starting VPN tunnel...")
        try await vpnManager.connect()
        print("[VPN] Tunnel start requested; check extension status for connection result")
    }
    
    /// Patch .ovpn for WSS: remote → 127.0.0.1:bridgePort, proto → tcp-client (matches Android forceWssConfig).
    /// Always writes "remote" and "proto tcp-client" at the top of the config (stripping any existing remote/proto from body).
    private func forceWssConfig(original: String) -> String {
        let bridgePort = Self.wssBridgePort
        let lines = original
            .replacingOccurrences(of: "\r\n", with: "\n")
            .components(separatedBy: "\n")
        var out: [String] = []
        for raw in lines {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let lower = line.lowercased()
            if lower.hasPrefix("remote ") || lower.hasPrefix("proto ") {
                continue
            }
            out.append(raw)
        }
        let header = [
            "remote 127.0.0.1 \(bridgePort)",
            "proto tcp-client"
        ]
        out.insert(contentsOf: header, at: 0)
        return out.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines) + "\n"
    }
    
    /// Build WSS URL for proxy: https://host → wss://host/api/proxy?mode=tcp (matches Android httpsToWssProxy).
    /// Server (OpenVpnProxyController) has two modes: tcp (default) and udp. We use TCP: OpenVPN proto tcp-client
    /// → local bridge 127.0.0.1:41194 → WebSocket binary stream → server HandleTcp. UDP mode uses different framing.
    private func httpsToWssProxy(_ apiUrl: String) -> String {
        guard let url = URL(string: apiUrl),
              let scheme = url.scheme?.lowercased(),
              let host = url.host else {
            return apiUrl
        }
        let wssScheme = (scheme == "https") ? "wss" : "ws"
        var comps = URLComponents()
        comps.scheme = wssScheme
        comps.host = host
        comps.port = url.port
        comps.path = "/api/proxy"
        comps.query = "mode=tcp"
        comps.fragment = nil
        return comps.string ?? "\(wssScheme)://\(host)/api/proxy?mode=tcp"
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
    func getExtensionLogs(since lastTimestamp: TimeInterval = 0) async -> ([String]?, TimeInterval, [String: String]?) {
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

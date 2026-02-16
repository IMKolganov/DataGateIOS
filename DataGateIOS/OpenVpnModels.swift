//
//  OpenVpnModels.swift
//  DataGateIOS
//

import Foundation

// MARK: - Response Models

struct OpenVpnServerWithStatusesResponse: Decodable {
    let openVpnServerWithStatuses: [OpenVpnServerWithStatusDto]
    
    enum CodingKeys: String, CodingKey {
        case openVpnServerWithStatuses
    }
}

struct OpenVpnServerWithStatusDto: Decodable {
    let openVpnServerResponses: OpenVpnServerResponse
    let openVpnServerStatusLogResponse: OpenVpnServerStatusLogResponse?
    let countConnectedClients: Int
    let countSessions: Int
    let totalBytesIn: Int64
    let totalBytesOut: Int64
    
    enum CodingKeys: String, CodingKey {
        case openVpnServerResponses
        case openVpnServerStatusLogResponse
        case countConnectedClients
        case countSessions
        case totalBytesIn
        case totalBytesOut
    }
}

struct OpenVpnServerResponse: Decodable {
    let openVpnServer: OpenVpnServerDto
    
    enum CodingKeys: String, CodingKey {
        case openVpnServer
    }
}

struct OpenVpnServerDto: Decodable {
    let id: Int
    let serverName: String
    /// Optional so decoding doesn't fail if backend omits; nil treated as false when picking best server.
    let isOnline: Bool?
    let isDefault: Bool
    let apiUrl: String
    let latitude: Double?
    let longitude: Double?
    /// Optional so decoding doesn't fail if backend omits or uses different key; nil treated as false when picking best server.
    let isEnableWss: Bool?
    let createDate: String
    let lastUpdate: String
    
    enum CodingKeys: String, CodingKey {
        case id
        case serverName
        case isOnline
        case isDefault
        case apiUrl
        case latitude
        case longitude
        case isEnableWss
        case createDate
        case lastUpdate
    }
    
    var createDateParsed: Date? {
        ISO8601DateFormatter().date(from: createDate)
    }
    
    var lastUpdateParsed: Date? {
        ISO8601DateFormatter().date(from: lastUpdate)
    }
}

/// Best server chosen locally from get-all-with-status (min countConnectedClients, online + WSS). Matches Android BestServerResult.
struct BestServerResult {
    let serverId: Int
    let name: String?
    let apiUrl: String?
    let countConnectedClients: Int
    let isDefault: Bool
    
    /// Build from a single server-with-status row. Only servers with isEnableWss == true are considered
    /// (servers without nginx/WSS cannot be used for WebSocket proxy).
    static func from(_ dto: OpenVpnServerWithStatusDto) -> BestServerResult? {
        let server = dto.openVpnServerResponses.openVpnServer
        guard server.isOnline == true, server.isEnableWss == true else { return nil }
        let name = server.serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        return BestServerResult(
            serverId: server.id,
            name: name.isEmpty ? "Server #\(server.id)" : name,
            apiUrl: server.apiUrl,
            countConnectedClients: max(0, dto.countConnectedClients),
            isDefault: server.isDefault
        )
    }
}

// MARK: - OVPN file (download by CN / add with token)

/// Response data for POST api/open-vpn-files/download-file-by-cn
struct DownloadFileByCnData: Decodable {
    let content: String  // base64
    let issuedOvpn: IssuedOvpn?
}

struct IssuedOvpn: Decodable {
    let fileName: String?
}

/// Result of ensureAndDownloadDeviceFile (matches Android OvpnDownloadResult).
struct OvpnDownloadResult {
    let fileName: String
    let content: Data
    let contentType: String?
}

struct OpenVpnServerStatusLogResponse: Decodable {
    let vpnServerId: Int
    let sessionId: String
    let upSince: String
    let serverLocalIp: String
    let serverRemoteIp: String
    let bytesIn: Int64
    let bytesOut: Int64
    let version: String
    
    enum CodingKeys: String, CodingKey {
        case vpnServerId
        case sessionId
        case upSince
        case serverLocalIp
        case serverRemoteIp
        case bytesIn
        case bytesOut
        case version
    }
    
    var upSinceParsed: Date? {
        ISO8601DateFormatter().date(from: upSince)
    }
    
    var sessionIdParsed: UUID? {
        UUID(uuidString: sessionId)
    }
}

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
    let isOnline: Bool
    let isDefault: Bool
    let apiUrl: String
    let latitude: Double?
    let longitude: Double?
    let isEnableWss: Bool
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

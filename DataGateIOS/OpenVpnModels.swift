//
//  OpenVpnModels.swift
//  DataGateIOS
//

import Foundation

// MARK: - Response Models

enum VpnServerType: Decodable, Equatable, Sendable {
    case openVpn, xray, unknown

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if let number = try? value.decode(Int.self) {
            self = number == 0 ? .openVpn : (number == 1 ? .xray : .unknown)
        } else if let text = try? value.decode(String.self) {
            switch text.lowercased() {
            case "openvpn", "open_vpn", "0": self = .openVpn
            case "xray", "1": self = .xray
            default: self = .unknown
            }
        } else {
            self = .unknown
        }
    }

    var filesBasePath: String {
        self == .xray ? "/api/xray-client-links" : "/api/open-vpn-files"
    }
}

struct OpenVpnServerWithStatusesResponse: Decodable {
    let openVpnServerWithStatuses: [OpenVpnServerWithStatusDto]
    
    enum CodingKeys: String, CodingKey {
        case openVpnServerWithStatuses
        case vpnServerWithStatuses
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        openVpnServerWithStatuses = try values.decodeIfPresent([OpenVpnServerWithStatusDto].self, forKey: .vpnServerWithStatuses)
            ?? values.decode([OpenVpnServerWithStatusDto].self, forKey: .openVpnServerWithStatuses)
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
        case vpnServerResponses
        case openVpnServerStatusLogResponse
        case vpnServerStatusLogResponse
        case countConnectedClients
        case countSessions
        case totalBytesIn
        case totalBytesOut
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        openVpnServerResponses = try values.decodeIfPresent(OpenVpnServerResponse.self, forKey: .vpnServerResponses)
            ?? values.decode(OpenVpnServerResponse.self, forKey: .openVpnServerResponses)
        openVpnServerStatusLogResponse = (try? values.decode(OpenVpnServerStatusLogResponse.self, forKey: .vpnServerStatusLogResponse))
            ?? (try? values.decode(OpenVpnServerStatusLogResponse.self, forKey: .openVpnServerStatusLogResponse))
        countConnectedClients = try values.decodeIfPresent(Int.self, forKey: .countConnectedClients) ?? 0
        countSessions = try values.decodeIfPresent(Int.self, forKey: .countSessions) ?? 0
        totalBytesIn = try values.decodeIfPresent(Int64.self, forKey: .totalBytesIn) ?? 0
        totalBytesOut = try values.decodeIfPresent(Int64.self, forKey: .totalBytesOut) ?? 0
    }
}

struct OpenVpnServerResponse: Decodable {
    let openVpnServer: OpenVpnServerDto
    
    enum CodingKeys: String, CodingKey {
        case openVpnServer
        case vpnServer
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        openVpnServer = try values.decodeIfPresent(OpenVpnServerDto.self, forKey: .vpnServer)
            ?? values.decode(OpenVpnServerDto.self, forKey: .openVpnServer)
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
    let serverType: VpnServerType
    let tags: [String]
    let isAccessibleForUserQuotaPlan: Bool
    let isDeleted: Bool
    let isDisabled: Bool
    
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
        case serverType, tags, isAccessibleForUserQuotaPlan, isDeleted, isDisabled
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(Int.self, forKey: .id)
        serverName = try values.decodeIfPresent(String.self, forKey: .serverName) ?? ""
        isOnline = try values.decodeIfPresent(Bool.self, forKey: .isOnline)
        isDefault = try values.decodeIfPresent(Bool.self, forKey: .isDefault) ?? false
        apiUrl = try values.decodeIfPresent(String.self, forKey: .apiUrl) ?? ""
        latitude = try values.decodeIfPresent(Double.self, forKey: .latitude)
        longitude = try values.decodeIfPresent(Double.self, forKey: .longitude)
        isEnableWss = try values.decodeIfPresent(Bool.self, forKey: .isEnableWss)
        createDate = try values.decodeIfPresent(String.self, forKey: .createDate) ?? ""
        lastUpdate = try values.decodeIfPresent(String.self, forKey: .lastUpdate) ?? ""
        serverType = try values.decodeIfPresent(VpnServerType.self, forKey: .serverType) ?? .openVpn
        tags = try values.decodeIfPresent([String].self, forKey: .tags) ?? []
        isAccessibleForUserQuotaPlan = try values.decodeIfPresent(Bool.self, forKey: .isAccessibleForUserQuotaPlan) ?? true
        isDeleted = try values.decodeIfPresent(Bool.self, forKey: .isDeleted) ?? false
        isDisabled = try values.decodeIfPresent(Bool.self, forKey: .isDisabled) ?? false
    }

    var listedLinkProtocol: String? {
        for tag in tags {
            let value = tag.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if value == "udp" || value == "tcp" { return value }
        }
        if let range = serverName.range(of: #"\b(udp|tcp)\b"#, options: [.regularExpression, .caseInsensitive]) {
            return String(serverName[range]).lowercased()
        }
        return nil
    }
    
    var createDateParsed: Date? {
        ISO8601DateFormatter().date(from: createDate)
    }
    
    var lastUpdateParsed: Date? {
        ISO8601DateFormatter().date(from: lastUpdate)
    }
}

/// Best online, quota-allowed server: Xray or OpenVPN TCP over WSS.
struct BestServerResult {
    let serverId: Int
    let name: String?
    let apiUrl: String?
    let countConnectedClients: Int
    let isDefault: Bool
    let serverType: VpnServerType
    
    /// UDP OpenVPN is not supported by this app's WSS bridge yet.
    static func from(_ dto: OpenVpnServerWithStatusDto) -> BestServerResult? {
        let server = dto.openVpnServerResponses.openVpnServer
        guard server.isOnline == true, server.isAccessibleForUserQuotaPlan,
              !server.isDeleted, !server.isDisabled else { return nil }
        switch server.serverType {
        case .xray: break
        case .openVpn:
            guard server.isEnableWss == true, server.listedLinkProtocol != "udp" else { return nil }
        case .unknown: return nil
        }
        let name = server.serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        return BestServerResult(
            serverId: server.id,
            name: name.isEmpty ? "Server #\(server.id)" : name,
            apiUrl: server.apiUrl,
            countConnectedClients: max(0, dto.countConnectedClients),
            isDefault: server.isDefault,
            serverType: server.serverType
        )
    }
}

// MARK: - OVPN file (download by CN / add with token)

/// Response data for POST api/open-vpn-files/download-file-by-cn. Sendable for use in URLSession completion (Swift 6).
struct DownloadFileByCnData: Decodable, Sendable {
    let content: String  // base64
    let issuedOvpn: IssuedOvpn?
    let issuedXray: IssuedOvpn?
    let fileName: String?
}

struct IssuedOvpn: Decodable, Sendable {
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

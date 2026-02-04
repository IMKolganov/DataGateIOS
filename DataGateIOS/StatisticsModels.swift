//
//  StatisticsModels.swift
//  DataGateIOS
//

import Foundation

// MARK: - Request Models

struct GetOverviewSeriesRequest {
    let from: Date
    let to: Date
    let grouping: GroupingType
    let vpnServerId: Int?
    let externalId: String?
    
    enum GroupingType: Int {
        case auto = 0
        case hours = 1
        case days = 2
        case months = 3
        case years = 4
        
        var queryValue: Int {
            return self.rawValue
        }
    }
}

// MARK: - Response Models

struct OverviewSeriesResponse: Decodable {
    let meta: OverviewMetaDto
    let summary: OverviewSummaryDto
    let overviewSeriesRows: [OverviewSeriesRowDto]
    
    enum CodingKeys: String, CodingKey {
        case meta
        case summary
        case overviewSeriesRows
    }
}

struct OverviewMetaDto: Decodable {
    let from: String
    let to: String
    let grouping: String
    let timezone: String
    let trafficUnit: String
    let vpnServerId: Int?
    
    enum CodingKeys: String, CodingKey {
        case from
        case to
        case grouping
        case timezone
        case trafficUnit
        case vpnServerId
    }
    
    var fromDate: Date? {
        ISO8601DateFormatter().date(from: from)
    }
    
    var toDate: Date? {
        ISO8601DateFormatter().date(from: to)
    }
}

struct OverviewSummaryDto: Decodable {
    let totalTrafficInBytes: Int64
    let totalTrafficOutBytes: Int64
    let peakActiveClients: Int
    
    enum CodingKeys: String, CodingKey {
        case totalTrafficInBytes
        case totalTrafficOutBytes
        case peakActiveClients
    }
}

struct OverviewSeriesRowDto: Decodable {
    let ts: String
    let activeClients: Int
    let trafficInBytes: Int64
    let trafficOutBytes: Int64
    let trafficTotalBytes: Int64
    
    enum CodingKeys: String, CodingKey {
        case ts
        case activeClients
        case trafficInBytes
        case trafficOutBytes
        case trafficTotalBytes
    }
    
    var timestamp: Date? {
        ISO8601DateFormatter().date(from: ts)
    }
}

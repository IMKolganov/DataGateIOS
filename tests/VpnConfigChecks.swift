import Foundation

@main
struct VpnConfigChecks {
    static func row(_ fields: [String: Any], legacy: Bool = false) throws -> OpenVpnServerWithStatusDto {
        let rootKey = legacy ? "openVpnServerWithStatuses" : "vpnServerWithStatuses"
        let responseKey = legacy ? "openVpnServerResponses" : "vpnServerResponses"
        let serverKey = legacy ? "openVpnServer" : "vpnServer"
        let object: [String: Any] = [rootKey: [[responseKey: [serverKey: fields], "countConnectedClients": 1]]]
        let data = try JSONSerialization.data(withJSONObject: object)
        return try JSONDecoder().decode(OpenVpnServerWithStatusesResponse.self, from: data).openVpnServerWithStatuses[0]
    }

    static func main() throws {
        let allowedXray: [String: Any] = ["id": 7, "serverType": 1, "isOnline": true, "isAccessibleForUserQuotaPlan": true]
        let best = BestServerResult.from(try row(allowedXray))!
        precondition(best.serverType == .xray)
        precondition(best.serverType.filesBasePath == "/api/xray-client-links")

        for (key, value) in [("isAccessibleForUserQuotaPlan", false), ("isOnline", false), ("isDeleted", true), ("isDisabled", true)] {
            var blocked = allowedXray
            blocked[key] = value
            let blockedRow = try row(blocked)
            precondition(BestServerResult.from(blockedRow) == nil, "must reject \(key)=\(value)")
        }
        var unknown = allowedXray
        unknown["serverType"] = 99
        let unknownRow = try row(unknown)
        precondition(BestServerResult.from(unknownRow) == nil)

        let legacy: [String: Any] = ["id": 1, "isOnline": true, "isEnableWss": true]
        let legacyBest = BestServerResult.from(try row(legacy, legacy: true))!
        precondition(legacyBest.serverType == .openVpn)
        precondition(legacyBest.serverType.filesBasePath == "/api/open-vpn-files")
        var udp = legacy
        udp["tags"] = ["udp"]
        let udpRow = try row(udp)
        precondition(BestServerResult.from(udpRow) == nil)
        udp.removeValue(forKey: "tags")
        udp["serverName"] = "OpenVPN Server (UDP)"
        let udpNameRow = try row(udp)
        precondition(BestServerResult.from(udpNameRow) == nil)
        var direct = legacy
        direct["isEnableWss"] = false
        let directRow = try row(direct)
        precondition(BestServerResult.from(directRow) == nil)

        let uri = "vless://11111111-1111-1111-1111-111111111111@vpn.example:8443?security=tls&type=xhttp#DataGate"
        let json = String(data: try JSONSerialization.data(withJSONObject: ["vless": uri]), encoding: .utf8)!
        for content in [uri, json, Data(json.utf8).base64EncodedString()] {
            let profile = try XrayClientProfile(content: content)
            precondition(profile.shareLink == uri)
            precondition(profile.providerConfiguration["transportMode"] as? String == "xray")
            precondition(profile.providerConfiguration["xrayShareLink"] as? String == uri)
            precondition(profile.providerConfiguration["server"] as? String == "vpn.example")
            precondition(profile.providerConfiguration["port"] as? Int == 8443)
        }
        for bad in ["", "https://vpn.example", "vless://@vpn.example:443", "vless://user@vpn.example:0"] {
            do {
                _ = try XrayClientProfile(content: bad)
                preconditionFailure("accepted invalid profile: \(bad)")
            } catch XrayClientProfile.ProfileError.invalidShareLink { }
        }

        let download = try JSONSerialization.data(withJSONObject: ["content": Data(json.utf8).base64EncodedString(), "issuedXray": ["fileName": "client.json"]])
        let decoded = try JSONDecoder().decode(DownloadFileByCnData.self, from: download)
        precondition(decoded.issuedXray?.fileName == "client.json")
        precondition(Data(base64Encoded: decoded.content) == Data(json.utf8))
        print("PASS: iOS VPN configuration (v3/legacy, quota, supported transports, VLESS provider keys)")
    }
}

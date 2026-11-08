import Foundation

/// Backend Xray client-link payload → the exact keys consumed by PacketTunnelProvider.
struct XrayClientProfile: Sendable {
    enum ProfileError: LocalizedError {
        case invalidShareLink

        var errorDescription: String? { "The server returned an invalid VLESS client profile." }
    }

    let shareLink: String
    let host: String
    let port: Int

    init(content: String) throws {
        guard let link = Self.extractShareLink(content),
              let url = URLComponents(string: link),
              url.scheme?.lowercased() == "vless",
              let host = url.host, !host.isEmpty,
              let user = url.user, !user.isEmpty else {
            throw ProfileError.invalidShareLink
        }
        let port = url.port ?? 443
        guard (1...65535).contains(port) else { throw ProfileError.invalidShareLink }
        self.shareLink = link
        self.host = host
        self.port = port
    }

    var providerConfiguration: [String: Any] {
        ["transportMode": "xray", "server": host, "port": port, "xrayShareLink": shareLink]
    }

    private static func extractShareLink(_ content: String, allowBase64: Bool = true) -> String? {
        let text = content.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.lowercased().hasPrefix("vless://") { return text }
        if let data = text.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            for key in ["vless", "Vless", "vlessXhttp", "VlessXhttp"] {
                if let link = json[key] as? String,
                   let result = extractShareLink(link, allowBase64: false) { return result }
            }
        }
        if allowBase64, let data = Data(base64Encoded: text),
           let decoded = String(data: data, encoding: .utf8) {
            return extractShareLink(decoded, allowBase64: false)
        }
        return nil
    }
}

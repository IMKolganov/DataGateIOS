//
//  JWTDecoder.swift
//  DataGateIOS
//

import Foundation

final class JWTDecoder {
    static func decode(jwt: String) -> [String: Any]? {
        let segments = jwt.components(separatedBy: ".")
        guard segments.count == 3 else { return nil }
        
        var base64String = segments[1]
        
        // Add padding if needed
        let remainder = base64String.count % 4
        if remainder > 0 {
            base64String = base64String.padding(toLength: base64String.count + 4 - remainder, withPad: "=", startingAt: 0)
        }
        
        // Replace URL-safe characters
        base64String = base64String.replacingOccurrences(of: "-", with: "+")
        base64String = base64String.replacingOccurrences(of: "_", with: "/")
        
        guard let data = Data(base64Encoded: base64String),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        
        return json
    }
    
    /// External ID for CN / API: from JWT claim "externalId" or "sub" (Google subject), same as Android JwtClaims.
    static func getExternalId(from jwt: String) -> String? {
        guard let payload = decode(jwt: jwt) else { return nil }
        let a = (payload["externalId"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let b = (payload["sub"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        return a.flatMap { $0.isEmpty ? nil : $0 } ?? b.flatMap { $0.isEmpty ? nil : $0 }
    }
}

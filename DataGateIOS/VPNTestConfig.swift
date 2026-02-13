//
//  VPNTestConfig.swift
//  DataGateIOS
//
//  Loads OpenVPN test config from external file (test-config.ovpn).
//  Add test-config.ovpn to the app target in Xcode; the file is in .gitignore.
//

import Foundation

/// Name of the OVPN config file in the app bundle (without extension).
private let testConfigFileName = "test-config"

struct VPNTestConfig {
    /// Result of loading test config from file
    struct LoadedConfig {
        let content: String
        let serverAddress: String
        let serverPort: Int
        let protocolType: String
    }

    /// Load OpenVPN config from external file (test-config.ovpn in app bundle).
    /// Add test-config.ovpn to the DataGateIOS target in Xcode.
    /// - Returns: Loaded config and parsed server/port/protocol
    /// - Throws: If file is missing or cannot be read/parsed
    static func loadTestConfig() throws -> LoadedConfig {
        guard let url = Bundle.main.url(forResource: testConfigFileName, withExtension: "ovpn") else {
            throw VPNTestConfigError.fileNotFound
        }
        let content: String
        do {
            content = try String(contentsOf: url, encoding: .utf8)
        } catch {
            throw VPNTestConfigError.readFailed(error)
        }
        guard !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw VPNTestConfigError.emptyFile
        }
        let (address, port, proto) = parseRemote(from: content)
        return LoadedConfig(
            content: content,
            serverAddress: address,
            serverPort: port,
            protocolType: proto
        )
    }

    /// Parse first "remote host port [proto]" line from .ovpn content
    private static func parseRemote(from content: String) -> (address: String, port: Int, protocol: String) {
        let lines = content.components(separatedBy: .newlines)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("remote ") {
                let parts = trimmed.dropFirst(7).split(separator: " ", omittingEmptySubsequences: true)
                if parts.count >= 2 {
                    let address = String(parts[0])
                    let port = Int(parts[1]) ?? 1194
                    let proto = parts.count >= 3 ? String(parts[2]) : "udp"
                    return (address, port, proto)
                }
            }
        }
        return ("127.0.0.1", 1194, "udp")
    }
}

enum VPNTestConfigError: LocalizedError {
    case fileNotFound
    case readFailed(Error)
    case emptyFile

    var errorDescription: String? {
        switch self {
        case .fileNotFound:
            return "Test config file not found. Add test-config.ovpn to the DataGateIOS target in Xcode."
        case .readFailed(let error):
            return "Failed to read test-config.ovpn: \(error.localizedDescription)"
        case .emptyFile:
            return "test-config.ovpn is empty."
        }
    }
}

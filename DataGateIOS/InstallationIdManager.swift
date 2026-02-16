//
//  InstallationIdManager.swift
//  DataGateIOS
//
//  Generates and stores a per-installation hash. Used to build full installation ID
//  in format: idg-<serverId>-<googleUserId>-<installationHash> (e.g. for CN).
//

import Foundation
import Security
import CryptoKit

final class InstallationIdManager {
    static let shared = InstallationIdManager()
    
    private let keychainService = "imkolganov.DataGateIOS"
    private let installationHashKey = "installationHash"
    
    private init() {}
    
    /// Persistent hash for this app installation (stored in Keychain, generated once).
    /// Safe for use in identifiers (e.g. CN). Example: "I_jm2_quxRey85ip75NyTl"
    func installationHash() -> String {
        if let existing = getStoredHash() {
            return existing
        }
        let newHash = generateAndStoreHash()
        return newHash
    }
    
    /// Full installation ID: idg-<serverId>-<googleUserId>-<installationHash>
    /// - Parameters:
    ///   - serverId: Best server id (e.g. from getBest).
    ///   - googleUserId: Google user id string (from backend or backend userId as string).
    func fullInstallationId(serverId: Int, googleUserId: String) -> String {
        let hash = installationHash()
        return "idg-\(serverId)-\(googleUserId)-\(hash)"
    }
    
    // MARK: - Private
    
    private func getStoredHash() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: installationHashKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8),
              !value.isEmpty else {
            return nil
        }
        return value
    }
    
    private func generateAndStoreHash() -> String {
        let seed = "\(UUID().uuidString)-\(Bundle.main.bundleIdentifier ?? "")-\(Date().timeIntervalSince1970)"
        let data = Data(seed.utf8)
        let hash = SHA256.hash(data: data)
        let bytes = Array(hash.prefix(16))
        let hashString = base64urlEncode(bytes)
        
        saveHash(hashString)
        return hashString
    }
    
    private func saveHash(_ value: String) {
        guard let data = value.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: installationHashKey,
            kSecValueData as String: data
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
    
    /// Base64url encode (no padding), safe for identifiers
    private func base64urlEncode(_ bytes: [UInt8]) -> String {
        let base64 = Data(bytes).base64EncodedString()
        return base64
            .replacingOccurrences(of: "+", with: "_")
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: "=", with: "")
    }
}

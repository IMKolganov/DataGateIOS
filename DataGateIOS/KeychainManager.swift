//
//  KeychainManager.swift
//  DataGateIOS
//

import Foundation
import Security

final class KeychainManager {
    static let shared = KeychainManager()
    
    private let service = "imkolganov.DataGateIOS"
    private let accessTokenKey = "accessToken"
    private let refreshTokenKey = "refreshToken"
    private let tokenExpirationKey = "tokenExpiration"
    private let userIdKey = "userId"
    private let displayNameKey = "displayName"
    private let emailKey = "email"
    private let isNewUserKey = "isNewUser"
    
    private init() {}
    
    // MARK: - Access Token
    
    func saveAccessToken(_ token: String, expiration: Date?) {
        save(token, forKey: accessTokenKey)
        if let expiration = expiration {
            let expirationString = ISO8601DateFormatter().string(from: expiration)
            save(expirationString, forKey: tokenExpirationKey)
        }
    }
    
    func getAccessToken() -> String? {
        return get(forKey: accessTokenKey)
    }
    
    func getTokenExpiration() -> Date? {
        guard let expirationString = get(forKey: tokenExpirationKey) else { return nil }
        return ISO8601DateFormatter().date(from: expirationString)
    }
    
    // MARK: - Refresh Token
    
    func saveRefreshToken(_ token: String) {
        save(token, forKey: refreshTokenKey)
    }
    
    func getRefreshToken() -> String? {
        return get(forKey: refreshTokenKey)
    }
    
    // MARK: - User Info
    
    func saveUserInfo(_ user: CurrentUser) {
        save(String(user.userId), forKey: userIdKey)
        save(user.displayName, forKey: displayNameKey)
        if let email = user.email {
            save(email, forKey: emailKey)
        } else {
            delete(forKey: emailKey)
        }
        save(String(user.isNewUser), forKey: isNewUserKey)
    }
    
    func getUserInfo() -> CurrentUser? {
        guard let userIdString = get(forKey: userIdKey),
              let userId = Int(userIdString),
              let displayName = get(forKey: displayNameKey),
              let isNewUserString = get(forKey: isNewUserKey) else {
            return nil
        }
        let isNewUser = (isNewUserString.lowercased() == "true")
        let email = get(forKey: emailKey)
        return CurrentUser(
            userId: userId,
            displayName: displayName,
            email: email,
            isNewUser: isNewUser
        )
    }
    
    // MARK: - Clear All
    
    func clearAll() {
        delete(forKey: accessTokenKey)
        delete(forKey: refreshTokenKey)
        delete(forKey: tokenExpirationKey)
        delete(forKey: userIdKey)
        delete(forKey: displayNameKey)
        delete(forKey: emailKey)
        delete(forKey: isNewUserKey)
    }
    
    // MARK: - Private Methods
    
    private func save(_ value: String, forKey key: String) {
        guard let data = value.data(using: .utf8) else { return }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        // Delete existing item first
        SecItemDelete(query as CFDictionary)
        
        // Add new item
        SecItemAdd(query as CFDictionary, nil)
    }
    
    private func get(forKey key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return value
    }
    
    private func delete(forKey key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        
        SecItemDelete(query as CFDictionary)
    }
}

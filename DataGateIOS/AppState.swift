//
//  AppState.swift
//  DataGateIOS
//

import SwiftUI
import UIKit

/// Global auth state and current user.
@Observable
@MainActor
final class AppState {
    private(set) var isAuthorized = false
    private(set) var currentUser: CurrentUser?
    private(set) var authError: String?
    private(set) var isInitializing = true

    private(set) var accessToken: String?
    private var refreshToken: String?
    private var expiration: Date?

    private let authService = AuthService.shared
    private let keychain = KeychainManager.shared
    private static let dateFormatter: ISO8601DateFormatter = ISO8601DateFormatter()

    init() {}
    
    /// Call this after AppState is created to restore session from Keychain
    func initialize() {
        Task { @MainActor in
            await restoreSession()
            isInitializing = false
        }
    }

    func login(idToken: String) {
        authError = nil
        authService.authorizeWithGoogle(idToken: idToken) { [weak self] result in
            Task { @MainActor in
                switch result {
                case .success(let response):
                    self?.accessToken = response.token
                    self?.refreshToken = response.refreshToken
                    self?.expiration = Self.dateFormatter.date(from: response.expiration)
                    self?.currentUser = CurrentUser(
                        userId: response.userId,
                        displayName: response.displayName ?? "",
                        email: response.email,
                        isNewUser: response.isNewUser ?? false
                    )
                    self?.isAuthorized = !response.token.isEmpty
                    self?.authError = nil
                    
                    // Save tokens and user info to Keychain
                    if let token = self?.accessToken {
                        self?.keychain.saveAccessToken(token, expiration: self?.expiration)
                    }
                    if let refresh = self?.refreshToken {
                        self?.keychain.saveRefreshToken(refresh)
                    }
                    if let user = self?.currentUser {
                        self?.keychain.saveUserInfo(user)
                    }
                case .failure(let error):
                    self?.isAuthorized = false
                    self?.currentUser = nil
                    self?.authError = (error as NSError).localizedDescription
                }
            }
        }
    }

    func refreshAccessToken(completion: ((Bool) -> Void)? = nil) {
        guard let token = refreshToken ?? keychain.getRefreshToken() else {
            completion?(false)
            return
        }
        
        // Update refreshToken if it was loaded from Keychain
        if refreshToken == nil {
            refreshToken = token
        }
        
        let deviceId = UIDevice.current.identifierForVendor?.uuidString ?? "unknown"
        let userAgent = "DataGateIOS/1.0 (\(UIDevice.current.model); iOS \(UIDevice.current.systemVersion))"
        let request = RefreshRequest(refreshToken: token, deviceId: deviceId, userAgent: userAgent)
        authService.refreshAccessToken(refreshRequest: request) { [weak self] result in
            Task { @MainActor in
                switch result {
                case .success(let response):
                    self?.accessToken = response.token
                    self?.expiration = Self.dateFormatter.date(from: response.expiration)
                    if let newRefresh = response.refreshToken {
                        self?.refreshToken = newRefresh
                        self?.keychain.saveRefreshToken(newRefresh)
                    }
                    // Save updated access token
                    if let token = self?.accessToken {
                        self?.keychain.saveAccessToken(token, expiration: self?.expiration)
                    }
                    completion?(true)
                case .failure:
                    // If refresh fails, clear tokens
                    self?.logout()
                    completion?(false)
                }
            }
        }
    }
    
    /// Restore session from Keychain on app launch
    @MainActor
    private func restoreSession() async {
        guard let savedToken = keychain.getAccessToken(),
              let savedRefresh = keychain.getRefreshToken() else {
            return
        }
        
        accessToken = savedToken
        refreshToken = savedRefresh
        expiration = keychain.getTokenExpiration()
        
        // Check if token is expired or will expire soon (within 5 minutes)
        if let expiration = expiration {
            let now = Date()
            let timeUntilExpiration = expiration.timeIntervalSince(now)
            
            if timeUntilExpiration > 300 { // More than 5 minutes left
                // Token is still valid, restore session
                isAuthorized = true
                // Restore user info from Keychain
                currentUser = keychain.getUserInfo()
            } else {
                // Token expired or expiring soon, try to refresh
                await withCheckedContinuation { continuation in
                    refreshAccessToken { success in
                        Task { @MainActor in
                            if success {
                                self.isAuthorized = true
                                // Restore user info from Keychain after refresh
                                self.currentUser = self.keychain.getUserInfo()
                            } else {
                                self.logout()
                            }
                            continuation.resume()
                        }
                    }
                }
            }
        } else {
            // No expiration date, assume token is valid
            isAuthorized = true
            // Restore user info from Keychain
            currentUser = keychain.getUserInfo()
        }
    }
    
    /// Check if token needs refresh and refresh if needed
    func ensureValidToken(completion: @escaping (Bool) -> Void) {
        guard let expiration = expiration ?? keychain.getTokenExpiration() else {
            // No expiration date, assume token is valid
            completion(true)
            return
        }
        
        let now = Date()
        let timeUntilExpiration = expiration.timeIntervalSince(now)
        
        // Refresh if expired or will expire within 5 minutes
        if timeUntilExpiration < 300 {
            refreshAccessToken(completion: completion)
        } else {
            completion(true)
        }
    }

    func logout() {
        isAuthorized = false
        currentUser = nil
        accessToken = nil
        refreshToken = nil
        expiration = nil
        authError = nil
        
        // Clear Keychain
        keychain.clearAll()
    }

    /// Token for authorized API requests (e.g. for future services).
    var bearerToken: String? { accessToken }
    
    /// External ID from JWT token claims
    var externalId: String? {
        guard let token = accessToken else { return nil }
        return JWTDecoder.getExternalId(from: token)
    }
}

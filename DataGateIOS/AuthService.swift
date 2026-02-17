//
//  AuthService.swift
//  DataGateIOS
//

import Foundation

final class AuthService {
    static let shared = AuthService()
    private let client = APIClient.shared

    private init() {}

    func authorizeWithGoogle(idToken: String, completion: @escaping (Result<GoogleLoginResponse, Error>) -> Void) {
        let body = GoogleLoginRequest(idToken: idToken)
        client.request(
            path: "/api/auth/google-login",
            method: "POST",
            body: body,
            authToken: nil,
            completion: completion
        )
    }

    func refreshAccessToken(refreshRequest: RefreshRequest, completion: @escaping (Result<RefreshResponse, Error>) -> Void) {
        client.request(
            path: "/api/auth/refresh",
            method: "POST",
            body: refreshRequest,
            authToken: nil,
            completion: completion
        )
    }
}

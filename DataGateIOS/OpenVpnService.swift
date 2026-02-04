//
//  OpenVpnService.swift
//  DataGateIOS
//

import Foundation

final class OpenVpnService {
    static let shared = OpenVpnService()
    private let client = APIClient.shared

    private init() {}

    func getAllServersWithStatus(
        authToken: String,
        appState: AppState? = nil,
        completion: @escaping (Result<OpenVpnServerWithStatusesResponse, Error>) -> Void
    ) {
        // Ensure token is valid before making request
        if let appState = appState {
            appState.ensureValidToken { [weak self] isValid in
                guard isValid, let token = appState.bearerToken else {
                    completion(.failure(NSError(domain: "OpenVpnService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid or expired token"])))
                    return
                }
                self?.performRequest(token: token, appState: appState, completion: completion)
            }
        } else {
            performRequest(token: authToken, appState: nil, completion: completion)
        }
    }
    
    private func performRequest(
        token: String,
        appState: AppState?,
        completion: @escaping (Result<OpenVpnServerWithStatusesResponse, Error>) -> Void
    ) {
        client.request(
            path: "/api/open-vpn-servers/get-all-with-status",
            method: "GET",
            body: nil as (any Encodable)?,
            authToken: token,
            completion: { [weak self] (result: Result<OpenVpnServerWithStatusesResponse, Error>) in
                switch result {
                case .success(let response):
                    completion(.success(response))
                case .failure(let error):
                    // If 401 and we have AppState, try to refresh and retry
                    if let nsError = error as NSError?,
                       nsError.code == 401,
                       let appState = appState {
                        appState.refreshAccessToken { success in
                            if success, let newToken = appState.bearerToken {
                                // Retry request with new token
                                self?.performRequest(token: newToken, appState: appState, completion: completion)
                            } else {
                                completion(.failure(error))
                            }
                        }
                    } else {
                        completion(.failure(error))
                    }
                }
            }
        )
    }
}

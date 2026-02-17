//
//  StatisticsService.swift
//  DataGateIOS
//

import Foundation

final class StatisticsService {
    static let shared = StatisticsService()
    private let baseURL = APIConfig.baseURL

    private init() {}

    func getOverviewSeries(
        request: GetOverviewSeriesRequest,
        authToken: String,
        appState: AppState? = nil,
        completion: @escaping (Result<OverviewSeriesResponse, Error>) -> Void
    ) {
        // Ensure token is valid before making request
        if let appState = appState {
            appState.ensureValidToken { [weak self] isValid in
                guard isValid, let token = appState.bearerToken else {
                    completion(.failure(NSError(domain: "StatisticsService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid or expired token"])))
                    return
                }
                self?.performRequest(request: request, token: token, appState: appState, completion: completion)
            }
        } else {
            performRequest(request: request, token: authToken, appState: nil, completion: completion)
        }
    }
    
    private func performRequest(
        request: GetOverviewSeriesRequest,
        token: String,
        appState: AppState?,
        completion: @escaping (Result<OverviewSeriesResponse, Error>) -> Void
    ) {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        
        guard let externalId = request.externalId else {
            completion(.failure(NSError(domain: "StatisticsService", code: -1, userInfo: [NSLocalizedDescriptionKey: "ExternalId is required"])))
            return
        }
        
        var components = URLComponents()
        components.scheme = baseURL.scheme
        components.host = baseURL.host
        // Use the endpoint from C# code: /api/open-vpn-clients/overview/series
        components.path = "/api/open-vpn-clients/overview/series"
        components.queryItems = [
            URLQueryItem(name: "From", value: formatter.string(from: request.from)),
            URLQueryItem(name: "To", value: formatter.string(from: request.to)),
            URLQueryItem(name: "Grouping", value: String(request.grouping.queryValue)),
            URLQueryItem(name: "ExternalId", value: externalId),
        ]
        
        if let vpnServerId = request.vpnServerId {
            components.queryItems?.append(URLQueryItem(name: "VpnServerId", value: String(vpnServerId)))
        }
        
        // Debug: print URL to verify
        if let url = components.url {
            print("📊 Statistics URL: \(url.absoluteString)")
            print("📊 ExternalId from token: \(externalId)")
        }
        
        guard let url = components.url else {
            completion(.failure(NSError(domain: "StatisticsService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "GET"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        
        URLSession.shared.dataTask(with: urlRequest) { [weak self] data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(NSError(domain: "StatisticsService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }
            
            // On 401, refresh token and retry once (same as OpenVpnService)
            if httpResponse.statusCode == 401, let appState = appState {
                Task { @MainActor in
                    appState.refreshAccessToken { success in
                        guard success, let newToken = appState.bearerToken else {
                            completion(.failure(NSError(domain: "StatisticsService", code: 401, userInfo: [NSLocalizedDescriptionKey: "Unauthorized"])))
                            return
                        }
                        self?.performRequest(request: request, token: newToken, appState: appState, completion: completion)
                    }
                }
                return
            }
            
            guard (200...299).contains(httpResponse.statusCode) else {
                let statusCode = httpResponse.statusCode
                completion(.failure(NSError(domain: "StatisticsService", code: statusCode, userInfo: [NSLocalizedDescriptionKey: "HTTP \(statusCode)"])))
                return
            }
            
            guard let data = data else {
                completion(.failure(NSError(domain: "StatisticsService", code: -1, userInfo: [NSLocalizedDescriptionKey: "No data"])))
                return
            }
            
            do {
                let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                let success = (json?["success"] as? Bool) ?? false
                
                if !success {
                    let message = (json?["message"] as? String) ?? "Request failed"
                    completion(.failure(NSError(domain: "StatisticsService", code: -1, userInfo: [NSLocalizedDescriptionKey: message])))
                    return
                }
                
                // Decode in MainActor context to satisfy Swift 6 concurrency requirements
                let decoder = JSONDecoder()
                Task { @MainActor in
                    do {
                        let apiResponse = try decoder.decode(ApiResponse<OverviewSeriesResponse>.self, from: data)
                        if let responseData = apiResponse.data {
                            completion(.success(responseData))
                        } else {
                            completion(.failure(NSError(domain: "StatisticsService", code: -1, userInfo: [NSLocalizedDescriptionKey: "No data in response"])))
                        }
                    } catch {
                        completion(.failure(error))
                    }
                }
            } catch {
                completion(.failure(error))
            }
        }.resume()
    }
}

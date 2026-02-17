//
//  APIClient.swift
//  DataGateIOS
//

import Foundation

/// Shared client for backend requests. All responses are wrapped in ApiResponse<T>.
final class APIClient {
    static let shared = APIClient()
    private let baseURL = APIConfig.baseURL
    private let session: URLSession

    private init() {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        configuration.waitsForConnectivity = true
        self.session = URLSession(configuration: configuration)
    }

    /// Performs request and unwraps ApiResponse<T>. On success returns data; otherwise returns error with message.
    func request<T: Decodable>(
        path: String,
        method: String = "GET",
        body: (any Encodable)? = nil,
        authToken: String? = nil,
        completion: @escaping (Result<T, Error>) -> Void
    ) {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            completion(.failure(NSError(domain: "APIClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid path"])))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        if let body = body {
            do {
                request.httpBody = try JSONEncoder().encode(AnyEncodable(body))
            } catch {
                completion(.failure(error))
                return
            }
        }

        session.dataTask(with: request) { data, response, error in
            // Handle network errors first
            if let error = error {
                let nsError = error as NSError
                // Ignore network framework warnings about unconnected connections
                if nsError.domain == "NSURLErrorDomain" || nsError.domain.contains("nw_") {
                    // These are usually non-critical warnings
                }
                completion(.failure(error))
                return
            }
            
            // Check HTTP status code
            if let httpResponse = response as? HTTPURLResponse {
                // Handle 401 Unauthorized - token expired
                if httpResponse.statusCode == 401 && authToken != nil {
                    // Try to refresh token and retry request
                    // Note: This requires AppState, so we'll handle it in the service layer
                    let statusMessage = HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode)
                    let errorMsg = "HTTP \(httpResponse.statusCode): \(statusMessage)"
                    completion(.failure(NSError(domain: "APIClient", code: httpResponse.statusCode, userInfo: [NSLocalizedDescriptionKey: errorMsg])))
                    return
                }
                
                guard (200...299).contains(httpResponse.statusCode) else {
                    let statusMessage = HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode)
                    let errorMsg = "HTTP \(httpResponse.statusCode): \(statusMessage)"
                    completion(.failure(NSError(domain: "APIClient", code: httpResponse.statusCode, userInfo: [NSLocalizedDescriptionKey: errorMsg])))
                    return
                }
            }
            
            guard let data = data else {
                completion(.failure(NSError(domain: "APIClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "No data received"])))
                return
            }

            // Don't log response body — it may contain tokens and other sensitive data
            // Read backend response for success/message and to show server error message
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(.failure(NSError(domain: "APIClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid JSON response"])))
                return
            }
            
            let success = (json["success"] as? Bool) ?? (json["Success"] as? Bool) ?? false
            let message = (json["message"] as? String) ?? (json["Message"] as? String)

            if !success {
                let msg = message ?? "Request failed"
                print("❌ API Error: \(msg)")
                completion(.failure(NSError(domain: "APIClient", code: -1, userInfo: [NSLocalizedDescriptionKey: msg])))
                return
            }

            let decoder = JSONDecoder()

            // Decode in MainActor context to satisfy Swift 6 concurrency requirements
            Task { @MainActor in
                do {
                    let apiResponse = try decoder.decode(ApiResponse<T>.self, from: data)
                    if let responseData = apiResponse.data {
                        print("✅ Decoded successfully")
                        completion(.success(responseData))
                    } else {
                        print("⚠️ No data in response")
                        completion(.failure(NSError(domain: "APIClient", code: -1, userInfo: [NSLocalizedDescriptionKey: message ?? "No data in response"])))
                    }
                } catch {
                    // Log decoding error details
                    print("❌ Decoding error: \(error)")
                    if let decodingError = error as? DecodingError {
                        switch decodingError {
                        case .keyNotFound(let key, let context):
                            print("   Missing key: \(key.stringValue) at \(context.codingPath.map { $0.stringValue }.joined(separator: "."))")
                        case .typeMismatch(let type, let context):
                            print("   Type mismatch: expected \(type) at \(context.codingPath.map { $0.stringValue }.joined(separator: "."))")
                        case .valueNotFound(let type, let context):
                            print("   Value not found: \(type) at \(context.codingPath.map { $0.stringValue }.joined(separator: "."))")
                        case .dataCorrupted(let context):
                            print("   Data corrupted at \(context.codingPath.map { $0.stringValue }.joined(separator: ".")): \(context.debugDescription)")
                        @unknown default:
                            print("   Unknown decoding error")
                        }
                    }
                    
                    // If decode failed, try to at least show backend message from raw JSON
                    if let msg = message {
                        completion(.failure(NSError(domain: "APIClient", code: -1, userInfo: [NSLocalizedDescriptionKey: msg])))
                    } else {
                        completion(.failure(error))
                    }
                }
            }
        }.resume()
    }
}

/// Type-erased wrapper for encoding any Encodable.
private struct AnyEncodable: Encodable {
    private let encode: (Encoder) throws -> Void
    init<T: Encodable>(_ value: T) {
        encode = value.encode
    }
    func encode(to encoder: Encoder) throws {
        try encode(encoder)
    }
}

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

        ClientIdentity.dataTask(with: request, session: session) { data, response, error in
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
                
                if httpResponse.statusCode == 400, let code = ClientIdentity.rejectionCode(from: data) {
                    completion(.failure(ClientIdentity.rejectionError(code: code)))
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

// MARK: - Client identity

/// Who is calling the DataGateMonitor backend: `X-Client-Name: ios` + the app build version.
/// Source of truth: NuGet DataGateMonitor.SharedModels (1.0.90+, `ClientNames.Ios`),
/// `DataGateMonitor.SharedModels.ClientIdentity.ClientIdentityRules`. Change together with the backend rules.
///
/// Only for backend requests: never for the extension's WSS to the VPN node (`/api/proxy`) or Google sign-in.
nonisolated enum ClientIdentity {
    static let nameHeader = "X-Client-Name"
    static let versionHeader = "X-Client-Version"
    static let nameQuery = "clientName"
    static let versionQuery = "clientVersion"
    static let clientName = "ios"
    static let maxVersionLength = 64

    /// Posted on the main queue, once per run, when the backend refuses this build (`object` is the `client_*` code).
    static let rejectedNotification = Notification.Name("DataGateClientIdentityRejected")

    /// `CFBundleShortVersionString (CFBundleVersion)`, e.g. `1.0.1 (2)`.
    static let clientVersion: String = version(from: Bundle.main.infoDictionary)

    static func version(from info: [String: Any]?) -> String {
        let short = (info?["CFBundleShortVersionString"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
        let build = (info?["CFBundleVersion"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
        let raw: String
        switch (short.isEmpty, build.isEmpty) {
        case (false, false): raw = "\(short) (\(build))"
        case (false, true): raw = short
        case (true, false): raw = build
        case (true, true): raw = ""
        }
        return sanitizeVersion(raw)
    }

    /// Printable ASCII only (0x20–0x7E), 1–64 chars; "0" when nothing is left.
    static func sanitizeVersion(_ raw: String) -> String {
        var scalars = String.UnicodeScalarView()
        scalars.append(contentsOf: raw.unicodeScalars.filter { $0.value >= 0x20 && $0.value <= 0x7E })
        let trimmed = String(String(scalars).trimmingCharacters(in: .whitespaces).prefix(maxVersionLength))
            .trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? "0" : trimmed
    }

    static func apply(to request: inout URLRequest, version: String = clientVersion) {
        request.setValue(clientName, forHTTPHeaderField: nameHeader)
        request.setValue(version, forHTTPHeaderField: versionHeader)
    }

    /// Adds `clientName` / `clientVersion` to a SignalR / WebSocket `/api/hubs/*` URL, keeping the existing query.
    static func appendToHubURL(_ url: URL, version: String = clientVersion) -> URL {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return url }
        var items = (components.queryItems ?? []).filter { $0.name != nameQuery && $0.name != versionQuery }
        items.append(URLQueryItem(name: nameQuery, value: clientName))
        items.append(URLQueryItem(name: versionQuery, value: version))
        components.queryItems = items
        return components.url ?? url
    }

    static let errorDomain = "ClientIdentity"
    static let outdatedMessage = "This version of DataGate is no longer supported by the server. Please update the app."

    static func rejectionError(code: String) -> NSError {
        NSError(domain: errorDomain, code: 400, userInfo: [NSLocalizedDescriptionKey: outdatedMessage, "code": code])
    }

    /// `data.code` of a client-identity 400 (`client_name_missing`, …), or nil for any other body.
    static func rejectionCode(from data: Data?) -> String? {
        guard let data,
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload = (root["data"] ?? root["Data"]) as? [String: Any],
              let code = ((payload["code"] ?? payload["Code"]) as? String)?.trimmingCharacters(in: .whitespaces),
              code.hasPrefix("client_") else {
            return nil
        }
        return code
    }

    /// The one entry point for backend requests: sets the headers, reports `client_*` 400s, then calls back.
    static func dataTask(
        with request: URLRequest,
        session: URLSession = .shared,
        completion: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTask {
        var request = request
        apply(to: &request)
        let path = request.url?.path ?? ""
        return session.dataTask(with: request) { data, response, error in
            if (response as? HTTPURLResponse)?.statusCode == 400, let code = rejectionCode(from: data) {
                print("❌ Backend rejected client identity (\(code)) for \(path): update the app")
                notifyRejected(code)
            }
            completion(data, response, error)
        }
    }

    nonisolated(unsafe) private static var didNotify = false
    private static let notifyLock = NSLock()

    static func notifyRejected(_ code: String) {
        notifyLock.lock()
        let first = !didNotify
        didNotify = true
        notifyLock.unlock()
        guard first else { return }
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: rejectedNotification, object: code)
        }
    }
}

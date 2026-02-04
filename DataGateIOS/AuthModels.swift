struct ApiResponse<T: Decodable>: Decodable {
    let success: Bool
    let message: String?
    let data: T?
    
    enum CodingKeys: String, CodingKey {
        case success
        case message
        case data
    }
}

struct GoogleLoginRequest: Encodable {
    let idToken: String
}

struct GoogleLoginResponse: Decodable {
    let token: String
    let expiration: String
    let refreshToken: String?
    let refreshExpiration: String?
    let userId: Int
    let displayName: String?
    let email: String?
    let isNewUser: Bool?
}

struct RefreshRequest: Encodable {
    let refreshToken: String
    let deviceId: String
    let userAgent: String
}

struct RefreshResponse: Decodable {
    let token: String
    let expiration: String
    let refreshToken: String?
    let refreshExpiration: String?
}

/// Authorized client model for display on the main screen.
struct CurrentUser {
    let userId: Int
    let displayName: String
    let email: String?
    let isNewUser: Bool
}

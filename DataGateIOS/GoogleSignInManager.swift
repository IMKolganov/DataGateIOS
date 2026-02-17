//
//  GoogleSignInManager.swift
//  DataGateIOS
//

import Foundation
import GoogleSignIn
import UIKit

enum GoogleSignInError: LocalizedError {
    case notConfigured
    case missingURLScheme
    case noRootViewController
    case noIdToken
    case cancelled
    case unknown(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "Google Sign-In is not configured. Add GIDClientID to Config.plist (copy Config.example.plist to Config.plist and fill in your values)."
        case .missingURLScheme:
            return "Google Sign-In URL scheme is missing. Add CFBundleURLTypes with your reversed client ID."
        case .noRootViewController:
            return "Could not present sign-in screen."
        case .noIdToken:
            return "No ID token received from Google."
        case .cancelled:
            return "Sign-in was cancelled."
        case .unknown(let message):
            return message
        }
    }
}

/// Wraps Google Sign-In and returns backend-ready idToken string.
final class GoogleSignInManager {
    static let shared = GoogleSignInManager()

    private init() {}

    /// Runs Google Sign-In flow and returns idToken string for backend auth, or an error.
    func signIn(completion: @escaping (Result<String, Error>) -> Void) {
        guard hasGoogleSignInConfiguration else {
            completion(.failure(GoogleSignInError.notConfigured))
            return
        }
        guard hasGoogleSignInURLScheme else {
            completion(.failure(GoogleSignInError.missingURLScheme))
            return
        }
        guard let rootVC = rootViewController else {
            completion(.failure(GoogleSignInError.noRootViewController))
            return
        }

        GIDSignIn.sharedInstance.signIn(withPresenting: rootVC) { signInResult, error in
            if let error = error as NSError? {
                // -5 = GIDSignInErrorCode.canceled (user cancelled the flow)
                if error.domain == "com.google.GIDSignIn" && error.code == -5 {
                    completion(.failure(GoogleSignInError.cancelled))
                } else {
                    completion(.failure(error))
                }
                return
            }
            guard let signInResult = signInResult else {
                completion(.failure(GoogleSignInError.unknown("No sign-in result")))
                return
            }

            signInResult.user.refreshTokensIfNeeded { user, error in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                guard let user = user else {
                    completion(.failure(GoogleSignInError.unknown("No user after refresh")))
                    return
                }
                guard let idToken = user.idToken?.tokenString else {
                    completion(.failure(GoogleSignInError.noIdToken))
                    return
                }
                completion(.success(idToken))
            }
        }
    }

    private var hasGoogleSignInConfiguration: Bool {
        guard let clientID = APIConfig.googleClientID,
              !clientID.isEmpty else { return false }
        if GIDSignIn.sharedInstance.configuration == nil {
            GIDSignIn.sharedInstance.configuration = GIDConfiguration(clientID: clientID)
        }
        return true
    }

    private var hasGoogleSignInURLScheme: Bool {
        let suffix = ".apps.googleusercontent.com"
        guard let clientID = APIConfig.googleClientID,
              clientID.hasSuffix(suffix) else { return false }
        let reversedId = String(clientID.dropLast(suffix.count))
        let scheme = "com.googleusercontent.apps." + reversedId
        guard let urlTypes = Bundle.main.object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String: Any]] else { return false }
        return urlTypes.contains { dict in
            (dict["CFBundleURLSchemes"] as? [String])?.contains(scheme) == true
        }
    }

    private var rootViewController: UIViewController? {
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first
        return scene?.windows.first(where: { $0.isKeyWindow })?.rootViewController
    }
}

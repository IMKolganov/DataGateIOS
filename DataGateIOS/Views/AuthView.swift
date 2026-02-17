//
//  AuthView.swift
//  DataGateIOS
//

import SwiftUI

struct AuthView: View {
    @Environment(AppState.self) private var appState
    @State private var isSigningIn = false
    @State private var signInError: String?

    private var displayedError: String? { signInError ?? appState.authError }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Text("DataGate")
                .font(AppTypography.title)
            Text("Sign in to your account")
                .font(AppTypography.bodySecondary)
                .foregroundStyle(.secondary)

            // Fixed height so layout doesn't jump when error appears or disappears
            Group {
                if let error = displayedError {
                    Text(error)
                        .font(AppTypography.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                } else {
                    Text(" ")
                        .font(AppTypography.caption)
                        .opacity(0)
                }
            }
            .frame(minHeight: 32)
            .padding(.horizontal, 32)

            Button {
                startGoogleSignIn()
            } label: {
                HStack(spacing: 8) {
                    if isSigningIn {
                        ProgressView()
                            .tint(.white)
                    }
                    Text(isSigningIn ? "Signing in…" : "Sign in with Google")
                        .font(AppTypography.button)
                    Image(systemName: "person.circle.fill")
                }
                .frame(maxWidth: .infinity)
                .frame(height: 50)
            }
            .buttonStyle(.borderedProminent)
            .padding(.horizontal, 32)
            .disabled(isSigningIn)

            Spacer()
        }
    }

    private func startGoogleSignIn() {
        signInError = nil
        isSigningIn = true
        GoogleSignInManager.shared.signIn { result in
            Task { @MainActor in
                isSigningIn = false
                switch result {
                case .success(let idToken):
                    appState.login(idToken: idToken)
                case .failure(GoogleSignInError.cancelled):
                    break
                case .failure(let error):
                    signInError = (error as? LocalizedError)?.errorDescription ?? (error as NSError).localizedDescription
                }
            }
        }
    }
}

#Preview {
    AuthView()
        .environment(AppState())
}

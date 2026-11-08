//
//  ContentView.swift
//  DataGateIOS
//

import SwiftUI

struct ContentView: View {
    @Environment(AppState.self) private var appState
    @State private var showClientOutdated = false

    var body: some View {
        Group {
            if appState.isInitializing {
                // Show splash screen while checking session
                ZStack {
                    Color(.systemBackground)
                    VStack(spacing: 16) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 60))
                            .foregroundStyle(.blue)
                        Text("DataGate")
                            .font(AppTypography.title)
                    }
                }
                .ignoresSafeArea()
            } else if appState.isAuthorized {
                MainView()
            } else {
                AuthView()
            }
        }
        .ignoresSafeArea(.all)
        .onReceive(NotificationCenter.default.publisher(for: ClientIdentity.rejectedNotification)) { _ in
            showClientOutdated = true
        }
        .alert("Update required", isPresented: $showClientOutdated) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(ClientIdentity.outdatedMessage)
        }
    }
}

#Preview {
    ContentView()
        .environment(AppState())
}

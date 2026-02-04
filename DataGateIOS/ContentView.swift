//
//  ContentView.swift
//  DataGateIOS
//

import SwiftUI

struct ContentView: View {
    @Environment(AppState.self) private var appState

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
    }
}

#Preview {
    ContentView()
        .environment(AppState())
}

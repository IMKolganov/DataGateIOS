//
//  DataGateIOSApp.swift
//  DataGateIOS
//
//  Created by Ivan Kolganov on 03/02/2026.
//

import SwiftUI
import GoogleSignIn

@main
struct DataGateIOSApp: App {
    @State private var appState = AppState()
    @State private var themeManager = ThemeManager.shared

    init() {
        if let clientID = APIConfig.googleClientID, !clientID.isEmpty {
            GIDSignIn.sharedInstance.configuration = GIDConfiguration(clientID: clientID)
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(appState)
                .environment(themeManager)
                .preferredColorScheme(themeManager.currentTheme.colorScheme)
                .onChange(of: themeManager.currentTheme) { _, _ in
                    // Force update when theme changes
                }
                .task {
                    appState.initialize()
                }
        }
    }
}

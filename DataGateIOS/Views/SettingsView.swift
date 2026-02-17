//
//  SettingsView.swift
//  DataGateIOS
//

import SwiftUI

struct SettingsView: View {
    @Environment(AppState.self) private var appState
    @Environment(ThemeManager.self) private var themeManager

    var body: some View {
        NavigationStack {
            List {
                if let user = appState.currentUser {
                    Section("Profile") {
                        LabeledContent("Name", value: user.displayName)
                        if let email = user.email, !email.isEmpty {
                            LabeledContent("Email", value: email)
                        }
                        LabeledContent("ID", value: String(user.userId))
                        if user.isNewUser {
                            LabeledContent("Status", value: "New user")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                
                Section("Appearance") {
                    let bindableTheme = Bindable(themeManager)
                    Picker("Theme", selection: bindableTheme.currentTheme) {
                        ForEach(AppTheme.allCases, id: \.self) { theme in
                            HStack {
                                Image(systemName: theme.icon)
                                Text(theme.rawValue)
                            }
                            .tag(theme)
                        }
                    }
                }
            }
            .listStyle(.plain)
            .contentMargins(.top, 0, for: .scrollContent)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Log out", role: .destructive) {
                        appState.logout()
                    }
                }
            }
        }
    }
}

#Preview {
    SettingsView()
        .environment(AppState())
}

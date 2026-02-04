//
//  AccessView.swift
//  DataGateIOS
//

import SwiftUI

struct AccessView: View {
    @Environment(AppState.self) private var appState
    @State private var servers: [OpenVpnServerWithStatusDto] = []
    @State private var isLoading = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if isLoading {
                    ProgressView("Loading servers...")
                } else if let error = errorMessage {
                    ContentUnavailableView(
                        "Error",
                        systemImage: "exclamationmark.triangle",
                        description: Text(error)
                    )
                } else if servers.isEmpty {
                    ContentUnavailableView(
                        "No servers",
                        systemImage: "server.rack",
                        description: Text("No VPN servers available")
                    )
                } else {
                    serverList
                }
            }
            .navigationTitle("Access")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .task {
                await loadServers()
            }
            .refreshable {
                await loadServers()
            }
        }
    }

    private var serverList: some View {
        ScrollView {
            LazyVStack(spacing: 12) {
                ForEach(servers, id: \.openVpnServerResponses.openVpnServer.id) { server in
                    ServerRowView(server: server)
                        .padding(.horizontal, 16)
                }
            }
            .padding(.top, 8)
        }
        .background(Color(.systemGroupedBackground))
        .scrollIndicators(.hidden)
        .contentMargins(.top, 0, for: .scrollContent)
    }

    @MainActor
    private func loadServers() async {
        guard let token = appState.bearerToken else {
            errorMessage = "Not authorized"
            return
        }
        
        // Prevent multiple simultaneous requests
        guard !isLoading else { return }

        isLoading = true
        errorMessage = nil

        OpenVpnService.shared.getAllServersWithStatus(authToken: token, appState: appState) { result in
            Task { @MainActor in
                isLoading = false
                switch result {
                case .success(let response):
                    servers = response.openVpnServerWithStatuses
                case .failure(let error):
                    let nsError = error as NSError
                    // Filter out network framework warnings
                    if !nsError.domain.contains("nw_") {
                        var errorText = nsError.localizedDescription
                        // Add more details for debugging
                        if let underlyingError = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
                            errorText += "\n(\(underlyingError.localizedDescription))"
                        }
                        errorMessage = errorText
                        print("❌ AccessView error: \(errorText)")
                    }
                }
            }
        }
    }
}

struct ServerRowView: View {
    let server: OpenVpnServerWithStatusDto

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                // Status indicator
                Circle()
                    .fill(server.openVpnServerResponses.openVpnServer.isOnline ? Color.green : Color.red)
                    .frame(width: 12, height: 12)
                
                Text(server.openVpnServerResponses.openVpnServer.serverName)
                    .font(AppTypography.headline)
                
                Spacer()
                
                if server.openVpnServerResponses.openVpnServer.isDefault {
                    Text("Default")
                        .font(AppTypography.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.blue.opacity(0.2))
                        .foregroundColor(.blue)
                        .cornerRadius(4)
                }
            }

            if let status = server.openVpnServerStatusLogResponse {
                VStack(alignment: .leading, spacing: 6) {
                    LabeledContent("Connected clients:", value: "\(server.countConnectedClients)")
                    LabeledContent("Sessions:", value: "\(server.countSessions)")
                    LabeledContent("Uptime:", value: formatUptime(from: status.upSinceParsed))
                    LabeledContent("OpenVPN version:", value: status.version)
                    LabeledContent("Bytes In:", value: formatBytes(server.totalBytesIn))
                    LabeledContent("Bytes Out:", value: formatBytes(server.totalBytesOut))
                }
                .font(AppTypography.caption)
                .foregroundStyle(.secondary)
            } else {
                Text("No status available")
                    .font(AppTypography.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.05), radius: 4, x: 0, y: 2)
    }

    private func formatUptime(from date: Date?) -> String {
        guard let date = date else { return "N/A" }
        let now = Date()
        let interval = now.timeIntervalSince(date)
        
        let days = Int(interval) / 86400
        let hours = (Int(interval) % 86400) / 3600
        let minutes = (Int(interval) % 3600) / 60
        
        if days > 0 {
            return "\(days)d \(hours)h \(minutes)m"
        } else if hours > 0 {
            return "\(hours)h \(minutes)m"
        } else {
            return "\(minutes)m"
        }
    }

    private func formatBytes(_ bytes: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: bytes)
    }
}

#Preview {
    AccessView()
        .environment(AppState())
}

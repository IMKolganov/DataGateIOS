//
//  HomeView.swift
//  DataGateIOS
//

import SwiftUI
import NetworkExtension

struct HomeView: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(AppState.self) private var appState
    @State private var connectionState: ConnectionState = .disconnected
    @State private var vpnViewModel = VPNConnectionViewModel()
    
    enum ConnectionState {
        case disconnected
        case connecting
        case connected
        
        var title: String {
            switch self {
            case .disconnected: return "Disconnected"
            case .connecting: return "Connecting"
            case .connected: return "Connected"
            }
        }
        
        func mainColor(for colorScheme: ColorScheme?) -> Color {
            switch self {
            case .connected: return AppColors.primary(for: colorScheme)
            case .connecting: return AppColors.tertiary(for: colorScheme)
            case .disconnected: return AppColors.error
            }
        }
        
        func backgroundColor(for colorScheme: ColorScheme?) -> Color {
            switch self {
            case .connected: return mainColor(for: colorScheme).opacity(0.18)
            case .connecting: return mainColor(for: colorScheme).opacity(0.15)
            case .disconnected: return Color(.systemGray6)
            }
        }
    }
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 0) {
                    // State Block
                    VStack(spacing: 12) {
                        Circle()
                            .fill(connectionState.mainColor(for: colorScheme))
                            .frame(width: 14, height: 14)
                        
                        Text(connectionState.title)
                            .font(AppTypography.statusTitle)
                            .foregroundColor(.primary)
                        
                        if let error = vpnViewModel.connectionError {
                            Text(error)
                                .font(AppTypography.statusSubtitle)
                                .foregroundColor(.red)
                                .lineLimit(2)
                        } else {
                            Text("Ready to connect")
                                .font(AppTypography.statusSubtitle)
                                .foregroundColor(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 20)
                    .background {
                        RoundedRectangle(cornerRadius: 24)
                            .fill(Color(.systemGray6))
                            .shadow(color: .black.opacity(0.1), radius: 4, x: 0, y: 2)
                    }
                    .padding(.horizontal, 20)
                    .padding(.bottom, 50)
                    
                    // Last applied tunnel settings (after connect)
                    if let tunnelInfo = vpnViewModel.lastAppliedTunnelSettings {
                        Text(tunnelInfo)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                            .lineLimit(2)
                            .padding(.horizontal, 20)
                            .padding(.vertical, 6)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(.systemGray6))
                            .cornerRadius(6)
                            .padding(.horizontal, 20)
                            .padding(.bottom, 8)
                    }
                    
                    // Connect Button
                    Button {
                        Task {
                            if vpnViewModel.isConnected {
                                await vpnViewModel.disconnect()
                            } else {
                                await vpnViewModel.connectWithServerConfig(appState: appState)
                                try? await Task.sleep(nanoseconds: 3_000_000_000)
                                await vpnViewModel.updateConnectionStatus()
                                try? await Task.sleep(nanoseconds: 1_000_000_000)
                                await vpnViewModel.refreshLogs()
                            }
                        }
                    } label: {
                    let mainColor = connectionState.mainColor(for: colorScheme)
                    let bgColor = connectionState.backgroundColor(for: colorScheme)
                    
                    VStack(spacing: 24) {
                        // Large circular button
                        ZStack {
                            // Outer circle with background and border
                            Circle()
                                .fill(bgColor)
                                .frame(width: 240, height: 240)
                                .overlay(
                                    Circle()
                                        .stroke(mainColor.opacity(0.6), lineWidth: 4)
                                )
                            
                            // Inner circle with radial gradient
                            Circle()
                                .fill(
                                    RadialGradient(
                                        colors: [
                                            mainColor,
                                            mainColor.opacity(0.7)
                                        ],
                                        center: .center,
                                        startRadius: 0,
                                        endRadius: 100
                                    )
                                )
                                .frame(width: 200, height: 200)
                            
                            // Power icon and text (smaller to fit inside inner circle)
                            VStack(spacing: 8) {
                                if vpnViewModel.isConnecting {
                                    ProgressView()
                                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                        .scaleEffect(1.5)
                                } else {
                                    Image(systemName: vpnViewModel.isConnected ? "power" : "power")
                                        .font(.system(size: 56, weight: .medium))
                                        .foregroundColor(.white)
                                }
                                
                                Text(vpnViewModel.isConnected ? "Disconnect" : vpnViewModel.isConnecting ? "Connecting..." : "Connect")
                                    .font(AppTypography.buttonLarge)
                                    .foregroundColor(.white)
                            }
                        }
                    }
                }
                .buttonStyle(.plain)
                .disabled(vpnViewModel.isConnecting)
                .padding(.bottom, 32)
                    
                    // Extension Logs — below button, open only when user taps
                    VStack(spacing: 8) {
                        Button {
                            vpnViewModel.toggleLogs()
                        } label: {
                            HStack {
                                Image(systemName: vpnViewModel.showLogs ? "chevron.down" : "chevron.right")
                                    .font(.system(size: 12, weight: .medium))
                                Text("Logs (\(vpnViewModel.extensionLogs.count))")
                                    .font(.system(size: 14, weight: .medium))
                                Spacer()
                                if vpnViewModel.showLogs {
                                    Button {
                                        Task { await vpnViewModel.refreshLogs() }
                                    } label: {
                                        Image(systemName: "arrow.clockwise")
                                            .font(.system(size: 12, weight: .medium))
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                            .foregroundColor(.secondary)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 12)
                            .background(Color(.systemGray6))
                            .cornerRadius(8)
                        }
                        .buttonStyle(.plain)
                        .padding(.horizontal, 20)
                        
                        if vpnViewModel.showLogs {
                            ScrollView {
                                VStack(alignment: .leading, spacing: 4) {
                                    if vpnViewModel.extensionLogs.isEmpty {
                                        Text("No logs")
                                            .font(.system(size: 12))
                                            .foregroundColor(.secondary)
                                            .padding()
                                    } else {
                                        ForEach(Array(vpnViewModel.extensionLogs.enumerated()), id: \.offset) { index, log in
                                            Text(log)
                                                .font(.system(size: 11, design: .monospaced))
                                                .foregroundColor(.secondary)
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                                .padding(.horizontal, 12)
                                                .padding(.vertical, 4)
                                                .background(index % 2 == 0 ? Color.clear : Color(.systemGray5))
                                        }
                                    }
                                }
                            }
                            .frame(maxHeight: 280)
                            .background(Color(.systemGray6))
                            .cornerRadius(8)
                            .padding(.horizontal, 20)
                        }
                    }
                    .padding(.bottom, 40)
                }
            }
            .scrollBounceBehavior(.basedOnSize)
            .navigationTitle("DataGate OpenVPN")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .task {
                vpnViewModel.startObserving()
                // Update connection state based on VPN status
                updateConnectionState()
            }
            .onChange(of: vpnViewModel.connectionStatus) { _, _ in
                updateConnectionState()
            }
        }
    }
    
    private func updateConnectionState() {
        switch vpnViewModel.connectionStatus {
        case .connected:
            connectionState = .connected
        case .connecting, .reasserting:
            connectionState = .connecting
        case .disconnected, .disconnecting, .invalid:
            connectionState = .disconnected
        @unknown default:
            connectionState = .disconnected
        }
    }
}

#Preview {
    HomeView()
}

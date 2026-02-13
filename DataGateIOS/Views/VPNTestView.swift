//
//  VPNTestView.swift
//  DataGateIOS
//
//  Test view for VPN connection using config from test-config.ovpn (in app bundle)
//

import SwiftUI
import NetworkExtension

struct VPNTestView: View {
    @State private var viewModel = VPNConnectionViewModel()
    
    var body: some View {
        VStack(spacing: 20) {
            Text("VPN Test")
                .font(.title)
                .padding()
            
            // Status
            VStack(spacing: 8) {
                Text("Status:")
                    .font(.headline)
                Text(viewModel.statusDescription)
                    .font(.title2)
                    .foregroundColor(statusColor)
            }
            .padding()
            .background(Color(.systemGray6))
            .cornerRadius(10)
            
            // Connection button
            Button(action: {
                Task {
                    if viewModel.isConnected {
                        await viewModel.disconnect()
                    } else {
                        await viewModel.connectWithTestConfig()
                    }
                }
            }) {
                HStack {
                    if viewModel.isConnecting {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    }
                    Text(viewModel.isConnected ? "Disconnect" : "Connect")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(viewModel.isConnected ? Color.red : Color.blue)
                .foregroundColor(.white)
                .cornerRadius(10)
            }
            .disabled(viewModel.isConnecting)
            
            // Error message
            if let error = viewModel.connectionError {
                Text("Error: \(error)")
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(8)
            }
            
            // Statistics
            if let stats = viewModel.statistics {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Statistics:")
                        .font(.headline)
                    Text("Bytes In: \(formatBytes(stats.bytesIn))")
                    Text("Bytes Out: \(formatBytes(stats.bytesOut))")
                    if let since = stats.connectedSince {
                        Text("Connected since: \(since, style: .relative)")
                    }
                }
                .font(.caption)
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.systemGray6))
                .cornerRadius(10)
            }
            
            Spacer()
            
            // Warning
            VStack(alignment: .leading, spacing: 4) {
                Text("⚠️ Testing Mode")
                    .font(.headline)
                    .foregroundColor(.orange)
                Text("• Works only on real device (not simulator)")
                Text("• Uses test config from file (test-config.ovpn)")
                Text("• Revoke certificates after testing")
            }
            .font(.caption)
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.1))
            .cornerRadius(8)
        }
        .padding()
        .task {
            viewModel.startObserving()
            // Update statistics periodically
            Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
                Task {
                    await viewModel.updateStatistics()
                }
            }
        }
    }
    
    private var statusColor: Color {
        switch viewModel.connectionStatus {
        case .connected:
            return .green
        case .connecting, .reasserting:
            return .orange
        case .disconnecting:
            return .yellow
        case .disconnected:
            return .gray
        default:
            return .red
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
    VPNTestView()
}

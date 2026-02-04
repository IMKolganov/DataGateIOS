//
//  StatisticsView.swift
//  DataGateIOS
//

import SwiftUI
import Charts

enum TimeRange: String, CaseIterable {
    case last24h = "Last 24h"
    case last7days = "Last 7 days"
    case last30days = "Last 30 days"
    case thisMonth = "This month"
    case lastMonth = "Last month"
    case ytd = "YTD"
    case lastYear = "Last year"
    case last3years = "Last 3 years"
    case custom = "From"
    
    var dateRange: (from: Date, to: Date) {
        let now = Date()
        let calendar = Calendar.current
        
        switch self {
        case .last24h:
            return (calendar.date(byAdding: .hour, value: -24, to: now) ?? now, now)
        case .last7days:
            return (calendar.date(byAdding: .day, value: -7, to: now) ?? now, now)
        case .last30days:
            return (calendar.date(byAdding: .day, value: -30, to: now) ?? now, now)
        case .thisMonth:
            let startOfMonth = calendar.date(from: calendar.dateComponents([.year, .month], from: now)) ?? now
            return (startOfMonth, now)
        case .lastMonth:
            let lastMonth = calendar.date(byAdding: .month, value: -1, to: now) ?? now
            let startOfLastMonth = calendar.date(from: calendar.dateComponents([.year, .month], from: lastMonth)) ?? now
            let endOfLastMonth = calendar.date(byAdding: .day, value: -1, to: startOfLastMonth) ?? now
            return (startOfLastMonth, endOfLastMonth)
        case .ytd:
            let startOfYear = calendar.date(from: calendar.dateComponents([.year], from: now)) ?? now
            return (startOfYear, now)
        case .lastYear:
            let lastYear = calendar.date(byAdding: .year, value: -1, to: now) ?? now
            let startOfLastYear = calendar.date(from: calendar.dateComponents([.year], from: lastYear)) ?? now
            let endOfLastYear = calendar.date(byAdding: .day, value: -1, to: startOfLastYear) ?? now
            return (startOfLastYear, endOfLastYear)
        case .last3years:
            return (calendar.date(byAdding: .year, value: -3, to: now) ?? now, now)
        case .custom:
            return (now, now)
        }
    }
}

struct StatisticsView: View {
    @Environment(AppState.self) private var appState
    @State private var selectedTimeRange: TimeRange = .last7days
    @State private var selectedGrouping: GetOverviewSeriesRequest.GroupingType = .auto
    @State private var customFromDate = Date()
    @State private var customToDate = Date()
    @State private var showCustomDatePicker = false
    
    @State private var overviewData: OverviewSeriesResponse?
    @State private var isLoading = false
    @State private var errorMessage: String?
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Filters
                filtersSection
                
                // Content
                if isLoading {
                    ProgressView("Loading statistics...")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let error = errorMessage {
                    ContentUnavailableView(
                        "Error",
                        systemImage: "exclamationmark.triangle",
                        description: Text(error)
                    )
                } else if let data = overviewData {
                    statisticsContent(data: data)
                } else {
                    ContentUnavailableView(
                        "No data",
                        systemImage: "chart.bar",
                        description: Text("Select filters and load statistics")
                    )
                }
            }
            .navigationTitle("Statistics")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .task {
                await loadStatistics()
            }
        }
    }
    
    private var filtersSection: some View {
        VStack(spacing: 12) {
            // Time range buttons
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(TimeRange.allCases, id: \.self) { range in
                        Button {
                            selectedTimeRange = range
                            if range == .custom {
                                showCustomDatePicker = true
                            } else {
                                Task {
                                    await loadStatistics()
                                }
                            }
                        } label: {
                            Text(range.rawValue)
                                .font(AppTypography.subheadline)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(selectedTimeRange == range ? Color.accentColor : Color(.systemGray5))
                                .foregroundColor(selectedTimeRange == range ? .white : .primary)
                                .cornerRadius(8)
                        }
                    }
                }
                .padding(.horizontal, 16)
            }
            
            // Grouping selector
            Picker("Grouping", selection: $selectedGrouping) {
                Text("Auto").tag(GetOverviewSeriesRequest.GroupingType.auto)
                Text("Hours").tag(GetOverviewSeriesRequest.GroupingType.hours)
                Text("Days").tag(GetOverviewSeriesRequest.GroupingType.days)
                Text("Months").tag(GetOverviewSeriesRequest.GroupingType.months)
                Text("Years").tag(GetOverviewSeriesRequest.GroupingType.years)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 16)
            .onChange(of: selectedGrouping) {
                Task {
                    await loadStatistics()
                }
            }
            
            // Custom date picker
            if showCustomDatePicker {
                VStack(spacing: 8) {
                    DatePicker("From", selection: $customFromDate, displayedComponents: .date)
                    DatePicker("To", selection: $customToDate, displayedComponents: .date)
                    Button("Apply") {
                        showCustomDatePicker = false
                        Task {
                            await loadStatistics()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(.horizontal, 16)
            }
        }
        .padding(.vertical, 12)
        .background(.ultraThinMaterial)
    }
    
    private func statisticsContent(data: OverviewSeriesResponse) -> some View {
        ScrollView {
            VStack(spacing: 20) {
                // Summary cards
                summaryCards(summary: data.summary)
                
                // Chart
                trafficChart(rows: data.overviewSeriesRows)
            }
            .padding(.top, 8)
            .padding(.horizontal, 16)
        }
    }
    
    private func summaryCards(summary: OverviewSummaryDto) -> some View {
        VStack(spacing: 12) {
            HStack(spacing: 12) {
                SummaryCard(
                    title: "Total In",
                    value: formatBytes(summary.totalTrafficInBytes),
                    color: .blue
                )
                SummaryCard(
                    title: "Total Out",
                    value: formatBytes(summary.totalTrafficOutBytes),
                    color: .green
                )
            }
            
            SummaryCard(
                title: "Peak Active Clients",
                value: "\(summary.peakActiveClients)",
                color: .orange
            )
        }
    }
    
    private func trafficChart(rows: [OverviewSeriesRowDto]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Traffic Over Time")
                .font(AppTypography.headline)
            
            Chart {
                ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                    if let date = row.timestamp {
                        AreaMark(
                            x: .value("Time", date),
                            y: .value("In", row.trafficInBytes)
                        )
                        .foregroundStyle(Color.blue.opacity(0.3))
                        .interpolationMethod(.catmullRom)
                        
                        AreaMark(
                            x: .value("Time", date),
                            y: .value("Out", row.trafficOutBytes)
                        )
                        .foregroundStyle(Color.green.opacity(0.3))
                        .interpolationMethod(.catmullRom)
                        
                        LineMark(
                            x: .value("Time", date),
                            y: .value("In", row.trafficInBytes)
                        )
                        .foregroundStyle(Color.blue)
                        .lineStyle(StrokeStyle(lineWidth: 2))
                        
                        LineMark(
                            x: .value("Time", date),
                            y: .value("Out", row.trafficOutBytes)
                        )
                        .foregroundStyle(Color.green)
                        .lineStyle(StrokeStyle(lineWidth: 2))
                    }
                }
            }
            .frame(height: 250)
            .chartXAxis {
                AxisMarks(values: .automatic) { _ in
                    AxisGridLine()
                    AxisValueLabel(format: .dateTime.month().day())
                }
            }
            .chartYAxis {
                AxisMarks { _ in
                    AxisGridLine()
                    AxisValueLabel(format: .byteCount(style: .binary))
                }
            }
            
            // Legend
            HStack(spacing: 20) {
                LegendItem(color: .blue, label: "In")
                LegendItem(color: .green, label: "Out")
            }
            .padding(.top, 8)
        }
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(12)
    }
    
    private func formatBytes(_ bytes: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB, .useGB, .useTB]
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: bytes)
    }
    
    @MainActor
    private func loadStatistics() async {
        guard let token = appState.bearerToken else {
            errorMessage = "Not authorized"
            return
        }
        
        guard !isLoading else { return }
        
        isLoading = true
        errorMessage = nil
        
        let dateRange = selectedTimeRange == .custom 
            ? (from: customFromDate, to: customToDate)
            : selectedTimeRange.dateRange
        
        let request = GetOverviewSeriesRequest(
            from: dateRange.from,
            to: dateRange.to,
            grouping: selectedGrouping,
            vpnServerId: nil, // No server filter for now
            externalId: appState.externalId
        )
        
        StatisticsService.shared.getOverviewSeries(
            request: request,
            authToken: token,
            appState: appState
        ) { result in
            Task { @MainActor in
                isLoading = false
                switch result {
                case .success(let response):
                    overviewData = response
                case .failure(let error):
                    errorMessage = (error as NSError).localizedDescription
                }
            }
        }
    }
}

struct SummaryCard: View {
    let title: String
    let value: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(AppTypography.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(AppTypography.headline)
                .foregroundColor(color)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(12)
    }
}

struct LegendItem: View {
    let color: Color
    let label: String
    
    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 12, height: 12)
            Text(label)
                .font(AppTypography.caption)
        }
    }
}

#Preview {
    StatisticsView()
        .environment(AppState())
}

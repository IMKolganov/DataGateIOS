//
//  MainView.swift
//  DataGateIOS
//

import SwiftUI

enum MainTab: Int, CaseIterable {
    case home = 0
    case access
    case statistics
    case settings

    var title: String {
        switch self {
        case .home: return "Home"
        case .access: return "Access"
        case .statistics: return "Statistics"
        case .settings: return "Settings"
        }
    }

    var icon: String {
        switch self {
        case .home: return "house.fill"
        case .access: return "lock.fill"
        case .statistics: return "person.fill"
        case .settings: return "gearshape.fill"
        }
    }
}

struct MainView: View {
    @State private var selectedTab: MainTab = .home

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch selectedTab {
                case .home: HomeView()
                case .access: AccessView()
                case .statistics: StatisticsView()
                case .settings: SettingsView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            
            mainTabFooter
        }
        .ignoresSafeArea(.all)
    }

    private var mainTabFooter: some View {
        VStack(spacing: 0) {
            Divider()
            
            HStack(spacing: 0) {
                ForEach(MainTab.allCases, id: \.rawValue) { tab in
                    Button {
                        selectedTab = tab
                    } label: {
                        VStack(spacing: 2) {
                            Image(systemName: tab.icon)
                                .font(.system(size: 20, weight: .medium))
                            Text(tab.title)
                                .font(AppTypography.caption)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                        .foregroundStyle(selectedTab == tab ? Color.accentColor : Color.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .frame(height: 44)
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 35)
        .background(.bar)
    }
}

#Preview {
    MainView()
        .environment(AppState())
}

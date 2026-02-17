//
//  AppTypography.swift
//  DataGateIOS
//

import SwiftUI

/// Unified typography system for the app
struct AppTypography {
    // MARK: - Font Sizes
    
    /// Large title (for main page headers)
    static let title: Font = .system(size: 20, weight: .semibold, design: .default)
    
    /// Headline (for section headers, card titles)
    static let headline: Font = .system(size: 17, weight: .semibold, design: .default)
    
    /// Body (main content text)
    static let body: Font = .system(size: 17, weight: .regular, design: .default)
    
    /// Body secondary (secondary content)
    static let bodySecondary: Font = .system(size: 15, weight: .regular, design: .default)
    
    /// Subheadline (smaller body text)
    static let subheadline: Font = .system(size: 15, weight: .medium, design: .default)
    
    /// Caption (small text, labels)
    static let caption: Font = .system(size: 12, weight: .regular, design: .default)
    
    /// Button text
    static let button: Font = .system(size: 17, weight: .semibold, design: .default)
    
    /// Button text small
    static let buttonSmall: Font = .system(size: 15, weight: .semibold, design: .default)
    
    // MARK: - Special Cases
    
    /// Large button text (for main action buttons)
    static let buttonLarge: Font = .system(size: 24, weight: .medium, design: .default)
    
    /// Status title (for connection status)
    static let statusTitle: Font = .system(size: 20, weight: .medium, design: .default)
    
    /// Status subtitle (for connection status description)
    static let statusSubtitle: Font = .system(size: 14, weight: .regular, design: .default)
}

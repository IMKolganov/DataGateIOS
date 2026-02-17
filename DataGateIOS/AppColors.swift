//
//  AppColors.swift
//  DataGateIOS
//

import SwiftUI

struct AppColors {
    // Light theme colors
    static let purple40 = Color(red: 0x66/255.0, green: 0x50/255.0, blue: 0xa4/255.0) // #6650a4
    static let pink40 = Color(red: 0x7D/255.0, green: 0x52/255.0, blue: 0x60/255.0) // #7D5260
    
    // Dark theme colors
    static let purple80 = Color(red: 0xD0/255.0, green: 0xBC/255.0, blue: 0xFF/255.0) // #D0BCFF
    static let pink80 = Color(red: 0xEF/255.0, green: 0xB8/255.0, blue: 0xC8/255.0) // #EFB8C8
    
    // Error color (for disconnected state)
    static var error: Color {
        Color.red
    }
    
    // Get primary color based on color scheme
    static func primary(for colorScheme: ColorScheme?) -> Color {
        colorScheme == .dark ? purple80 : purple40
    }
    
    // Get tertiary color based on color scheme (for connecting state)
    static func tertiary(for colorScheme: ColorScheme?) -> Color {
        colorScheme == .dark ? pink80 : pink40
    }
}

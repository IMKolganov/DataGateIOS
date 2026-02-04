//
//  APIConfig.swift
//  DataGateIOS
//

import Foundation

enum APIConfig {
    private static var config: NSDictionary? {
        guard let configPath = Bundle.main.path(forResource: "Config", ofType: "plist") else {
            return nil
        }
        return NSDictionary(contentsOfFile: configPath)
    }
    
    static var baseURL: URL {
        guard let config = config,
              let urlString = config["APIBaseURL"] as? String,
              let url = URL(string: urlString) else {
            fatalError("⚠️ Config.plist not found or APIBaseURL is missing. Please copy Config.example.plist to Config.plist and fill in your values.")
        }
        return url
    }
    
    static var googleClientID: String? {
        guard let config = config else { return nil }
        return config["GIDClientID"] as? String
    }
}

//
//  ExtensionLogBridge.h
//  DataGateVPNExtension
//
//  C bridge for saving logs from C++ code to UserDefaults
//  This allows C++ code (like load_ca, parse) to save logs that will be visible in the app
//

#ifndef ExtensionLogBridge_h
#define ExtensionLogBridge_h

#ifdef __cplusplus
extern "C" {
#endif

// Save log message to UserDefaults (will be visible in app)
// level: "INFO", "WARNING", "ERROR", etc.
// message: log message (will be truncated if too long)
void saveLogToUserDefaults(const char* level, const char* message);

#ifdef __cplusplus
}
#endif

#endif /* ExtensionLogBridge_h */

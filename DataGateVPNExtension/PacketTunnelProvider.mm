//
//  PacketTunnelProvider.mm
//  DataGateVPNExtension
//
//  Objective-C++ implementation for OpenVPN3 integration
//

// Suppress warnings from external libraries (mbedtls, asio, openvpn3)
// These are documentation warnings and deprecation warnings that we cannot fix
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wdocumentation-deprecated-sync"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wmacro-redefined"

#import "PacketTunnelProvider.h"
#import "OpenVPNAdapter.h"
#import <NetworkExtension/NetworkExtension.h>
#import <signal.h>
#import <execinfo.h>
#import <Foundation/Foundation.h>

// PSA Crypto initialization for mbedTLS 3.6+ (required for TLS 1.3)
// CRITICAL: Include build_info.h to get MBEDTLS_VERSION_NUMBER
#include <mbedtls/build_info.h>
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
#include <psa/crypto.h>
#endif

// Global error storage key for UserDefaults
static NSString *const kExtensionErrorKey = @"DataGateVPNExtension.LastError";
static NSString *const kExtensionCrashKey = @"DataGateVPNExtension.LastCrash";
static NSString *const kExtensionLogsKey = @"DataGateVPNExtension.Logs";
static const NSUInteger kMaxLogEntries = 100; // Keep last 100 log entries

// Global exception handler for C++ exceptions
// Note: Currently unused but kept for potential future use
__attribute__((unused)) static void cpp_exception_handler() {
    @try {
        NSLog(@"❌ [PacketTunnel] FATAL: Uncaught C++ exception detected!");
        NSString *errorMsg = @"Uncaught C++ exception - Extension may crash";
        NSDictionary *errorDict = @{
            @"domain": @"PacketTunnelProvider",
            @"code": @(9999),
            @"description": errorMsg,
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        [[NSUserDefaults standardUserDefaults] setObject:errorDict forKey:kExtensionCrashKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        // Try to log stack trace
        void *callstack[128];
        int frames = backtrace(callstack, 128);
        char **symbols = backtrace_symbols(callstack, frames);
        NSMutableString *stackTrace = [NSMutableString string];
        for (int i = 0; i < frames; i++) {
            [stackTrace appendFormat:@"%s\n", symbols[i]];
        }
        free(symbols);
        NSLog(@"❌ [PacketTunnel] Stack trace:\n%@", stackTrace);
    } @catch (...) {
        // If even error handling fails, at least try to log
        printf("[PacketTunnel] FATAL: Even error handler failed!\n");
    }
}

// Signal handler for critical signals
static void signal_handler(int sig) {
    @try {
        NSString *signalName = @"Unknown";
        switch (sig) {
            case SIGABRT: signalName = @"SIGABRT"; break;
            case SIGSEGV: signalName = @"SIGSEGV"; break;
            case SIGBUS: signalName = @"SIGBUS"; break;
            case SIGILL: signalName = @"SIGILL"; break;
            case SIGFPE: signalName = @"SIGFPE"; break;
            default: break;
        }
        
        NSLog(@"❌ [PacketTunnel] FATAL: Signal %@ (%d) received!", signalName, sig);
        NSString *errorMsg = [NSString stringWithFormat:@"Extension crashed with signal %@ (%d)", signalName, sig];
        
        NSDictionary *errorDict = @{
            @"domain": @"PacketTunnelProvider",
            @"code": @(10000 + sig),
            @"description": errorMsg,
            @"signal": signalName,
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        [[NSUserDefaults standardUserDefaults] setObject:errorDict forKey:kExtensionCrashKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        // Log stack trace
        void *callstack[128];
        int frames = backtrace(callstack, 128);
        char **symbols = backtrace_symbols(callstack, frames);
        NSMutableString *stackTrace = [NSMutableString string];
        for (int i = 0; i < frames; i++) {
            [stackTrace appendFormat:@"%s\n", symbols[i]];
        }
        free(symbols);
        NSLog(@"❌ [PacketTunnel] Stack trace:\n%@", stackTrace);
        
        // CRITICAL: Save stack trace to UserDefaults so it's visible in app logs
        NSMutableDictionary *crashDictWithStackTrace = [errorDict mutableCopy];
        crashDictWithStackTrace[@"stackTrace"] = stackTrace;
        [[NSUserDefaults standardUserDefaults] setObject:crashDictWithStackTrace forKey:kExtensionCrashKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        // Also save to logs array for visibility
        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:kExtensionLogsKey] mutableCopy] ?: [NSMutableArray array];
        [logs addObject:@{
            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
            @"level": @"ERROR",
            @"message": [NSString stringWithFormat:@"[CRASH] Signal %@ received! Stack trace:\n%@", signalName, stackTrace]
        }];
        if (logs.count > 200) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 200)]; }
        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:kExtensionLogsKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
    } @catch (...) {
        printf("[PacketTunnel] FATAL: Signal handler failed!\n");
    }
    
    // Re-raise signal to get default behavior (crash report)
    signal(sig, SIG_DFL);
    raise(sig);
}

// Uncaught exception handler for Objective-C exceptions
static void uncaught_exception_handler(NSException *exception) {
    @try {
        NSLog(@"❌ [PacketTunnel] FATAL: Uncaught Objective-C exception: %@", exception);
        NSLog(@"❌ [PacketTunnel] Reason: %@", exception.reason);
        NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
        
        NSDictionary *errorDict = @{
            @"domain": @"PacketTunnelProvider",
            @"code": @(10001),
            @"description": [NSString stringWithFormat:@"Uncaught exception: %@", exception.reason],
            @"exceptionName": exception.name ?: @"Unknown",
            @"stackTrace": exception.callStackSymbols ?: @[],
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        [[NSUserDefaults standardUserDefaults] setObject:errorDict forKey:kExtensionCrashKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
    } @catch (...) {
        printf("[PacketTunnel] FATAL: Exception handler failed!\n");
    }
}

// Setup global handlers - called on library load
__attribute__((constructor))
static void setup_global_handlers() {
    printf("[PacketTunnel] Setting up global exception and signal handlers...\n");
    NSLog(@"🔧 [PacketTunnel] Setting up global exception and signal handlers...");
    
    // Set up signal handlers for critical signals
    signal(SIGABRT, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGBUS, signal_handler);
    signal(SIGILL, signal_handler);
    signal(SIGFPE, signal_handler);
    
    // Set up uncaught exception handler
    NSSetUncaughtExceptionHandler(&uncaught_exception_handler);
    
    NSLog(@"✅ [PacketTunnel] Global handlers installed");
}

// Log immediately when extension loads - this should be FIRST thing to execute
__attribute__((constructor))
static void extension_loaded() {
    // Use printf first in case NSLog isn't initialized yet
    
    // Check if Address Sanitizer is enabled
    #if __has_feature(address_sanitizer)
        printf("[PacketTunnel] ✅ Address Sanitizer (ASAN) is ENABLED\n");
        NSLog(@"✅ [PacketTunnel] Address Sanitizer (ASAN) is ENABLED");
    #else
        printf("[PacketTunnel] ⚠️ Address Sanitizer (ASAN) is NOT enabled\n");
        NSLog(@"⚠️ [PacketTunnel] Address Sanitizer (ASAN) is NOT enabled");
    #endif
    
    // Check if Thread Sanitizer is enabled
    #if __has_feature(thread_sanitizer)
        printf("[PacketTunnel] ✅ Thread Sanitizer (TSAN) is ENABLED\n");
        NSLog(@"✅ [PacketTunnel] Thread Sanitizer (TSAN) is ENABLED");
    #endif
    printf("[PacketTunnel] Extension binary loaded!\n");
    printf("[PacketTunnel] Extension constructor called\n");
    NSLog(@"🔧 [PacketTunnel] Extension binary loaded!");
    NSLog(@"🔧 [PacketTunnel] Extension constructor called");
    NSLog(@"🔧 [PacketTunnel] Extension path: %@", [[NSBundle mainBundle] bundlePath]);
    NSLog(@"🔧 [PacketTunnel] Extension bundle ID: %@", [[NSBundle mainBundle] bundleIdentifier]);
}

@interface PacketTunnelProvider () <OpenVPNAdapterDelegate>
@property (nonatomic, strong) NSTimer *reconnectTimer;
@property (nonatomic, assign) BOOL isConnected;
@property (nonatomic, strong) OpenVPNAdapter *openVPNAdapter;
@property (nonatomic, copy) void (^startCompletionHandler)(NSError *);
@property (nonatomic, strong) NSError *lastError; // Store last error for app messages
@property (nonatomic, strong) NSTimer *watchdogTimer; // Timer to ensure Extension stays alive
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *logEntries; // Store log entries for debugging
@end

@implementation PacketTunnelProvider

- (instancetype)init {
    printf("[PacketTunnel] init() called\n");
    NSLog(@"🔧 [PacketTunnel] init() called");
    
    // CRITICAL: Log mbedTLS version for debugging
    printf("[PacketTunnel] mbedTLS version check: MBEDTLS_VERSION_NUMBER = 0x%08X\n", MBEDTLS_VERSION_NUMBER);
    NSLog(@"🔧 [PacketTunnel] mbedTLS version: 0x%08X (string: %s)", MBEDTLS_VERSION_NUMBER, MBEDTLS_VERSION_STRING);
    
    @try {
        self = [super init];
        if (self) {
            self.logEntries = [NSMutableArray array];
            
            // CRITICAL: Initialize PSA Crypto for mbedTLS 3.6+ (required for TLS 1.3)
            // Must be done BEFORE any mbedTLS operations
            // NOTE: Do this AFTER self.logEntries is initialized so we can log it
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
            [self addLogEntry:[NSString stringWithFormat:@"mbedTLS version: 0x%08X (%s)", MBEDTLS_VERSION_NUMBER, MBEDTLS_VERSION_STRING] level:@"INFO"];
            [self addLogEntry:@"mbedTLS version >= 3.6.0, initializing PSA Crypto..." level:@"INFO"];
            
            static bool psa_initialized = false;
            if (!psa_initialized) {
                [self addLogEntry:@"🔐 Initializing PSA Crypto for mbedTLS 3.6+..." level:@"INFO"];
                printf("[PacketTunnel] 🔐 Initializing PSA Crypto for mbedTLS 3.6+...\n");
                NSLog(@"🔐 [PacketTunnel] Initializing PSA Crypto for mbedTLS 3.6+...");
                
                psa_status_t status = psa_crypto_init();
                if (status == PSA_SUCCESS) {
                    [self addLogEntry:@"✅ PSA Crypto initialized successfully" level:@"INFO"];
                    printf("[PacketTunnel] ✅ PSA Crypto initialized successfully\n");
                    NSLog(@"✅ [PacketTunnel] PSA Crypto initialized successfully");
                    psa_initialized = true;
                } else {
                    [self addLogEntry:[NSString stringWithFormat:@"⚠️ PSA Crypto init returned: %d", (int)status] level:@"WARNING"];
                    printf("[PacketTunnel] ⚠️ PSA Crypto init returned: %d\n", (int)status);
                    NSLog(@"⚠️ [PacketTunnel] PSA Crypto init returned: %d", (int)status);
                }
            } else {
                [self addLogEntry:@"ℹ️ PSA Crypto already initialized" level:@"INFO"];
                printf("[PacketTunnel] ℹ️ PSA Crypto already initialized\n");
                NSLog(@"ℹ️ [PacketTunnel] PSA Crypto already initialized");
            }
#else
            [self addLogEntry:[NSString stringWithFormat:@"⚠️ mbedTLS version < 3.6.0 (0x%08X), PSA Crypto init not required", MBEDTLS_VERSION_NUMBER] level:@"INFO"];
            printf("[PacketTunnel] ⚠️ mbedTLS version < 3.6.0 (0x%08X), PSA Crypto init not required\n", MBEDTLS_VERSION_NUMBER);
            NSLog(@"⚠️ [PacketTunnel] mbedTLS version < 3.6.0 (0x%08X), PSA Crypto init not required", MBEDTLS_VERSION_NUMBER);
#endif
            
            // Save logs immediately so PSA init logs are preserved
            [self saveLogsToUserDefaults];
            
            printf("[PacketTunnel] init() completed successfully\n");
            NSLog(@"🔧 [PacketTunnel] init() completed successfully");
            NSLog(@"🔧 [PacketTunnel] self: %p", self);
            [self addLogEntry:@"Extension initialized" level:@"INFO"];
        } else {
            printf("[PacketTunnel] init() FAILED - self is nil!\n");
            NSLog(@"❌ [PacketTunnel] init() FAILED - self is nil!");
        }
    } @catch (NSException *exception) {
        printf("[PacketTunnel] init() EXCEPTION: %s\n", exception.reason.UTF8String);
        NSLog(@"❌ [PacketTunnel] init() EXCEPTION: %@", exception);
        NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
    }
    return self;
}

- (void)addLogEntry:(NSString *)message level:(NSString *)level {
    @synchronized(self.logEntries) {
        NSDictionary *entry = @{
            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
            @"level": level ?: @"INFO",
            @"message": message ?: @""
        };
        [self.logEntries addObject:entry];
        
        // Keep only last kMaxLogEntries entries
        if (self.logEntries.count > kMaxLogEntries) {
            [self.logEntries removeObjectAtIndex:0];
        }
        
        // Save to UserDefaults immediately for critical logs, periodically for others
        if ([level isEqualToString:@"ERROR"] || [level isEqualToString:@"WARNING"] || self.logEntries.count % 5 == 0) {
            [self saveLogsToUserDefaults];
        }
    }
}

- (void)saveLogsToUserDefaults {
    @synchronized(self.logEntries) {
        // CRITICAL: Merge with existing logs from UserDefaults (includes logs from OpenVPNAdapter)
        NSArray *existingLogs = [[NSUserDefaults standardUserDefaults] objectForKey:kExtensionLogsKey];
        NSMutableArray *allLogs = existingLogs ? [existingLogs mutableCopy] : [NSMutableArray array];
        
        // Add current logEntries, avoiding duplicates
        NSMutableSet *existingKeys = [NSMutableSet set];
        for (NSDictionary *log in allLogs) {
            NSString *key = [NSString stringWithFormat:@"%@_%@", log[@"timestamp"], log[@"message"]];
            [existingKeys addObject:key];
        }
        
        for (NSDictionary *log in self.logEntries) {
            NSString *key = [NSString stringWithFormat:@"%@_%@", log[@"timestamp"], log[@"message"]];
            if (![existingKeys containsObject:key]) {
                [allLogs addObject:log];
                [existingKeys addObject:key];
            }
        }
        
        // Sort by timestamp
        [allLogs sortUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
            NSNumber *ts1 = obj1[@"timestamp"];
            NSNumber *ts2 = obj2[@"timestamp"];
            return [ts1 compare:ts2];
        }];
        
        // Keep only last 200 entries (increased to match saveLogToUserDefaults limit)
        // This ensures we don't lose logs from OpenVPNAdapter
        if (allLogs.count > 200) {
            [allLogs removeObjectsInRange:NSMakeRange(0, allLogs.count - 200)];
        }
        
        printf("[PacketTunnel] Saving %zu log entries to UserDefaults (merged with %zu existing)\n", 
               (size_t)self.logEntries.count, (size_t)(existingLogs ? existingLogs.count : 0));
        [[NSUserDefaults standardUserDefaults] setObject:allLogs forKey:kExtensionLogsKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        printf("[PacketTunnel] Logs saved successfully (total: %zu entries)\n", (size_t)allLogs.count);
    }
}

- (void)startTunnelWithOptions:(NSDictionary<NSString *,NSObject *> *)options 
              completionHandler:(void (^)(NSError *))completionHandler {
    
    // CRITICAL: Log immediately using printf (works even if NSLog fails)
    printf("========================================\n");
    printf("[PacketTunnel] ====== START TUNNEL CALLED ======\n");
    printf("[PacketTunnel] Timestamp: %s\n", [[NSDate date].description UTF8String]);
    printf("[PacketTunnel] self: %p\n", (__bridge void *)self);
    printf("[PacketTunnel] Thread: %s\n", [[NSThread currentThread].description UTF8String]);
    printf("========================================\n");
    
    @try {
        NSLog(@"🚀 [PacketTunnel] ====== START TUNNEL CALLED ======");
        NSLog(@"🚀 [PacketTunnel] Extension is launching!");
        NSLog(@"🚀 [PacketTunnel] Options: %@", options);
        NSLog(@"🚀 [PacketTunnel] self: %p", self);
        NSLog(@"🚀 [PacketTunnel] Thread: %@", [NSThread currentThread]);
        [self addLogEntry:@"startTunnelWithOptions called" level:@"INFO"];
        [self addLogEntry:[NSString stringWithFormat:@"Options keys: %@", [options allKeys]] level:@"INFO"];
        
        // CRITICAL: Save logs immediately to UserDefaults so they're available even if Extension crashes
        [self saveLogsToUserDefaults];
        printf("[PacketTunnel] Logs saved to UserDefaults immediately after startTunnelWithOptions\n");
        
        // Get configuration from providerConfiguration
        NETunnelProviderProtocol *protocol = (NETunnelProviderProtocol *)self.protocolConfiguration;
        if (!protocol) {
            NSLog(@"❌ [PacketTunnel] ERROR: Protocol configuration not found");
            NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                 code:1 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Protocol configuration not found"}];
            completionHandler(error);
            return;
        }
        NSLog(@"✅ [PacketTunnel] Protocol configuration found");
        
        NSDictionary *config = protocol.providerConfiguration;
        if (!config) {
            NSLog(@"❌ [PacketTunnel] ERROR: Provider configuration not found");
            NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                 code:2 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Provider configuration not found"}];
            completionHandler(error);
            return;
        }
        NSLog(@"✅ [PacketTunnel] Provider configuration found");
        
        NSString *configContent = config[@"config"];
        NSString *server = config[@"server"];
        NSNumber *port = config[@"port"];
        
        if (!configContent || configContent.length == 0) {
            NSLog(@"❌ [PacketTunnel] ERROR: Config content is empty or nil!");
            NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                 code:2 
                                             userInfo:@{NSLocalizedDescriptionKey: @"OpenVPN config content is missing"}];
            self.lastError = error;
            completionHandler(error);
            return;
        }
        
        NSLog(@"🚀 [PacketTunnel] Starting tunnel with server: %@:%@", server, port);
        NSLog(@"🚀 [PacketTunnel] Config content length: %lu bytes", (unsigned long)configContent.length);
        [self addLogEntry:[NSString stringWithFormat:@"Config length: %lu bytes", (unsigned long)configContent.length] level:@"INFO"];
        NSLog(@"🚀 [PacketTunnel] Config preview (first 500 chars):\n%@", 
              [configContent substringToIndex:MIN(500, configContent.length)]);
        
        // Verify config structure before proceeding
        NSRange caRange = [configContent rangeOfString:@"<ca>"];
        NSRange caEndRange = [configContent rangeOfString:@"</ca>"];
        NSRange certRange = [configContent rangeOfString:@"<cert>"];
        NSRange certEndRange = [configContent rangeOfString:@"</cert>"];
        NSRange keyRange = [configContent rangeOfString:@"<key>"];
        NSRange keyEndRange = [configContent rangeOfString:@"</key>"];
        NSRange tlsCryptRange = [configContent rangeOfString:@"<tls-crypt>"];
        NSRange tlsCryptEndRange = [configContent rangeOfString:@"</tls-crypt>"];
        
        BOOL hasCA = caRange.location != NSNotFound && caEndRange.location != NSNotFound;
        BOOL hasCert = certRange.location != NSNotFound && certEndRange.location != NSNotFound;
        BOOL hasKey = keyRange.location != NSNotFound && keyEndRange.location != NSNotFound;
        BOOL hasTlsCrypt = tlsCryptRange.location != NSNotFound && tlsCryptEndRange.location != NSNotFound;
        
        NSLog(@"🔍 [PacketTunnel] Config structure verification:");
        NSLog(@"   <ca>: %@ (pos: %lu-%lu)", hasCA ? @"YES" : @"NO", 
              (unsigned long)caRange.location, (unsigned long)caEndRange.location);
        NSLog(@"   <cert>: %@ (pos: %lu-%lu)", hasCert ? @"YES" : @"NO", 
              (unsigned long)certRange.location, (unsigned long)certEndRange.location);
        NSLog(@"   <key>: %@ (pos: %lu-%lu)", hasKey ? @"YES" : @"NO", 
              (unsigned long)keyRange.location, (unsigned long)keyEndRange.location);
        NSLog(@"   <tls-crypt>: %@ (pos: %lu-%lu)", hasTlsCrypt ? @"YES" : @"NO", 
              (unsigned long)tlsCryptRange.location, (unsigned long)tlsCryptEndRange.location);
        
        [self addLogEntry:[NSString stringWithFormat:@"Config structure: <ca>=%@, <cert>=%@, <key>=%@, <tls-crypt>=%@", 
                           hasCA ? @"YES" : @"NO",
                           hasCert ? @"YES" : @"NO",
                           hasKey ? @"YES" : @"NO",
                           hasTlsCrypt ? @"YES" : @"NO"] level:@"INFO"];
        
        if (!hasCA || !hasCert || !hasKey) {
            NSString *errorMsg = [NSString stringWithFormat:@"Missing required config sections: <ca>=%@, <cert>=%@, <key>=%@", 
                                   hasCA ? @"YES" : @"NO",
                                   hasCert ? @"YES" : @"NO",
                                   hasKey ? @"YES" : @"NO"];
            NSLog(@"❌ [PacketTunnel] %@", errorMsg);
            [self addLogEntry:errorMsg level:@"ERROR"];
            NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                 code:4 
                                             userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
            self.lastError = error;
            [self saveErrorToUserDefaults:error];
            completionHandler(error);
            return;
        }
        
        // Check for CA certificate in config
        if (hasCA) {
            NSRange certSectionRange = NSMakeRange(caRange.location, caEndRange.location + caEndRange.length - caRange.location);
            NSString *caSection = [configContent substringWithRange:certSectionRange];
            NSLog(@"✅ [PacketTunnel] Found CA section: %lu bytes", (unsigned long)caSection.length);
            
            NSRange certStartRange = [caSection rangeOfString:@"-----BEGIN CERTIFICATE-----"];
            NSRange certEndRange = [caSection rangeOfString:@"-----END CERTIFICATE-----"];
            if (certStartRange.location != NSNotFound && certEndRange.location != NSNotFound) {
                NSRange certContentRange = NSMakeRange(certStartRange.location, 
                                                       certEndRange.location + certEndRange.length - certStartRange.location);
                NSString *caCert = [caSection substringWithRange:certContentRange];
                NSLog(@"✅ [PacketTunnel] CA certificate found: %lu bytes", (unsigned long)caCert.length);
                [self addLogEntry:[NSString stringWithFormat:@"CA cert found: %lu bytes", (unsigned long)caCert.length] level:@"INFO"];
                NSLog(@"🚀 [PacketTunnel] CA cert full content:\n%@", caCert);
                
                // Log full CA cert
                [self addLogEntry:[NSString stringWithFormat:@"CA cert full content (%lu bytes):\n%@", (unsigned long)caCert.length, caCert] level:@"INFO"];
            } else {
                NSLog(@"⚠️ [PacketTunnel] CA section found but certificate markers not found");
                [self addLogEntry:@"CA section found but certificate markers not found" level:@"WARNING"];
            }
        }
        
        // Store completion handler FIRST before any async operations
        self.startCompletionHandler = completionHandler;
        
        // Initialize OpenVPN3 adapter
        NSLog(@"🔧 [PacketTunnel] Initializing OpenVPNAdapter...");
        @try {
            if (!self.openVPNAdapter) {
                NSLog(@"🔧 [PacketTunnel] Creating new OpenVPNAdapter instance...");
                self.openVPNAdapter = [[OpenVPNAdapter alloc] init];
                NSLog(@"🔧 [PacketTunnel] OpenVPNAdapter created: %p", self.openVPNAdapter);
                self.openVPNAdapter.delegate = self;
                NSLog(@"🔧 [PacketTunnel] Delegate set");
                // CRITICAL: Set packetFlow so tun_builder_establish can get file descriptor
                self.openVPNAdapter.packetFlow = self.packetFlow;
                NSLog(@"🔧 [PacketTunnel] packetFlow set on adapter");
            } else {
                NSLog(@"🔧 [PacketTunnel] Using existing OpenVPNAdapter: %p", self.openVPNAdapter);
                // Ensure packetFlow is set
                if (!self.openVPNAdapter.packetFlow) {
                    self.openVPNAdapter.packetFlow = self.packetFlow;
                    NSLog(@"🔧 [PacketTunnel] packetFlow set on existing adapter");
                }
            }
        } @catch (NSException *exception) {
            NSLog(@"❌ [PacketTunnel] EXCEPTION creating OpenVPNAdapter: %@", exception);
            NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
            NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                 code:3 
                                             userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to create OpenVPNAdapter: %@", exception.reason]}];
            self.lastError = error;
            completionHandler(error);
            return;
        }
        
        NSLog(@"✅ [PacketTunnel] OpenVPNAdapter initialized successfully");
        [self addLogEntry:@"OpenVPNAdapter initialized successfully" level:@"INFO"];
        [self saveLogsToUserDefaults];
        
        // Configure basic tunnel network settings (will be updated by OpenVPN3)
        NSLog(@"🔧 [PacketTunnel] Configuring tunnel network settings...");
        printf("[PacketTunnel] ====== CALLING configureTunnelSettings ======\n");
        [self addLogEntry:@"Configuring tunnel network settings..." level:@"INFO"];
        [self saveLogsToUserDefaults];
        
        [self configureTunnelSettingsWithCompletion:^(NSError *error) {
            printf("[PacketTunnel] ====== configureTunnelSettings COMPLETION CALLED ======\n");
            if (error) {
                printf("[PacketTunnel] Error: %s\n", [error.localizedDescription UTF8String]);
            } else {
                printf("[PacketTunnel] Error: nil\n");
            }
            
            @try {
                if (error) {
                    NSLog(@"❌ [PacketTunnel] Error configuring tunnel: %@", error.localizedDescription);
                    [self addLogEntry:[NSString stringWithFormat:@"Error configuring tunnel: %@", error.localizedDescription] level:@"ERROR"];
                    [self saveLogsToUserDefaults];
                    if (self.startCompletionHandler) {
                        self.startCompletionHandler(error);
                        self.startCompletionHandler = nil;
                    }
                    return;
                }
                
                NSLog(@"✅ [PacketTunnel] Tunnel network settings configured");
                printf("[PacketTunnel] ✅ Tunnel network settings configured\n");
                [self addLogEntry:@"Tunnel network settings configured" level:@"INFO"];
                [self saveLogsToUserDefaults];
                
                NSLog(@"🔧 [PacketTunnel] Starting packet reading...");
                [self addLogEntry:@"Starting packet reading..." level:@"INFO"];
                [self saveLogsToUserDefaults];
                
                // CRITICAL: DO NOT call startReadingPackets here!
                // OpenVPNAdapter.startReadingFromPacketFlow() already calls readPacketsWithCompletionHandler
                // Calling both will cause a conflict where only one handler can be active
                NSLog(@"⚠️ [PacketTunnel] SKIPPING startReadingPackets - OpenVPNAdapter handles packet reading");
                [self addLogEntry:@"SKIPPING startReadingPackets - OpenVPNAdapter handles packet reading" level:@"WARNING"];
                // [self startReadingPackets]; // DISABLED - causes conflict with OpenVPNAdapter
                
                NSLog(@"🔧 [PacketTunnel] Starting OpenVPN3 connection...");
                NSLog(@"🔧 [PacketTunnel] Config content preview (first 200 chars): %@", 
                      [configContent substringToIndex:MIN(200, configContent.length)]);
                [self addLogEntry:[NSString stringWithFormat:@"Config preview (first 200): %@", 
                                   [configContent substringToIndex:MIN(200, configContent.length)]] level:@"INFO"];
                
                // Log sections with certificates to show where they are in config
                if (hasCA && caRange.location != NSNotFound) {
                    NSInteger caStart = MAX(0, (NSInteger)caRange.location - 30);
                    NSInteger caLength = MIN(400, configContent.length - caStart);
                    NSString *caSectionPreview = [configContent substringWithRange:NSMakeRange(caStart, caLength)];
                    NSLog(@"🔍 [PacketTunnel] Config around <ca> section (pos %lu):\n%@", 
                          (unsigned long)caRange.location, caSectionPreview);
                    [self addLogEntry:[NSString stringWithFormat:@"Config around <ca> (pos %lu, %lu bytes): %@", 
                                       (unsigned long)caRange.location, (unsigned long)caLength, caSectionPreview] level:@"INFO"];
                }
                if (hasCert && certRange.location != NSNotFound) {
                    NSInteger certStart = MAX(0, (NSInteger)certRange.location - 30);
                    NSInteger certLength = MIN(400, configContent.length - certStart);
                    NSString *certSectionPreview = [configContent substringWithRange:NSMakeRange(certStart, certLength)];
                    NSLog(@"🔍 [PacketTunnel] Config around <cert> section (pos %lu):\n%@", 
                          (unsigned long)certRange.location, certSectionPreview);
                    [self addLogEntry:[NSString stringWithFormat:@"Config around <cert> (pos %lu, %lu bytes): %@", 
                                       (unsigned long)certRange.location, (unsigned long)certLength, certSectionPreview] level:@"INFO"];
                }
                
                // Start OpenVPN3 connection with config
                @try {
                    [self addLogEntry:@"Step: Starting OpenVPN3 adapter" level:@"INFO"];
                    NSLog(@"🔧 [PacketTunnel] Calling openVPNAdapter.startWithConfig...");
                    [self addLogEntry:@"Calling openVPNAdapter.startWithConfig" level:@"INFO"];
                    [self saveLogsToUserDefaults]; // Save before calling OpenVPN3
                    
                    printf("========================================\n");
                    printf("[PacketTunnel] ====== CALLING startWithConfig ======\n");
                    printf("[PacketTunnel] Config length: %lu bytes\n", (unsigned long)configContent.length);
                    printf("[PacketTunnel] OpenVPNAdapter: %p\n", (__bridge void *)self.openVPNAdapter);
                    printf("========================================\n");
                    
                    [self.openVPNAdapter startWithConfig:configContent];
                    
                    printf("[PacketTunnel] ====== startWithConfig RETURNED ======\n");
                    NSLog(@"✅ [PacketTunnel] OpenVPN3 start command sent (async, will continue in background thread)");
                    [self addLogEntry:@"OpenVPN3 start command sent successfully (async)" level:@"INFO"];
                    [self saveLogsToUserDefaults]; // Save after calling OpenVPN3
                    
                    // CRITICAL: Check if logs from OpenVPNAdapter appeared
                    NSArray *logsAfter = [[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"];
                    NSLog(@"📊 [PacketTunnel] Logs count after startWithConfig: %lu", (unsigned long)logsAfter.count);
                    if (logsAfter.count > 0) {
                        NSDictionary *lastLog = logsAfter.lastObject;
                        NSLog(@"📊 [PacketTunnel] Last log: %@", lastLog);
                    }
                    
                    // Start watchdog timer to ensure Extension stays alive and can report errors
                    [self addLogEntry:@"Starting watchdog timer" level:@"INFO"];
                    [self startWatchdogTimer];
                    [self addLogEntry:@"Watchdog timer started" level:@"INFO"];
                } @catch (NSException *exception) {
                    NSString *errorMsg = [NSString stringWithFormat:@"EXCEPTION starting OpenVPN3: %@", exception.reason];
                    NSLog(@"❌ [PacketTunnel] %@", errorMsg);
                    NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
                    [self addLogEntry:errorMsg level:@"ERROR"];
                    [self addLogEntry:[NSString stringWithFormat:@"Stack trace: %@", exception.callStackSymbols] level:@"ERROR"];
                    NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                         code:6 
                                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to start OpenVPN3: %@", exception.reason]}];
                    [self saveErrorToUserDefaults:error];
                    self.lastError = error;
                    [self saveLogsToUserDefaults];
                    if (self.startCompletionHandler) {
                        self.startCompletionHandler(error);
                        self.startCompletionHandler = nil;
                    }
                    return;
                }
                
                // Note: completionHandler will be called in openVPNAdapterDidConnect: or didFailWithError:
            } @catch (NSException *exception) {
                NSLog(@"❌ [PacketTunnel] EXCEPTION in configureTunnelSettings completion: %@", exception);
                NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
                if (self.startCompletionHandler) {
                    NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                         code:4 
                                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Exception: %@", exception.reason]}];
                    self.startCompletionHandler(error);
                    self.startCompletionHandler = nil;
                }
            }
        }];
    } @catch (NSException *exception) {
        printf("[PacketTunnel] FATAL EXCEPTION in startTunnelWithOptions: %s\n", exception.reason.UTF8String);
        NSLog(@"❌ [PacketTunnel] FATAL EXCEPTION in startTunnelWithOptions: %@", exception);
        NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
        NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                             code:999 
                                         userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Fatal exception: %@", exception.reason]}];
        completionHandler(error);
    }
}

- (void)startReadingPackets {
    NSLog(@"[PacketTunnel] 📥 Starting to read packets from packetFlow...");
    NSLog(@"[PacketTunnel] ⚠️ WARNING: This may conflict with OpenVPNAdapter's readPacketsWithCompletionHandler!");
    
    // Read packets from tunnel and forward to OpenVPN3
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        NSLog(@"[PacketTunnel] 📥 PacketTunnelProvider's readPackets handler ENTERED with %lu packet(s)", (unsigned long)packets.count);
        @try {
            NSLog(@"[PacketTunnel] 📦 Received %lu packets from iOS", (unsigned long)packets.count);
            
            for (NSUInteger i = 0; i < packets.count; i++) {
                @try {
                    NSData *packetData = packets[i];
                    NSNumber *protocol = i < protocols.count ? protocols[i] : @(AF_INET);
                    NSLog(@"[PacketTunnel] 📦 Packet[%lu]: %lu bytes, protocol: %@", 
                          (unsigned long)i, (unsigned long)packetData.length, protocol);
                    
                    // Forward packet to OpenVPN3
                    if (self.openVPNAdapter) {
                        [self.openVPNAdapter handlePacketFromTunnel:packetData];
                    } else {
                        NSLog(@"⚠️ [PacketTunnel] Cannot forward packet - OpenVPNAdapter is nil");
                    }
                } @catch (NSException *exception) {
                    NSLog(@"❌ [PacketTunnel] EXCEPTION processing packet[%lu]: %@", (unsigned long)i, exception);
                    NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
                    NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                         code:7 
                                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Error processing packet: %@", exception.reason]}];
                    self.lastError = error;
                    // Continue reading despite error
                }
            }
            
            // Continue reading
            [self startReadingPackets];
        } @catch (NSException *exception) {
            NSLog(@"❌ [PacketTunnel] FATAL EXCEPTION in packet reading completion handler: %@", exception);
            NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
            NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                 code:8 
                                             userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Fatal error in packet reading: %@", exception.reason]}];
            self.lastError = error;
            // Don't continue reading if fatal error occurred
        }
    }];
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason 
            completionHandler:(void (^)(void))completionHandler {
    
    NSLog(@"[PacketTunnel] Stopping tunnel. Reason: %ld", (long)reason);
    
    // Disconnect OpenVPN3
    if (self.openVPNAdapter) {
        NSLog(@"[PacketTunnel] Stopping OpenVPNAdapter...");
        [self.openVPNAdapter stop];
        self.openVPNAdapter = nil;
        NSLog(@"[PacketTunnel] OpenVPNAdapter stopped");
    }
    
    self.isConnected = NO;
    self.lastError = nil;
    
    if (self.reconnectTimer) {
        [self.reconnectTimer invalidate];
        self.reconnectTimer = nil;
    }
    
    if (self.watchdogTimer) {
        [self.watchdogTimer invalidate];
        self.watchdogTimer = nil;
    }
    
    completionHandler();
}

- (void)handleAppMessage:(NSData *)messageData 
       completionHandler:(void (^)(NSData *))completionHandler {
    
    @try {
        NSLog(@"[PacketTunnel] 📨 Received app message (%lu bytes)", (unsigned long)messageData.length);
        
        // Handle messages from main app
        NSError *error;
        NSDictionary *message = [NSJSONSerialization JSONObjectWithData:messageData 
                                                                 options:0 
                                                                   error:&error];
        
        if (error) {
            NSLog(@"❌ [PacketTunnel] Error parsing message: %@", error.localizedDescription);
            self.lastError = error;
            completionHandler(nil);
            return;
        }
        
        NSString *command = message[@"command"];
        NSLog(@"[PacketTunnel] 📨 Command: %@", command);
        
        if ([command isEqualToString:@"getStatistics"]) {
            @try {
                // Return statistics
                NSDictionary *stats = @{
                    @"bytesIn": @0,  // TODO: Get from OpenVPN3
                    @"bytesOut": @0, // TODO: Get from OpenVPN3
                    @"connectedSince": [NSDate date]
                };
                
                NSData *responseData = [NSJSONSerialization dataWithJSONObject:stats 
                                                                       options:0 
                                                                         error:&error];
                if (error) {
                    NSLog(@"❌ [PacketTunnel] Error serializing statistics: %@", error.localizedDescription);
                    self.lastError = error;
                    completionHandler(nil);
                } else {
                    completionHandler(responseData);
                }
            } @catch (NSException *exception) {
                NSLog(@"❌ [PacketTunnel] EXCEPTION in getStatistics: %@", exception);
                NSError *err = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                   code:9 
                                               userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Exception: %@", exception.reason]}];
                self.lastError = err;
                completionHandler(nil);
            }
        } else if ([command isEqualToString:@"getLogs"]) {
            @try {
                // Save current logs to UserDefaults before returning
                [self saveLogsToUserDefaults];
                
                // Return recent logs and status (for debugging)
                NSMutableDictionary *response = [NSMutableDictionary dictionary];
                response[@"status"] = @"Extension is running";
                response[@"isConnected"] = @(self.isConnected);
                response[@"hasAdapter"] = @(self.openVPNAdapter != nil);
                
                // CRITICAL: Merge logs from multiple sources
                // 1. Current logEntries from PacketTunnelProvider
                NSMutableArray *allLogs = [NSMutableArray array];
                @synchronized(self.logEntries) {
                    [allLogs addObjectsFromArray:[self.logEntries copy]];
                }
                
                // 2. Logs from UserDefaults (includes logs from OpenVPNAdapter)
                NSArray *savedLogs = [[NSUserDefaults standardUserDefaults] objectForKey:kExtensionLogsKey];
                if (savedLogs && savedLogs.count > 0) {
                    // Merge saved logs, avoiding duplicates by timestamp+message
                    NSMutableSet *existingLogs = [NSMutableSet set];
                    for (NSDictionary *log in allLogs) {
                        NSString *key = [NSString stringWithFormat:@"%@_%@", log[@"timestamp"], log[@"message"]];
                        [existingLogs addObject:key];
                    }
                    
                    for (NSDictionary *log in savedLogs) {
                        NSString *key = [NSString stringWithFormat:@"%@_%@", log[@"timestamp"], log[@"message"]];
                        if (![existingLogs containsObject:key]) {
                            [allLogs addObject:log];
                            [existingLogs addObject:key];
                        }
                    }
                }
                
                // Sort by timestamp
                [allLogs sortUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
                    NSNumber *ts1 = obj1[@"timestamp"];
                    NSNumber *ts2 = obj2[@"timestamp"];
                    return [ts1 compare:ts2];
                }];
                
                // Keep only last 100 entries
                if (allLogs.count > 100) {
                    [allLogs removeObjectsInRange:NSMakeRange(0, allLogs.count - 100)];
                }
                
                response[@"logs"] = allLogs;
                response[@"logCount"] = @(allLogs.count);
                response[@"savedLogs"] = allLogs; // Also include in savedLogs for compatibility
                response[@"savedLogCount"] = @(allLogs.count);
                
                // Include last error if any
                if (self.lastError) {
                    response[@"lastError"] = @{
                        @"domain": self.lastError.domain,
                        @"code": @(self.lastError.code),
                        @"description": self.lastError.localizedDescription ?: @"Unknown error"
                    };
                }
                // Include last applied network settings (for debugging: gateway, IP, DNS, matchDomains)
                NSDictionary *lastSettings = [[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.LastAppliedSettings"];
                if (lastSettings) {
                    response[@"lastAppliedSettings"] = lastSettings;
                }
                
                NSData *responseData = [NSJSONSerialization dataWithJSONObject:response 
                                                                       options:0 
                                                                         error:&error];
                if (error) {
                    NSLog(@"❌ [PacketTunnel] Error serializing logs: %@", error.localizedDescription);
                    self.lastError = error;
                    completionHandler(nil);
                } else {
                    completionHandler(responseData);
                }
            } @catch (NSException *exception) {
                NSLog(@"❌ [PacketTunnel] EXCEPTION in getLogs: %@", exception);
                NSError *err = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                                   code:10 
                                               userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Exception: %@", exception.reason]}];
                self.lastError = err;
                completionHandler(nil);
            }
        } else if ([command isEqualToString:@"getError"]) {
            @try {
                // Return last error - check both memory and UserDefaults
                NSError *errorToReturn = self.lastError;
                
                // If no error in memory, try to load from UserDefaults (in case Extension restarted)
                if (!errorToReturn) {
                    NSDictionary *savedErrorDict = [[NSUserDefaults standardUserDefaults] objectForKey:kExtensionErrorKey];
                    if (savedErrorDict) {
                        errorToReturn = [NSError errorWithDomain:savedErrorDict[@"domain"] ?: @"Unknown"
                                                             code:[savedErrorDict[@"code"] integerValue]
                                                         userInfo:@{NSLocalizedDescriptionKey: savedErrorDict[@"description"] ?: @"Unknown error"}];
                        NSLog(@"📖 [PacketTunnel] Loaded error from UserDefaults");
                    }
                }
                
                // Also check for crash info
                NSDictionary *crashDict = [[NSUserDefaults standardUserDefaults] objectForKey:kExtensionCrashKey];
                if (crashDict && !errorToReturn) {
                    errorToReturn = [NSError errorWithDomain:crashDict[@"domain"] ?: @"PacketTunnelProvider"
                                                         code:[crashDict[@"code"] integerValue]
                                                     userInfo:@{NSLocalizedDescriptionKey: crashDict[@"description"] ?: @"Extension crashed"}];
                    NSLog(@"💥 [PacketTunnel] Found crash info in UserDefaults");
                }
                
                if (errorToReturn) {
                    NSDictionary *errorDict = @{
                        @"domain": errorToReturn.domain,
                        @"code": @(errorToReturn.code),
                        @"description": errorToReturn.localizedDescription ?: @"Unknown error",
                        @"userInfo": errorToReturn.userInfo ?: @{},
                        @"fromUserDefaults": @(self.lastError == nil)
                    };
                    NSData *responseData = [NSJSONSerialization dataWithJSONObject:errorDict 
                                                                           options:0 
                                                                             error:&error];
                    if (error) {
                        NSLog(@"❌ [PacketTunnel] Error serializing error: %@", error.localizedDescription);
                        completionHandler(nil);
                    } else {
                        completionHandler(responseData);
                    }
                } else {
                    completionHandler(nil);
                }
            } @catch (NSException *exception) {
                NSLog(@"❌ [PacketTunnel] EXCEPTION in getError: %@", exception);
                completionHandler(nil);
            }
        } else if ([command isEqualToString:@"ping"]) {
            // Simple ping command to check if Extension is alive
            @try {
                NSDictionary *response = @{
                    @"status": @"alive",
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"hasAdapter": @(self.openVPNAdapter != nil),
                    @"isConnected": @(self.isConnected)
                };
                NSData *responseData = [NSJSONSerialization dataWithJSONObject:response 
                                                                       options:0 
                                                                         error:&error];
                completionHandler(responseData);
            } @catch (NSException *exception) {
                NSLog(@"❌ [PacketTunnel] EXCEPTION in ping: %@", exception);
                completionHandler(nil);
            }
        } else {
            NSLog(@"⚠️ [PacketTunnel] Unknown command: %@", command);
            completionHandler(nil);
        }
    } @catch (NSException *exception) {
        NSLog(@"❌ [PacketTunnel] FATAL EXCEPTION in handleAppMessage: %@", exception);
        NSLog(@"❌ [PacketTunnel] Stack trace: %@", exception.callStackSymbols);
        NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                             code:11 
                                         userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Fatal exception in handleAppMessage: %@", exception.reason]}];
        self.lastError = error;
        completionHandler(nil);
    }
}

- (void)sleepWithCompletionHandler:(void (^)(void))completionHandler {
    // Handle sleep - pause VPN if needed
    NSLog(@"[PacketTunnel] Going to sleep");
    completionHandler();
}

- (void)wake {
    // Handle wake - resume VPN if needed
    NSLog(@"[PacketTunnel] Waking up");
}

#pragma mark - Private Methods

- (void)configureTunnelSettingsWithCompletion:(void (^)(NSError *))completionHandler {
    // Do NOT apply temporary settings here. Apply network settings only ONCE when OpenVPN3
    // pushes the real config in needsNetworkSettings. This matches working clients (e.g. OpenVPN Connect)
    // and avoids iOS routing issues from applying 10.8.0.x then updating to server-pushed 10.50.29.x.
    NSLog(@"🔧 [PacketTunnel] Skipping initial setTunnelNetworkSettings (will apply once from OpenVPN3)");
    [self addLogEntry:@"Skipping initial tunnel settings (will apply from OpenVPN3)" level:@"INFO"];
    [self saveLogsToUserDefaults];
    completionHandler(nil);
}

#pragma mark - OpenVPNAdapterDelegate

- (void)openVPNAdapterDidConnect:(OpenVPNAdapter *)adapter {
    @try {
        NSLog(@"✅ [PacketTunnel] OpenVPN3 connected!");
        self.isConnected = YES;
        self.lastError = nil; // Clear any previous errors
        
        // Clear saved crash/error so app does not show stale SIGABRT from a previous run
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:kExtensionErrorKey];
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:kExtensionCrashKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        // Re-apply network settings with full tun_builder state so routing/DNS are correct for traffic
        [adapter updateNetworkSettings];
        // startCompletionHandler is called in needsNetworkSettings after setTunnelNetworkSettings completes
    } @catch (NSException *exception) {
        NSLog(@"❌ [PacketTunnel] EXCEPTION in openVPNAdapterDidConnect: %@", exception);
        NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                             code:12 
                                         userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Exception in connection handler: %@", exception.reason]}];
        self.lastError = error;
        if (self.startCompletionHandler) {
            self.startCompletionHandler(error);
            self.startCompletionHandler = nil;
        }
    }
}

- (void)openVPNAdapter:(OpenVPNAdapter *)adapter didFailWithError:(NSError *)error {
    @try {
        NSString *errorMsg = [NSString stringWithFormat:@"OpenVPN3 connection failed: %@ (domain: %@, code: %ld)", 
                              error.localizedDescription, error.domain, (long)error.code];
        NSLog(@"❌ [PacketTunnel] %@", errorMsg);
        NSLog(@"❌ [PacketTunnel] Error userInfo: %@", error.userInfo);
        [self addLogEntry:errorMsg level:@"ERROR"];
        self.isConnected = NO;
        self.lastError = error; // Store error for app messages
        
        // Save error to UserDefaults so it can be retrieved even after Extension restarts
        [self saveErrorToUserDefaults:error];
        [self saveLogsToUserDefaults];
        
        // Complete tunnel start with error
        if (self.startCompletionHandler) {
            self.startCompletionHandler(error);
            self.startCompletionHandler = nil;
        }
    } @catch (NSException *exception) {
        NSLog(@"❌ [PacketTunnel] EXCEPTION in didFailWithError: %@", exception);
        // If we can't handle the error properly, at least log it and try to save
        self.lastError = error; // Try to preserve original error
        @try {
            [self saveErrorToUserDefaults:error];
        } @catch (...) {
            // Even saving failed - log it
            NSLog(@"❌ [PacketTunnel] FATAL: Cannot save error!");
        }
    }
}

- (void)openVPNAdapterDidDisconnect:(OpenVPNAdapter *)adapter {
    @try {
        NSLog(@"🔴 [PacketTunnel] OpenVPN3 disconnected");
        self.isConnected = NO;
    } @catch (NSException *exception) {
        NSLog(@"❌ [PacketTunnel] EXCEPTION in openVPNAdapterDidDisconnect: %@", exception);
    }
}

- (void)openVPNAdapter:(OpenVPNAdapter *)adapter 
    needsNetworkSettings:(NEPacketTunnelNetworkSettings *)settings {
    @try {
        NSLog(@"🔧 [PacketTunnel] Updating network settings from OpenVPN3");
        NSString *remoteStr = settings.tunnelRemoteAddress ?: @"(nil)";
        NSString *ipv4Str = @"(none)";
        if (settings.IPv4Settings.addresses.count > 0) {
            ipv4Str = [settings.IPv4Settings.addresses componentsJoinedByString:@", "];
        }
        NSString *dnsStr = @"(none)";
        if (settings.DNSSettings.servers.count > 0) {
            dnsStr = [settings.DNSSettings.servers componentsJoinedByString:@", "];
        }
        NSString *matchDomainsStr = settings.DNSSettings.matchDomains.count > 0
            ? [settings.DNSSettings.matchDomains componentsJoinedByString:@"; "] : @"(nil=all)";
        [self addLogEntry:[NSString stringWithFormat:@"🔧 Updating network settings from OpenVPN3: tunnelRemote=%@, IPv4=%@, DNS=%@, matchDomains=%@", remoteStr, ipv4Str, dnsStr, matchDomainsStr] level:@"INFO"];
        // TUNNEL DEBUG: dump routes (должен быть default = 0.0.0.0/0)
        if (settings.IPv4Settings.includedRoutes.count > 0) {
            NSMutableArray *routeStrs = [NSMutableArray array];
            for (NEIPv4Route *r in settings.IPv4Settings.includedRoutes) {
                [routeStrs addObject:[NSString stringWithFormat:@"%@/%@", r.destinationAddress, r.destinationSubnetMask]];
            }
            [self addLogEntry:[NSString stringWithFormat:@"[TUNNEL DEBUG] includedRoutes(%lu): %@", (unsigned long)settings.IPv4Settings.includedRoutes.count, [routeStrs componentsJoinedByString:@", "]] level:@"INFO"];
        }
        if (settings.IPv4Settings.excludedRoutes.count > 0) {
            NSMutableArray *exStrs = [NSMutableArray array];
            for (NEIPv4Route *r in settings.IPv4Settings.excludedRoutes) {
                [exStrs addObject:[NSString stringWithFormat:@"%@/%@", r.destinationAddress, r.destinationSubnetMask]];
            }
            [self addLogEntry:[NSString stringWithFormat:@"[TUNNEL DEBUG] excludedRoutes(%lu): %@", (unsigned long)settings.IPv4Settings.excludedRoutes.count, [exStrs componentsJoinedByString:@", "]] level:@"WARNING"];
        }
        [self saveLogsToUserDefaults];
        // Save last applied settings so app can verify (key used by VPNManager when requesting status)
        [[NSUserDefaults standardUserDefaults] setObject:@{ @"tunnelRemote": remoteStr, @"IPv4": ipv4Str, @"dns": dnsStr, @"matchDomains": matchDomainsStr } forKey:@"DataGateVPNExtension.LastAppliedSettings"];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        // Use weak reference to avoid retain cycle
        __weak PacketTunnelProvider *weakSelf = self;
        [self setTunnelNetworkSettings:settings completionHandler:^(NSError *error) {
            @try {
                PacketTunnelProvider *strongSelf = weakSelf;
                if (!strongSelf) {
                    NSLog(@"⚠️ [PacketTunnel] self was deallocated before completion handler");
                    return;
                }
                if (error) {
                    NSLog(@"❌ [PacketTunnel] Error updating network settings: %@", error.localizedDescription);
                    [strongSelf addLogEntry:[NSString stringWithFormat:@"❌ setTunnelNetworkSettings failed: %@", error.localizedDescription] level:@"ERROR"];
                    [strongSelf saveLogsToUserDefaults];
                    strongSelf.lastError = error;
                    if (strongSelf.startCompletionHandler) {
                        strongSelf.startCompletionHandler(error);
                        strongSelf.startCompletionHandler = nil;
                    }
                } else {
                    NSLog(@"✅ [PacketTunnel] Network settings updated successfully (tunnel ready for traffic)");
                    [strongSelf addLogEntry:@"✅ Network settings from OpenVPN3 applied (tunnel ready for traffic)" level:@"INFO"];
                    [strongSelf saveLogsToUserDefaults];
                    if (strongSelf.startCompletionHandler) {
                        strongSelf.startCompletionHandler(nil);
                        strongSelf.startCompletionHandler = nil;
                    }
                }
            } @catch (NSException *exception) {
                NSLog(@"❌ [PacketTunnel] EXCEPTION in setTunnelNetworkSettings completion: %@", exception);
                PacketTunnelProvider *selfForCatch = weakSelf;
                if (selfForCatch.startCompletionHandler) {
                    NSError *err = [NSError errorWithDomain:@"PacketTunnelProvider" code:13 userInfo:@{ NSLocalizedDescriptionKey: (exception.reason ?: @"Unknown") }];
                    selfForCatch.startCompletionHandler(err);
                    selfForCatch.startCompletionHandler = nil;
                }
            }
        }];
    } @catch (NSException *exception) {
        NSLog(@"❌ [PacketTunnel] EXCEPTION in needsNetworkSettings: %@", exception);
        NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                             code:13 
                                         userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Exception updating network settings: %@", exception.reason]}];
        self.lastError = error;
    }
}

- (void)openVPNAdapter:(OpenVPNAdapter *)adapter needsSendPacket:(NSData *)packet {
    @try {
        // Send packet to iOS (packet from VPN server to be injected into device network)
        NSLog(@"[PacketTunnel] 📤 Need to send packet (%lu bytes) to iOS network", (unsigned long)packet.length);
        
        // Write packet to packetFlow - this injects it into the device's network stack
        // The packet will be routed according to the tunnel network settings
        [self.packetFlow writePackets:@[packet] withProtocols:@[@(AF_INET)]];
        NSLog(@"[PacketTunnel] ✅ Packet written to packetFlow");
    } @catch (NSException *exception) {
        NSLog(@"❌ [PacketTunnel] EXCEPTION in needsSendPacket: %@", exception);
        NSError *error = [NSError errorWithDomain:@"PacketTunnelProvider" 
                                             code:14 
                                         userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Exception sending packet: %@", exception.reason]}];
        [self saveErrorToUserDefaults:error];
        self.lastError = error;
    }
}

#pragma mark - Error Persistence & Watchdog

- (void)saveErrorToUserDefaults:(NSError *)error {
    @try {
        NSDictionary *errorDict = @{
            @"domain": error.domain,
            @"code": @(error.code),
            @"description": error.localizedDescription ?: @"Unknown error",
            @"userInfo": error.userInfo ?: @{},
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        [[NSUserDefaults standardUserDefaults] setObject:errorDict forKey:kExtensionErrorKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        NSLog(@"💾 [PacketTunnel] Error saved to UserDefaults");
    } @catch (NSException *exception) {
        NSLog(@"❌ [PacketTunnel] Failed to save error to UserDefaults: %@", exception);
    }
}

- (void)startWatchdogTimer {
    // Invalidate existing timer if any
    if (self.watchdogTimer) {
        [self.watchdogTimer invalidate];
    }
    
    // Create timer that fires every 5 seconds to ensure Extension is alive
    // This also ensures we can respond to app messages even if main thread is blocked
    self.watchdogTimer = [NSTimer scheduledTimerWithTimeInterval:5.0
                                                           target:self
                                                         selector:@selector(watchdogTick:)
                                                         userInfo:nil
                                                          repeats:YES];
    NSLog(@"🐕 [PacketTunnel] Watchdog timer started");
}

- (void)watchdogTick:(NSTimer *)timer {
    @try {
        // Just log that we're alive - this ensures Extension doesn't die silently
        static int tickCount = 0;
        tickCount++;
        if (tickCount % 12 == 0) { // Log every minute (12 * 5 seconds)
            NSLog(@"🐕 [PacketTunnel] Watchdog tick - Extension is alive (tick %d)", tickCount);
        }
        
        // If we have a last error, make sure it's saved
        if (self.lastError) {
            [self saveErrorToUserDefaults:self.lastError];
        }
        
        // Check if we should still be running
        if (!self.openVPNAdapter && self.isConnected) {
            NSLog(@"⚠️ [PacketTunnel] Watchdog: Adapter is nil but isConnected is YES - inconsistency detected");
        }
    } @catch (NSException *exception) {
        NSLog(@"❌ [PacketTunnel] EXCEPTION in watchdog: %@", exception);
        // Don't let watchdog crash - it's our safety net
    }
}

// Restore warnings for our code
#pragma clang diagnostic pop

@end

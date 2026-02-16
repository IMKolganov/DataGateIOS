//
//  OpenVPNAdapter.mm
//  DataGateVPNExtension
//
//  Objective-C++ adapter for OpenVPN3 C++ library
//

// Suppress warnings from external libraries (mbedtls, asio, openvpn3)
// These are documentation warnings and deprecation warnings that we cannot fix
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wdocumentation-deprecated-sync"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wmacro-redefined"

#import "OpenVPNAdapter.h"
#import <NetworkExtension/NetworkExtension.h>
#import <exception>
#import <cstdlib>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#import <CoreFoundation/CoreFoundation.h>

// PSA Crypto initialization for mbedTLS 3.6+ (required for TLS 1.3)
// CRITICAL: Include build_info.h to get MBEDTLS_VERSION_NUMBER
#include <mbedtls/build_info.h>
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
#include <psa/crypto.h>
#endif
#import <string>
#include <vector>
#include <mutex>

// Debug: parse IPv4 header and return "src -> dst proto=N" (nil if not IPv4 or too short)
static NSString* _tunnelDebugIPv4Summary(NSData *data) {
    if (!data || data.length < 20) return nil;
    const uint8_t *p = (const uint8_t *)data.bytes;
    if ((p[0] >> 4) != 4) return nil;
    char src[32], dst[32];
    snprintf(src, sizeof(src), "%u.%u.%u.%u", p[12], p[13], p[14], p[15]);
    snprintf(dst, sizeof(dst), "%u.%u.%u.%u", p[16], p[17], p[18], p[19]);
    return [NSString stringWithFormat:@"%s -> %s proto=%u", src, dst, (unsigned int)p[9]];
}

// C bridge function to save logs from C++ to UserDefaults
// This allows C++ code (like load_ca, parse) to save logs that will be visible in the app
extern "C" {
    void saveLogToUserDefaults(const char* level, const char* message) {
        @autoreleasepool {
            @try {
                static NSString *const kLogsKey = @"DataGateVPNExtension.Logs";
                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:kLogsKey] mutableCopy] ?: [NSMutableArray array];
                NSString *levelStr = level ? [NSString stringWithUTF8String:level] : @"INFO";
                NSString *messageStr = message ? [NSString stringWithUTF8String:message] : @"";
                
                NSDictionary *logEntry = @{
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"level": levelStr,
                    @"message": messageStr
                };
                
                [logs addObject:logEntry];
                
                // Keep only last 200 entries (increased to preserve detailed logs)
                if (logs.count > 200) {
                    [logs removeObjectsInRange:NSMakeRange(0, logs.count - 200)];
                }
                
                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:kLogsKey];
                // CRITICAL: Force immediate synchronization to ensure logs are saved before possible crash
                BOOL syncResult = [[NSUserDefaults standardUserDefaults] synchronize];
                if (!syncResult) {
                    printf("[OpenVPNAdapter] ⚠️ WARNING: synchronize() returned NO - logs may not be saved!\n");
                }
                
                // Also print to console for debugging (immediate, works even if UserDefaults fails)
                printf("[OpenVPNAdapter] [%s] %s\n", level ? level : "INFO", message ? message : "");
                fflush(stdout); // Force flush to ensure console output is visible
            } @catch (NSException *e) {
                printf("[OpenVPNAdapter] ⚠️ Failed to save log: %s\n", e.reason.UTF8String);
            } @catch (...) {
                // Silently fail if UserDefaults is not available
            }
        }
    }
    
    // C bridge function to validate certificate using Security Framework
    // Returns 0 if certificate is valid, non-zero if invalid
    int validateCertificateWithSecurityFramework(const unsigned char* pem_data, size_t pem_len) {
        @autoreleasepool {
            @try {
                // Convert PEM to DER for Security Framework
                NSString *pemString = [[NSString alloc] initWithBytes:pem_data length:pem_len encoding:NSUTF8StringEncoding];
                if (!pemString) {
                    printf("[SecurityFramework] Failed to create NSString from PEM data\n");
                    return -1;
                }
                
                // Extract base64 content
                NSRange beginRange = [pemString rangeOfString:@"-----BEGIN CERTIFICATE-----"];
                NSRange endRange = [pemString rangeOfString:@"-----END CERTIFICATE-----"];
                if (beginRange.location == NSNotFound || endRange.location == NSNotFound) {
                    printf("[SecurityFramework] PEM markers not found\n");
                    return -2;
                }
                
                NSUInteger base64Start = beginRange.location + beginRange.length;
                NSUInteger base64Length = endRange.location - base64Start;
                NSString *base64Content = [pemString substringWithRange:NSMakeRange(base64Start, base64Length)];
                
                // Remove whitespace
                base64Content = [base64Content stringByReplacingOccurrencesOfString:@"\n" withString:@""];
                base64Content = [base64Content stringByReplacingOccurrencesOfString:@"\r" withString:@""];
                base64Content = [base64Content stringByReplacingOccurrencesOfString:@" " withString:@""];
                
                // Decode base64 to DER
                NSData *derData = [[NSData alloc] initWithBase64EncodedString:base64Content options:0];
                if (!derData) {
                    printf("[SecurityFramework] Failed to decode base64\n");
                    return -3;
                }
                
                // Create certificate using Security Framework
                SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)derData);
                if (!cert) {
                    printf("[SecurityFramework] ❌ SecCertificateCreateWithData FAILED - certificate is invalid!\n");
                    saveLogToUserDefaults("ERROR", "[SecurityFramework] ❌ Certificate validation FAILED - Security Framework cannot parse");
                    return -4;
                }
                
                printf("[SecurityFramework] ✅ SecCertificateCreateWithData SUCCESS - certificate is valid!\n");
                saveLogToUserDefaults("INFO", "[SecurityFramework] ✅ Certificate validated by Security Framework");
                
                // Get certificate summary for logging
                CFStringRef summary = SecCertificateCopySubjectSummary(cert);
                if (summary) {
                    NSString *summaryStr = (__bridge_transfer NSString *)summary;
                    char summaryBuf[256];
                    snprintf(summaryBuf, sizeof(summaryBuf), "[SecurityFramework] Certificate subject: %s", [summaryStr UTF8String]);
                    saveLogToUserDefaults("INFO", summaryBuf);
                }
                
                CFRelease(cert);
                return 0; // Success
            } @catch (NSException *exception) {
                printf("[SecurityFramework] Exception: %s\n", exception.reason.UTF8String);
                saveLogToUserDefaults("ERROR", "[SecurityFramework] Exception during validation");
                return -5;
            }
        }
    }
}

// Log immediately when OpenVPNAdapter is loaded
__attribute__((constructor))
static void openvpn_adapter_loaded() {
    printf("[OpenVPNAdapter] OpenVPNAdapter binary loaded!\n");
    NSLog(@"🔧 [OpenVPNAdapter] OpenVPNAdapter binary loaded!");
}

// Forward declarations - OpenVPN3 headers will be included only when needed
// This prevents crashes during Extension initialization

// OpenVPN3 preprocessor definitions
#ifndef OPENVPN_CORE_API_VISIBILITY_HIDDEN
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN
#endif
#define OPENVPN_PLATFORM_MAC 1
#define OPENVPN_PLATFORM_IPHONE 1
#define OPENVPN_PLATFORM_IPHONE_DEVICE 1

// Define logging macros before including log headers
#define OPENVPN_LOG_CLASS openvpn::ClientAPI::LogReceiver
#define OPENVPN_LOG_INFO openvpn::ClientAPI::LogInfo

// OpenVPN3 includes - io.hpp must be included first to define openvpn_io namespace
// NOTE: These are included here, but if Extension crashes, we may need to move them
// to a separate compilation unit or delay loading
#include <openvpn/io/io.hpp>
#include <client/ovpncli.hpp>
#include <openvpn/tun/builder/base.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/log/logthread.hpp>
#include <openvpn/mbedtls/util/rand.hpp>
#include <openvpn/crypto/cryptochoose.hpp>
#include "IOSEntropySource.hpp"
#include <algorithm>
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

using namespace openvpn;
using namespace openvpn::ClientAPI;

// Route information structure
struct RouteInfo {
    std::string address;
    int prefix_length;
    int metric;
    bool ipv6;
    bool exclude;
};

/// OpenVPN3 client wrapper for iOS Network Extension
/// Inherits from OpenVPNClient (which already inherits from TunBuilderBase)
class IOSOpenVPNClient : public OpenVPNClient {
public:
    IOSOpenVPNClient(OpenVPNAdapter *adapter) : adapter_(adapter) {
        NSLog(@"[IOSOpenVPNClient] ✅ Client created");
        printf("[IOSOpenVPNClient] ✅ Client created\n");
        
        // Log adapter and packetFlow status
        if (!adapter_) {
            NSLog(@"[IOSOpenVPNClient] ⚠️ WARNING: adapter_ is nil in constructor!");
            printf("[IOSOpenVPNClient] ⚠️ WARNING: adapter_ is nil in constructor!\n");
        } else {
            NSLog(@"[IOSOpenVPNClient] ✅ adapter_ is not nil: %p", (__bridge void *)adapter_);
            printf("[IOSOpenVPNClient] ✅ adapter_ is not nil: %p\n", (__bridge void *)adapter_);
            
            if (!adapter_.packetFlow) {
                NSLog(@"[IOSOpenVPNClient] ⚠️ WARNING: adapter_.packetFlow is nil in constructor!");
                printf("[IOSOpenVPNClient] ⚠️ WARNING: adapter_.packetFlow is nil in constructor!\n");
            } else {
                NSLog(@"[IOSOpenVPNClient] ✅ adapter_.packetFlow is not nil: %p", (__bridge void *)adapter_.packetFlow);
                printf("[IOSOpenVPNClient] ✅ adapter_.packetFlow is not nil: %p\n", (__bridge void *)adapter_.packetFlow);
            }
        }
    }
    
    ~IOSOpenVPNClient() {
        NSLog(@"[IOSOpenVPNClient] 🔴 Client destroyed");
        invalidateSockets();
    }
    
    // Override TunBuilderBase methods for iOS Network Extension
    bool tun_builder_new() override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_new() called");
        return true;
    }
    
    bool tun_builder_set_layer(int layer) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_set_layer(%d)", layer);
        return true;
    }
    
    bool tun_builder_set_remote_address(const std::string &address, bool ipv6) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_set_remote_address(%s, ipv6=%d)", address.c_str(), ipv6);
        remote_address_ = address;
        remote_ipv6_ = ipv6;
        return true;
    }
    
    bool tun_builder_add_address(const std::string &address, 
                                 int prefix_length,
                                 const std::string &gateway, 
                                 bool ipv6, 
                                 bool net30) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_add_address(%s/%d, gateway=%s, ipv6=%d, net30=%d)", 
              address.c_str(), prefix_length, gateway.c_str(), ipv6, net30);
        
        // Store address info for later use
        if (ipv6) {
            ipv6_address_ = address;
            ipv6_prefix_ = prefix_length;
            ipv6_gateway_ = gateway;
        } else {
            ipv4_address_ = address;
            ipv4_prefix_ = prefix_length;
            ipv4_gateway_ = gateway;
        }
        
        return true;
    }
    
    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_reroute_gw(ipv4=%d, ipv6=%d, flags=0x%x)", ipv4, ipv6, flags);
        reroute_ipv4_ = ipv4;
        reroute_ipv6_ = ipv6;
        reroute_flags_ = flags;
        return true;
    }
    
    bool tun_builder_add_route(const std::string &address, int prefix_length, int metric, bool ipv6) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_add_route(%s/%d, metric=%d, ipv6=%d)", 
              address.c_str(), prefix_length, metric, ipv6);
        routes_.push_back({address, prefix_length, metric, ipv6, false});
        return true;
    }
    
    bool tun_builder_exclude_route(const std::string &address, int prefix_length, int metric, bool ipv6) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_exclude_route(%s/%d, metric=%d, ipv6=%d)", 
              address.c_str(), prefix_length, metric, ipv6);
        routes_.push_back({address, prefix_length, metric, ipv6, true});
        return true;
    }
    
    bool tun_builder_set_dns_options(const DnsOptions &dns) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_set_dns_options()");
        NSLog(@"[IOSOpenVPNClient]    DNS servers count: %zu", dns.servers.size());
        for (const auto& [priority, server] : dns.servers) {
            if (!server.addresses.empty()) {
                NSLog(@"[IOSOpenVPNClient]    DNS[priority=%d]: %s", priority, server.addresses[0].to_string().c_str());
            }
        }
        NSLog(@"[IOSOpenVPNClient]    Search domains count: %zu", dns.search_domains.size());
        for (size_t i = 0; i < dns.search_domains.size(); ++i) {
            NSLog(@"[IOSOpenVPNClient]    Domain[%zu]: %s", i, dns.search_domains[i].domain.c_str());
        }
        
        // Store DNS info
        dns_options_ = dns;
        
        // Notify adapter to update network settings
        dispatch_async(dispatch_get_main_queue(), ^{
            [adapter_ updateNetworkSettings];
        });
        
        return true;
    }
    
    bool tun_builder_set_mtu(int mtu) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_set_mtu(%d)", mtu);
        mtu_ = mtu;
        return true;
    }
    
    bool tun_builder_set_allow_family(int af, bool allow) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_set_allow_family(af=%d, allow=%d)", af, allow);
        printf("[IOSOpenVPNClient] 📝 tun_builder_set_allow_family(af=%d, allow=%d)\n", af, allow);
        // iOS Network Extension handles this automatically, just return true
        return true;
    }
    
    bool tun_builder_set_allow_local_dns(bool allow) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_set_allow_local_dns(allow=%d)", allow);
        printf("[IOSOpenVPNClient] 📝 tun_builder_set_allow_local_dns(allow=%d)\n", allow);
        // iOS Network Extension handles DNS blocking automatically, just return true
        return true;
    }
    
    bool tun_builder_set_session_name(const std::string &name) override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_set_session_name(%s)", name.c_str());
        printf("[IOSOpenVPNClient] 📝 tun_builder_set_session_name(%s)\n", name.c_str());
        // CRITICAL: Save to UserDefaults immediately
        @try {
            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
            [logs addObject:@{
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"level": @"INFO",
                @"message": [NSString stringWithFormat:@"[IOSOpenVPNClient] 📝 tun_builder_set_session_name(%s)", name.c_str()]
            }];
            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        } @catch (...) {}
        // iOS Network Extension doesn't need session name, just return true
        return true;
    }
    
    int tun_builder_establish() override {
        NSLog(@"[IOSOpenVPNClient] 📝 tun_builder_establish() called");
        printf("[IOSOpenVPNClient] 📝 tun_builder_establish() called\n");
        saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] 📝 tun_builder_establish() called");
        
        NSString *ipv4Info = [NSString stringWithFormat:@"[IOSOpenVPNClient]    IPv4: %s/%d gateway=%s", 
                              ipv4_address_.c_str(), ipv4_prefix_, ipv4_gateway_.c_str()];
        NSString *ipv6Info = [NSString stringWithFormat:@"[IOSOpenVPNClient]    IPv6: %s/%d gateway=%s", 
                              ipv6_address_.c_str(), ipv6_prefix_, ipv6_gateway_.c_str()];
        NSString *routesInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient]    Routes count: %zu", routes_.size()];
        NSString *mtuInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient]    MTU: %d", mtu_];
        
        NSLog(@"%@", ipv4Info);
        NSLog(@"%@", ipv6Info);
        NSLog(@"%@", routesInfo);
        NSLog(@"%@", mtuInfo);
        printf("%s\n%s\n%s\n%s\n", [ipv4Info UTF8String], [ipv6Info UTF8String], [routesInfo UTF8String], [mtuInfo UTF8String]);
        saveLogToUserDefaults("INFO", [ipv4Info UTF8String]);
        saveLogToUserDefaults("INFO", [ipv6Info UTF8String]);
        saveLogToUserDefaults("INFO", [routesInfo UTF8String]);
        saveLogToUserDefaults("INFO", [mtuInfo UTF8String]);
        
        // Based on OpenVPNAdapter implementation pattern:
        // Use socketpair() to create a pair of connected sockets
        // One socket goes to OpenVPN3, the other bridges to NEPacketTunnelFlow
        
        if (!adapter_ || !adapter_.packetFlow) {
            NSString *errorMsg = @"[IOSOpenVPNClient] ❌ adapter_ or packetFlow is nil!";
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            return -1;
        }
        
        NSLog(@"[IOSOpenVPNClient] ✅ adapter_ and packetFlow are available");
        printf("[IOSOpenVPNClient] ✅ adapter_ and packetFlow are available\n");
        saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] ✅ adapter_ and packetFlow are available");
        
        // Configure sockets (creates socketpair and CFSocket wrappers)
        if (!configureSockets()) {
            NSString *errorMsg = @"[IOSOpenVPNClient] ❌ Failed to configure sockets";
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            return -1;
        }
        
        // Start reading packets from NEPacketTunnelFlow
        startReadingFromPacketFlow();
        
        // Return the native file descriptor for OpenVPN3
        NSString *successMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ✅ tun_builder_establish() returning fd: %d", openVPNSocketFD_];
        NSLog(@"%@", successMsg);
        printf("%s\n", [successMsg UTF8String]);
        saveLogToUserDefaults("INFO", [successMsg UTF8String]);
        
        return openVPNSocketFD_;
    }
    
    // Configure socket pair for bridging NEPacketTunnelFlow and OpenVPN3
    // Based on OpenVPNAdapter implementation pattern
    bool configureSockets() {
        NSLog(@"[IOSOpenVPNClient] 🔧 configureSockets() called");
        printf("[IOSOpenVPNClient] 🔧 configureSockets() called\n");
        saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] 🔧 configureSockets() called");
        
        int sockets[2];
        if (socketpair(PF_LOCAL, SOCK_DGRAM, IPPROTO_IP, sockets) == -1) {
            NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ Failed to create socketpair: %s", strerror(errno)];
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            return false;
        }
        
        NSLog(@"[IOSOpenVPNClient] ✅ socketpair created: [%d, %d]", sockets[0], sockets[1]);
        printf("[IOSOpenVPNClient] ✅ socketpair created: [%d, %d]\n", sockets[0], sockets[1]);
        saveLogToUserDefaults("INFO", [NSString stringWithFormat:@"[IOSOpenVPNClient] ✅ socketpair created: [%d, %d]", sockets[0], sockets[1]].UTF8String);
        
        // Create CFSocket for OUR end of the pair (sockets[0]).
        // Socket pair semantics: write to [0] -> readable on [1]; write to [1] -> readable on [0].
        // We must READ from [0] (to get what OpenVPN3 writes to [1]) and WRITE to [0] (so OpenVPN3 reads from [1]).
        // Previously we wrote to [1], so our writes appeared on [0] and we read our own data (ECHO). Fixed by using [0] for both.
        CFSocketContext socketCtxt = {0, static_cast<void *>(this), NULL, NULL, NULL};
        
        packetFlowSocket_ = CFSocketCreateWithNative(kCFAllocatorDefault, sockets[0], 
                                                      kCFSocketDataCallBack,
                                                      PacketFlowSocketCallback, 
                                                      &socketCtxt);
        
        if (!packetFlowSocket_) {
            NSLog(@"[IOSOpenVPNClient] ❌ Failed to create CFSocket wrapper");
            close(sockets[0]);
            close(sockets[1]);
            return false;
        }
        // Use same socket for sending: we send to [0], so data arrives on [1] for OpenVPN3 to read.
        openVPNSocket_ = packetFlowSocket_;
        CFRetain(openVPNSocket_);
        
        // Configure socket options
        int buf_value = 65536;
        socklen_t buf_len = sizeof(buf_value);
        
        if (setsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, &buf_value, buf_len) == -1 ||
            setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &buf_value, buf_len) == -1 ||
            setsockopt(sockets[1], SOL_SOCKET, SO_RCVBUF, &buf_value, buf_len) == -1 ||
            setsockopt(sockets[1], SOL_SOCKET, SO_SNDBUF, &buf_value, buf_len) == -1) {
            NSLog(@"[IOSOpenVPNClient] ⚠️ Failed to set socket buffer sizes: %s", strerror(errno));
            // Continue anyway, not fatal
        }
        
        // CRITICAL: Set socket to non-blocking mode for OpenVPN3 side
        // OpenVPN3 expects non-blocking I/O for async operations
        int flags = fcntl(sockets[1], F_GETFL, 0);
        if (flags == -1) {
            NSLog(@"[IOSOpenVPNClient] ⚠️ Failed to get socket flags: %s", strerror(errno));
        } else {
            if (fcntl(sockets[1], F_SETFL, flags | O_NONBLOCK) == -1) {
                NSLog(@"[IOSOpenVPNClient] ⚠️ Failed to set socket to non-blocking: %s", strerror(errno));
            } else {
                NSString *nonBlockMsg = @"[IOSOpenVPNClient] ✅ Set OpenVPN3 socket to non-blocking mode";
                NSLog(@"%@", nonBlockMsg);
                printf("%s\n", [nonBlockMsg UTF8String]);
                saveLogToUserDefaults("INFO", [nonBlockMsg UTF8String]);
            }
        }
        
        // DIAGNOSTIC: Check socket state before creating CFSocket
        int rcvbuf = 0, sndbuf = 0;
        socklen_t optlen = sizeof(rcvbuf);
        getsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen);
        getsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen);
        NSString *socketStateMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Socket[0] state: RCVBUF=%d, SNDBUF=%d", rcvbuf, sndbuf];
        NSLog(@"%@", socketStateMsg);
        printf("%s\n", [socketStateMsg UTF8String]);
        saveLogToUserDefaults("INFO", [socketStateMsg UTF8String]);
        
        // CRITICAL: Add packetFlowSocket to the Extension's MAIN run loop, not the current thread's run loop
        // tun_builder_establish() may be called from OpenVPN3's background thread, but CFSocket callbacks
        // must be processed by the Extension's main run loop to work correctly
        // We need to dispatch this to the main queue to ensure we're on the Extension's main thread
        dispatch_sync(dispatch_get_main_queue(), ^{
            CFRunLoopRef mainRunLoop = CFRunLoopGetCurrent(); // Now we're on main thread, so GetCurrent() = GetMain()
            CFRunLoopSourceRef packetFlowSocketSource = CFSocketCreateRunLoopSource(kCFAllocatorDefault, packetFlowSocket_, 0);
            if (!packetFlowSocketSource) {
                NSLog(@"[IOSOpenVPNClient] ❌ Failed to create run loop source for packetFlowSocket");
                saveLogToUserDefaults("ERROR", "[IOSOpenVPNClient] ❌ Failed to create run loop source for packetFlowSocket");
                return;
            }
            // Use kCFRunLoopCommonModes to ensure callbacks are processed
            // This is more reliable than kCFRunLoopDefaultMode for Network Extensions
            CFRunLoopAddSource(mainRunLoop, packetFlowSocketSource, kCFRunLoopCommonModes);
            CFRelease(packetFlowSocketSource);
            
            // CRITICAL: Enable callbacks for the socket
            // Without this, PacketFlowSocketCallback will never be called even when data arrives
            CFSocketEnableCallBacks(packetFlowSocket_, kCFSocketDataCallBack);
            
            NSString *enableCallbacksMsg = @"[IOSOpenVPNClient] ✅ Enabled CFSocket callbacks (kCFSocketDataCallBack) on MAIN run loop";
            NSLog(@"%@", enableCallbacksMsg);
            printf("%s\n", [enableCallbacksMsg UTF8String]);
            saveLogToUserDefaults("INFO", [enableCallbacksMsg UTF8String]);
            
            // Verify we're on main run loop
            BOOL isMainThread = [NSThread isMainThread];
            CFRunLoopRef verifyRunLoop = CFRunLoopGetCurrent();
            BOOL isMainRunLoop = (verifyRunLoop == CFRunLoopGetMain());
            NSString *runLoopVerifyMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Run loop verification: isMainThread=%d, isMainRunLoop=%d, runLoop=%p", 
                                         isMainThread, isMainRunLoop, verifyRunLoop];
            NSLog(@"%@", runLoopVerifyMsg);
            printf("%s\n", [runLoopVerifyMsg UTF8String]);
            saveLogToUserDefaults("INFO", [runLoopVerifyMsg UTF8String]);
        });
        
        // Get main run loop for logging (after sync dispatch)
        CFRunLoopRef mainRunLoop = CFRunLoopGetMain();
        
        // Verify main run loop state
        BOOL isWaiting = CFRunLoopIsWaiting(mainRunLoop);
        CFRunLoopMode currentMode = CFRunLoopCopyCurrentMode(mainRunLoop);
        // Create a copy of the string before releasing CFString to avoid use-after-release
        NSString *modeStr = currentMode ? [NSString stringWithString:(__bridge NSString *)currentMode] : @"unknown";
        if (currentMode) CFRelease(currentMode);
        
        NSString *runLoopMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ✅ Added packetFlowSocket to MAIN run loop: %p (isWaiting=%d, mode=%@)", 
                               mainRunLoop, isWaiting, modeStr];
        NSLog(@"%@", runLoopMsg);
        printf("%s\n", [runLoopMsg UTF8String]);
        saveLogToUserDefaults("INFO", [runLoopMsg UTF8String]);
        
        // DIAGNOSTIC: Check CFSocket state
        BOOL socketValid = CFSocketIsValid(packetFlowSocket_);
        NSString *socketInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 CFSocket state: valid=%d, socket=%p", 
                               socketValid, packetFlowSocket_];
        NSLog(@"%@", socketInfo);
        printf("%s\n", [socketInfo UTF8String]);
        saveLogToUserDefaults("INFO", [socketInfo UTF8String]);
        
        // Store native FD for OpenVPN3 (sockets[1]). We use [0] for read+write; OpenVPN3 uses [1]. No more echo.
        openVPNSocketFD_ = sockets[1];
        
        NSString *successMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ✅ Socket pair configured: we use fd %d (read+write), OpenVPN3 uses fd %d", sockets[0], sockets[1]];
        NSLog(@"%@", successMsg);
        printf("%s\n", [successMsg UTF8String]);
        saveLogToUserDefaults("INFO", [successMsg UTF8String]);
        
        return true;
    }
    
    void invalidateSockets() {
        NSLog(@"[IOSOpenVPNClient] 🔄 invalidateSockets() called");
        printf("[IOSOpenVPNClient] 🔄 invalidateSockets() called\n");
        saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] 🔄 invalidateSockets() called");
        
        // openVPNSocket_ may be the same as packetFlowSocket_ (we use [0] for both read and write), so only release once.
        if (packetFlowSocket_) {
            CFSocketInvalidate(packetFlowSocket_);
            CFRelease(packetFlowSocket_);
            packetFlowSocket_ = nullptr;
            NSLog(@"[IOSOpenVPNClient] ✅ Invalidated packetFlowSocket_");
            saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] ✅ Invalidated packetFlowSocket_");
        }
        openVPNSocket_ = nullptr;  // same as packetFlowSocket_ if shared, do not double-release
        
        if (openVPNSocketFD_ != -1) {
            close(openVPNSocketFD_);
            openVPNSocketFD_ = -1;
            NSLog(@"[IOSOpenVPNClient] ✅ Closed openVPNSocketFD_");
            saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] ✅ Closed openVPNSocketFD_");
        }
    }
    
    void startReadingFromPacketFlow() {
        NSLog(@"[IOSOpenVPNClient] 📖 startReadingFromPacketFlow() called");
        printf("[IOSOpenVPNClient] 📖 startReadingFromPacketFlow() called\n");
        saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] 📖 startReadingFromPacketFlow() called");
        
        // DIAGNOSTIC: Check current thread
        NSString *threadInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Current thread: %@, isMainThread=%d", 
                                [NSThread currentThread].name ?: @"unnamed", 
                                [NSThread isMainThread]];
        NSLog(@"%@", threadInfo);
        printf("%s\n", [threadInfo UTF8String]);
        saveLogToUserDefaults("INFO", [threadInfo UTF8String]);
        
        // DIAGNOSTIC: Check run loop state
        CFRunLoopRef currentRunLoop = CFRunLoopGetCurrent();
        BOOL runLoopExists = currentRunLoop != NULL;
        BOOL runLoopIsWaiting = runLoopExists ? CFRunLoopIsWaiting(currentRunLoop) : NO;
        NSString *runLoopInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Run loop check: exists=%d, isWaiting=%d, address=%p", 
                                runLoopExists, runLoopIsWaiting, currentRunLoop];
        NSLog(@"%@", runLoopInfo);
        printf("%s\n", [runLoopInfo UTF8String]);
        saveLogToUserDefaults("INFO", [runLoopInfo UTF8String]);
        
        if (!adapter_ || !adapter_.packetFlow) {
            NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ Cannot start reading - packetFlow is nil";
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
            return;
        }
        
        // DIAGNOSTIC: Check packetFlow validity
        NSString *packetFlowInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 packetFlow check: address=%p, class=%@", 
                                    (__bridge void *)adapter_.packetFlow, 
                                    NSStringFromClass([adapter_.packetFlow class])];
        NSLog(@"%@", packetFlowInfo);
        printf("%s\n", [packetFlowInfo UTF8String]);
        saveLogToUserDefaults("INFO", [packetFlowInfo UTF8String]);
        
        NSLog(@"[IOSOpenVPNClient] ✅ Starting packet reading loop");
        printf("[IOSOpenVPNClient] ✅ Starting packet reading loop\n");
        saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] ✅ Starting packet reading loop");
        
        // Use a block that captures self as raw pointer (C++ class, not Objective-C object)
        IOSOpenVPNClient *weakSelf = this;
        
        // Define the reading handler
        // Use __block to allow the block to capture itself for recursive calls
        // Note: We suppress the retain cycle warning because the block will be released
        // when packetFlow stops using it, breaking the cycle
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Warc-retain-cycles"
        __block void (^readingHandler)(NSArray<NSData *> *, NSArray<NSNumber *> *) = ^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
            // Create weak reference to avoid retain cycle in recursive calls
            __weak void (^weakReadingHandler)(NSArray<NSData *> *, NSArray<NSNumber *> *) = readingHandler;
            
            // CRITICAL: Log immediately at the start of handler
            NSTimeInterval handlerTime = [[NSDate date] timeIntervalSince1970];
            NSString *handlerThread = [NSString stringWithFormat:@"%@", [NSThread currentThread].name ?: @"unnamed"];
            NSString *handlerEntryMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 📥 readingHandler ENTERED: packets=%lu, protocols=%lu, thread=%@, timestamp=%.6f", 
                                        (unsigned long)packets.count, (unsigned long)protocols.count, handlerThread, handlerTime];
            NSLog(@"%@", handlerEntryMsg);
            printf("%s\n", [handlerEntryMsg UTF8String]);
            saveLogToUserDefaults("INFO", [handlerEntryMsg UTF8String]);
            
            // DIAGNOSTIC: Check if handler is called on correct thread
            CFRunLoopRef handlerRunLoop = CFRunLoopGetCurrent();
            NSString *handlerRunLoopInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Handler run loop: %p, isMainThread=%d", 
                                           handlerRunLoop, [NSThread isMainThread]];
            NSLog(@"%@", handlerRunLoopInfo);
            printf("%s\n", [handlerRunLoopInfo UTF8String]);
            saveLogToUserDefaults("INFO", [handlerRunLoopInfo UTF8String]);
            
            IOSOpenVPNClient *strongSelf = weakSelf;
            if (!strongSelf) {
                NSLog(@"[IOSOpenVPNClient] ⚠️ readingHandler: strongSelf is null");
                saveLogToUserDefaults("WARNING", "[IOSOpenVPNClient] ⚠️ readingHandler: strongSelf is null");
                return;
            }
            if (!strongSelf->adapter_ || !strongSelf->adapter_.packetFlow || !strongSelf->openVPNSocket_) {
                NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ readingHandler: adapter_/packetFlow/openVPNSocket_ is null";
                NSLog(@"%@", errorMsg);
                printf("%s\n", [errorMsg UTF8String]);
                saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                return;
            }
            
            // Write packets to OpenVPN3 socket
            // iOS packetFlow provides data WITHOUT prefix, but with protocol in separate array
            // OpenVPN3 expects data WITH 4-byte protocol prefix (like OpenVPNPacket.vpnData format)
            if (packets.count > 0) {
                NSString *logMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 📥 Received %lu packet(s) from packetFlow", (unsigned long)packets.count];
                NSLog(@"%@", logMsg);
                printf("%s\n", [logMsg UTF8String]);
                saveLogToUserDefaults("INFO", [logMsg UTF8String]);
            }
            
            for (NSUInteger i = 0; i < packets.count && i < protocols.count; i++) {
                @try {
                    NSData *packetData = packets[i];
                    NSNumber *protocolFamily = protocols[i];
                    
                    NSString *packetInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Processing packet[%lu]: length=%lu, protocol=%@", 
                                            (unsigned long)i, (unsigned long)packetData.length, protocolFamily];
                    NSLog(@"%@", packetInfo);
                    printf("%s\n", [packetInfo UTF8String]);
                    saveLogToUserDefaults("INFO", [packetInfo UTF8String]);
                    // TUNNEL DEBUG: first 5 packets FROM device — видно, шлёт ли iOS трафик в туннель и куда
                    if (i < 5 && packetData.length >= 20) {
                        NSString *sum = _tunnelDebugIPv4Summary(packetData);
                        if (sum.length) {
                            NSString *msg = [NSString stringWithFormat:@"[TUNNEL DEBUG] FROM_DEVICE pkt%lu: %@", (unsigned long)i, sum];
                            saveLogToUserDefaults("INFO", [msg UTF8String]);
                        }
                    }
                    if (packetData.length == 0) {
                        NSLog(@"[IOSOpenVPNClient] ⚠️ Skipping empty packet[%lu]", (unsigned long)i);
                        continue;
                    }
                    
                    // Add 4-byte protocol prefix for OpenVPN3 (big-endian uint32_t)
                    uint32_t protocol = [protocolFamily unsignedIntValue];
                    uint32_t protocolPrefix = CFSwapInt32HostToBig(protocol); // Convert to big-endian
                    
                    NSMutableData *vpnData = [NSMutableData dataWithCapacity:4 + packetData.length];
                    [vpnData appendBytes:&protocolPrefix length:4];
                    [vpnData appendData:packetData];
                    
                    NSString *sendInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 About to send packet[%lu] to OpenVPN3: totalSize=%lu, protocol=0x%08x", 
                                         (unsigned long)i, (unsigned long)vpnData.length, protocol];
                    NSLog(@"%@", sendInfo);
                    printf("%s\n", [sendInfo UTF8String]);
                    saveLogToUserDefaults("INFO", [sendInfo UTF8String]);
                    
                    // Send to OpenVPN3 socket
                    // Use timeout 0.05 like in original OpenVPNAdapter
                    CFSocketError sendResult = CFSocketSendData(strongSelf->openVPNSocket_, NULL, (__bridge CFDataRef)vpnData, 0.05);
                    if (sendResult != kCFSocketSuccess) {
                        NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ Failed to send packet[%lu] to OpenVPN3: error=%ld", 
                                              (unsigned long)i, (long)sendResult];
                        NSLog(@"%@", errorMsg);
                        printf("%s\n", [errorMsg UTF8String]);
                        saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                    } else {
                            NSString *successMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ✅ Successfully sent packet[%lu] to OpenVPN3: %lu bytes", 
                                               (unsigned long)i, (unsigned long)vpnData.length];
                        NSLog(@"%@", successMsg);
                        printf("%s\n", [successMsg UTF8String]);
                        fflush(stdout); // Force flush
                        saveLogToUserDefaults("INFO", [successMsg UTF8String]);
                        // Diagnostic: remember last sent packet (raw IP, no prefix) to detect echo in callback
                        {
                            std::lock_guard<std::mutex> lock(strongSelf->lastSentPacketMutex_);
                            const uint8_t *ptr = (const uint8_t *)packetData.bytes;
                            strongSelf->lastSentPacket_.assign(ptr, ptr + packetData.length);
                        }
                        // CRITICAL: Force sync after each packet to ensure logs are saved before possible crash
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    }
                } @catch (NSException *e) {
                    NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION processing packet[%lu]: %@, stack=%@", 
                                         (unsigned long)i, e.reason, e.callStackSymbols];
                    NSLog(@"%@", errorMsg);
                    printf("%s\n", [errorMsg UTF8String]);
                    fflush(stdout);
                    saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
                    [[NSUserDefaults standardUserDefaults] synchronize];
                }
            }
            
            NSString *loopCompleteMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ✅ Finished processing %lu packet(s)", (unsigned long)packets.count];
            NSLog(@"%@", loopCompleteMsg);
            printf("%s\n", [loopCompleteMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("INFO", [loopCompleteMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize]; // Force sync after loop
            
            // Continue reading (recursive call to same handler)
            // CRITICAL: Must be called on main queue
            NSString *continueMsg = @"[IOSOpenVPNClient] 🔄 About to continue reading packets (recursive call)";
            NSLog(@"%@", continueMsg);
            printf("%s\n", [continueMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("INFO", [continueMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            
            // Capture weak reference explicitly to avoid retain cycle
            __weak void (^capturedWeakHandler)(NSArray<NSData *> *, NSArray<NSNumber *> *) = weakReadingHandler;
            dispatch_async(dispatch_get_main_queue(), ^{
                @try {
                    NSString *continueOnMainMsg = @"[IOSOpenVPNClient] 🔄 Continuing reading on main queue";
                    NSLog(@"%@", continueOnMainMsg);
                    printf("%s\n", [continueOnMainMsg UTF8String]);
                    fflush(stdout);
                    saveLogToUserDefaults("INFO", [continueOnMainMsg UTF8String]);
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    
                    if (!strongSelf->adapter_ || !strongSelf->adapter_.packetFlow) {
                        NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ Cannot continue reading - packetFlow is nil";
                        NSLog(@"%@", errorMsg);
                        printf("%s\n", [errorMsg UTF8String]);
                        fflush(stdout);
                        saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                        [[NSUserDefaults standardUserDefaults] synchronize];
                        return;
                    }
                    
                    NSString *beforeRecursiveMsg = @"[IOSOpenVPNClient] 🔄 Calling readPacketsWithCompletionHandler recursively";
                    NSLog(@"%@", beforeRecursiveMsg);
                    printf("%s\n", [beforeRecursiveMsg UTF8String]);
                    fflush(stdout);
                    saveLogToUserDefaults("INFO", [beforeRecursiveMsg UTF8String]);
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    
                    // Use weak reference to avoid retain cycle
                    void (^strongReadingHandler)(NSArray<NSData *> *, NSArray<NSNumber *> *) = capturedWeakHandler;
                    if (strongReadingHandler) {
                        [strongSelf->adapter_.packetFlow readPacketsWithCompletionHandler:strongReadingHandler];
                    } else {
                        NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ Cannot continue reading - readingHandler was deallocated";
                        NSLog(@"%@", errorMsg);
                        saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                    }
                    
                    NSString *afterRecursiveMsg = @"[IOSOpenVPNClient] ✅ Recursive readPacketsWithCompletionHandler called successfully";
                    NSLog(@"%@", afterRecursiveMsg);
                    printf("%s\n", [afterRecursiveMsg UTF8String]);
                    fflush(stdout);
                    saveLogToUserDefaults("INFO", [afterRecursiveMsg UTF8String]);
                    [[NSUserDefaults standardUserDefaults] synchronize];
                } @catch (NSException *e) {
                    NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION in readingHandler continuation: %@, stack=%@", 
                                         e.reason, e.callStackSymbols];
                    NSLog(@"%@", errorMsg);
                    printf("%s\n", [errorMsg UTF8String]);
                    fflush(stdout);
                    saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
                    [[NSUserDefaults standardUserDefaults] synchronize];
                }
            });
        };
        #pragma clang diagnostic pop
        
        // DIAGNOSTIC: Store block pointer for verification
        void *blockPtr = (__bridge void *)readingHandler;
        NSString *blockInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Block created: address=%p", blockPtr];
        NSLog(@"%@", blockInfo);
        printf("%s\n", [blockInfo UTF8String]);
        saveLogToUserDefaults("INFO", [blockInfo UTF8String]);
        
        // Start reading
        NSLog(@"[IOSOpenVPNClient] 📖 Calling readPacketsWithCompletionHandler...");
        printf("[IOSOpenVPNClient] 📖 Calling readPacketsWithCompletionHandler...\n");
        saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] 📖 Calling readPacketsWithCompletionHandler...");
        
        // DIAGNOSTIC: Check if packetFlow is still valid right before call
        if (!adapter_ || !adapter_.packetFlow) {
            NSString *errorMsg = @"[IOSOpenVPNClient] ❌ packetFlow became nil right before readPackets call!";
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            return;
        }
        
        // CRITICAL: readPacketsWithCompletionHandler must be called on the Extension's main queue
        // OpenVPN3 may call tun_builder_establish from a background thread, but NEPacketTunnelFlow
        // requires calls on the Extension's main queue
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                // DIAGNOSTIC: Log timestamp before call
                NSTimeInterval beforeCall = [[NSDate date] timeIntervalSince1970];
                NSString *beforeCallMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Before readPackets call (on main queue): timestamp=%.6f, thread=%@", 
                                          beforeCall, [NSThread currentThread].name ?: @"unnamed"];
                NSLog(@"%@", beforeCallMsg);
                printf("%s\n", [beforeCallMsg UTF8String]);
                saveLogToUserDefaults("INFO", [beforeCallMsg UTF8String]);
                
                // DIAGNOSTIC: Verify we're on main queue
                NSString *queueInfo = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 Queue check: isMainThread=%d, isMainQueue=%d", 
                                      [NSThread isMainThread], dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL) != NULL];
                NSLog(@"%@", queueInfo);
                printf("%s\n", [queueInfo UTF8String]);
                saveLogToUserDefaults("INFO", [queueInfo UTF8String]);
                
                if (!adapter_ || !adapter_.packetFlow) {
                    NSString *errorMsg = @"[IOSOpenVPNClient] ❌ packetFlow became nil on main queue!";
                    NSLog(@"%@", errorMsg);
                    printf("%s\n", [errorMsg UTF8String]);
                    saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
                    return;
                }
                
                [adapter_.packetFlow readPacketsWithCompletionHandler:readingHandler];
            
                // DIAGNOSTIC: Log timestamp after call (should be immediate)
                NSTimeInterval afterCall = [[NSDate date] timeIntervalSince1970];
                NSString *afterCallMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 After readPackets call: timestamp=%.6f, elapsed=%.6f", 
                                         afterCall, afterCall - beforeCall];
                NSLog(@"%@", afterCallMsg);
                printf("%s\n", [afterCallMsg UTF8String]);
                saveLogToUserDefaults("INFO", [afterCallMsg UTF8String]);
                
                NSLog(@"[IOSOpenVPNClient] ✅ readPacketsWithCompletionHandler called successfully (on main queue)");
                printf("[IOSOpenVPNClient] ✅ readPacketsWithCompletionHandler called successfully (on main queue)\n");
                saveLogToUserDefaults("INFO", "[IOSOpenVPNClient] ✅ readPacketsWithCompletionHandler called successfully (on main queue)");
                
                // DIAGNOSTIC: Schedule a delayed check to see if handler was called
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    NSString *delayedCheck = @"[IOSOpenVPNClient] 🔍 Delayed check (1s): If handler was called, you should see 'readingHandler ENTERED' above";
                    NSLog(@"%@", delayedCheck);
                    printf("%s\n", [delayedCheck UTF8String]);
                    saveLogToUserDefaults("INFO", [delayedCheck UTF8String]);
                });
                
            } @catch (NSException *e) {
                NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION calling readPacketsWithCompletionHandler: %@, stack=%@", 
                                      e.reason, e.callStackSymbols];
                NSLog(@"%@", errorMsg);
                printf("%s\n", [errorMsg UTF8String]);
                saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            }
        });
    }
    
    // Static callback for CFSocket
    // Called when data arrives from OpenVPN3 (on packetFlowSocket_)
    // OpenVPN3 data already contains 4-byte protocol prefix, we need to extract it
    static void PacketFlowSocketCallback(CFSocketRef socket, CFSocketCallBackType type, CFDataRef address, const void *data, void *info) {
        // CRITICAL: Force immediate log synchronization at callback entry
        fflush(stdout);
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        // Get thread info for debugging
        NSString *threadName = [NSThread isMainThread] ? @"Main" : [NSThread currentThread].name ?: @"Unknown";
        NSTimeInterval timestamp = [[NSDate date] timeIntervalSince1970];
        
        NSString *entryMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔔 PacketFlowSocketCallback ENTERED: type=%lu, thread=%@, timestamp=%.6f", 
                              (unsigned long)type, threadName, timestamp];
        NSLog(@"%@", entryMsg);
        printf("%s\n", [entryMsg UTF8String]);
        fflush(stdout);
        saveLogToUserDefaults("INFO", [entryMsg UTF8String]);
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        if (type != kCFSocketDataCallBack) {
            NSString *nonDataMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: ignoring non-data callback (type=%lu, expected=%lu)", 
                                    (unsigned long)type, (unsigned long)kCFSocketDataCallBack];
            NSLog(@"%@", nonDataMsg);
            printf("%s\n", [nonDataMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("WARNING", [nonDataMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        // Additional validation: data should not be null for data callbacks
        if (!data) {
            NSString *nullDataMsg = @"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: data is null for data callback!";
            NSLog(@"%@", nullDataMsg);
            printf("%s\n", [nullDataMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("WARNING", [nullDataMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        // Note: For C++ classes, we use static_cast, not __bridge
        IOSOpenVPNClient *client = static_cast<IOSOpenVPNClient *>(info);
        if (!client) {
            NSLog(@"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: client is null");
            saveLogToUserDefaults("WARNING", "[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: client is null");
            return;
        }
        if (!client->adapter_ || !client->adapter_.packetFlow) {
            NSLog(@"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: adapter_ or packetFlow is null");
            saveLogToUserDefaults("WARNING", "[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: adapter_ or packetFlow is null");
            return;
        }
        
        // Data from OpenVPN3 -> write to NEPacketTunnelFlow
        // OpenVPN3 already adds 4-byte protocol prefix (like OpenVPNPacket.vpnData format)
        // CRITICAL: data is CFDataRef - we need to convert it to NSData IMMEDIATELY
        // and create a copy to ensure it's valid after callback returns
        CFDataRef cfData = (CFDataRef)data;
        if (!cfData) {
            NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: CFDataRef is null";
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        // Get length from CFData
        CFIndex dataLength = CFDataGetLength(cfData);
        if (dataLength < 4) {
            NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ Received packet too short: %ld bytes", (long)dataLength];
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        // CRITICAL: Create NSData copy IMMEDIATELY - CFData may become invalid after callback returns
        NSData *vpnData = nil;
        @try {
            const UInt8 *bytes = CFDataGetBytePtr(cfData);
            if (!bytes) {
                NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: CFDataGetBytePtr returned null";
                NSLog(@"%@", errorMsg);
                printf("%s\n", [errorMsg UTF8String]);
                fflush(stdout);
                saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                [[NSUserDefaults standardUserDefaults] synchronize];
                return;
            }
            // Create NSData copy - this ensures data is valid after callback returns
            vpnData = [NSData dataWithBytes:bytes length:dataLength];
        } @catch (NSException *e) {
            NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION creating NSData from CFData: %@", e.reason];
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        if (!vpnData || vpnData.length < 4) {
            NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ Failed to create valid NSData: length=%lu", (unsigned long)(vpnData ? vpnData.length : 0)];
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        NSString *logMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 📤 Received packet from OpenVPN3: %lu bytes", (unsigned long)vpnData.length];
        NSLog(@"%@", logMsg);
        printf("%s\n", [logMsg UTF8String]);
        fflush(stdout);
        saveLogToUserDefaults("INFO", [logMsg UTF8String]);
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        // Diagnostic: log first bytes of payload for first 3 received packets (to confirm what OpenVPN3 writes)
        static int s_receivedFromVPNCount = 0;
        if (s_receivedFromVPNCount < 3 && vpnData.length >= 4) {
            s_receivedFromVPNCount++;
            NSData *payload = [vpnData subdataWithRange:NSMakeRange(4, MIN(32u, (unsigned)(vpnData.length - 4)))];
            NSMutableString *hex = [NSMutableString stringWithCapacity:payload.length * 3];
            const uint8_t *p = (const uint8_t *)payload.bytes;
            for (NSUInteger i = 0; i < payload.length; i++) {
                if (i) [hex appendString:@" "];
                [hex appendFormat:@"%02x", p[i]];
            }
            if (payload.length >= 20) {
                NSString *dir = [NSString stringWithFormat:@"%u.%u.%u.%u -> %u.%u.%u.%u", p[12], p[13], p[14], p[15], p[16], p[17], p[18], p[19]];
                saveLogToUserDefaults("INFO", [NSString stringWithFormat:@"[TUNNEL DEBUG] FROM_OPENVPN3 #%d: %lu bytes, first 32b hex: %@, src->dst: %@", s_receivedFromVPNCount, (unsigned long)(vpnData.length - 4), hex, dir].UTF8String);
            } else {
                saveLogToUserDefaults("INFO", [NSString stringWithFormat:@"[TUNNEL DEBUG] FROM_OPENVPN3 #%d: %lu bytes, hex: %@", s_receivedFromVPNCount, (unsigned long)(vpnData.length - 4), hex].UTF8String);
            }
        }
        
        // CRITICAL: Extract data IMMEDIATELY - we have a copy now, so it's safe
        uint32_t protocol = 0;
        @try {
            [vpnData getBytes:&protocol length:4];
            protocol = CFSwapInt32BigToHost(protocol); // Convert from big-endian to host byte order
        } @catch (NSException *e) {
            NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION extracting protocol: %@", e.reason];
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        // Extract packet data (skip 4-byte prefix) - we have a copy, so this is safe
        NSData *packetDataSubdata = nil;
        @try {
            packetDataSubdata = [vpnData subdataWithRange:NSMakeRange(4, vpnData.length - 4)];
            if (!packetDataSubdata || packetDataSubdata.length == 0) {
                NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ Packet data extraction resulted in empty data";
                NSLog(@"%@", errorMsg);
                printf("%s\n", [errorMsg UTF8String]);
                fflush(stdout);
                saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                [[NSUserDefaults standardUserDefaults] synchronize];
                return;
            }
        } @catch (NSException *e) {
            NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION extracting packet data: %@", e.reason];
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        // CRITICAL: Create an explicit copy of packetData before passing to async block
        // subdataWithRange returns an autoreleased object that may be deallocated
        // before the async block executes. Creating a copy ensures data validity.
        NSData *packetData = [packetDataSubdata copy];
        if (!packetData || packetData.length == 0) {
            NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ Failed to create packetData copy";
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
        
        // Diagnostic: check if received packet is identical to last sent (echo = wrong fd or OpenVPN3 bug)
        {
            std::lock_guard<std::mutex> lock(client->lastSentPacketMutex_);
            if (!client->lastSentPacket_.empty() && client->lastSentPacket_.size() == packetData.length &&
                memcmp(client->lastSentPacket_.data(), packetData.bytes, packetData.length) == 0) {
                saveLogToUserDefaults("WARNING", "[TUNNEL DEBUG] ECHO DETECTED: received packet is IDENTICAL to last sent (request echoed back - check fd assignment or OpenVPN3 tun write)");
            }
        }
        
        // Convert protocol to AF_INET/AF_INET6 format for iOS
        // OpenVPN3 uses PF_INET (2) / PF_INET6 (30), iOS uses AF_INET (2) / AF_INET6 (30)
        // They're the same values, so we can use directly
        NSNumber *protocolFamily = @(protocol);
        
        // Write to packetFlow (iOS expects data WITHOUT prefix, but with protocol in separate array)
        // CRITICAL: Always use dispatch_async for writePackets, even on main thread
        // This prevents blocking the CFSocket callback and allows run loop to process other events
        // Synchronous writePackets calls can cause deadlocks or crashes when multiple callbacks fire
        @try {
            // Double-check adapter and packetFlow are still valid
            if (!client->adapter_ || !client->adapter_.packetFlow) {
                NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: adapter_ or packetFlow became null before write";
                NSLog(@"%@", errorMsg);
                printf("%s\n", [errorMsg UTF8String]);
                fflush(stdout);
                saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                [[NSUserDefaults standardUserDefaults] synchronize];
                return;
            }
            
            // CRITICAL: Always use dispatch_async for writePackets, even on main thread
            // This prevents blocking the CFSocket callback and allows run loop to process other events
            // Synchronous writePackets calls can cause deadlocks or crashes when multiple callbacks fire
            // Block automatically retains captured objects (ARC), so packetData and protocolFamily are safe
            // Capture protocol primitive by value for logging
            uint32_t capturedProtocol = protocol;
            
            dispatch_async(dispatch_get_main_queue(), ^{
                @autoreleasepool {
                    @try {
                        // Double-check adapter and packetFlow are still valid (inside async block)
                        if (!client->adapter_ || !client->adapter_.packetFlow) {
                            NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: adapter_ or packetFlow became null in async write";
                            NSLog(@"%@", errorMsg);
                            printf("%s\n", [errorMsg UTF8String]);
                            fflush(stdout);
                            saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                            [[NSUserDefaults standardUserDefaults] synchronize];
                            return;
                        }
                        
                        // Verify packetData is still valid (inside async block)
                        // Block automatically retains packetData, so it should remain valid
                        if (!packetData || packetData.length == 0) {
                            NSString *errorMsg = @"[IOSOpenVPNClient] ⚠️ PacketFlowSocketCallback: packetData is invalid in async write";
                            NSLog(@"%@", errorMsg);
                            printf("%s\n", [errorMsg UTF8String]);
                            fflush(stdout);
                            saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                            [[NSUserDefaults standardUserDefaults] synchronize];
                            return;
                        }
                        
                        // Write packet asynchronously - this prevents blocking the CFSocket callback
                        [client->adapter_.packetFlow writePackets:@[packetData] withProtocols:@[protocolFamily]];
                        // TUNNEL DEBUG: first 5 packets TO device — что мы отдаём обратно в стек
                        static int s_tunnelDebugWriteCount = 0;
                        s_tunnelDebugWriteCount++;
                        if (s_tunnelDebugWriteCount <= 5 && packetData.length >= 20) {
                            NSString *sum = _tunnelDebugIPv4Summary(packetData);
                            if (sum.length) {
                                NSString *msg = [NSString stringWithFormat:@"[TUNNEL DEBUG] TO_DEVICE #%d: %@", s_tunnelDebugWriteCount, sum];
                                saveLogToUserDefaults("INFO", [msg UTF8String]);
                            }
                        }
                        NSString *writeLogMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ✅ Wrote packet to packetFlow: %lu bytes, protocol=%u", (unsigned long)packetData.length, capturedProtocol];
                        NSLog(@"%@", writeLogMsg);
                        printf("%s\n", [writeLogMsg UTF8String]);
                        fflush(stdout);
                        saveLogToUserDefaults("INFO", [writeLogMsg UTF8String]);
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (NSException *e) {
                        NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION in async writePackets: %@, stack=%@", e.reason, e.callStackSymbols];
                        NSLog(@"%@", errorMsg);
                        printf("%s\n", [errorMsg UTF8String]);
                        fflush(stdout);
                        saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    }
                }
            });
        } @catch (NSException *e) {
            NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION writing to packetFlow: %@, stack=%@", e.reason, e.callStackSymbols];
            NSLog(@"%@", errorMsg);
            printf("%s\n", [errorMsg UTF8String]);
            fflush(stdout);
            saveLogToUserDefaults("ERROR", [errorMsg UTF8String]);
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
    }
    
    void tun_builder_teardown(bool disconnect) override {
        NSString *logMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 📝 tun_builder_teardown(disconnect=%d) called", disconnect];
        NSLog(@"%@", logMsg);
        printf("%s\n", [logMsg UTF8String]);
        saveLogToUserDefaults("INFO", [logMsg UTF8String]);
        
        // Clean up sockets
        invalidateSockets();
        
        // Notify adapter that tunnel is torn down
        dispatch_async(dispatch_get_main_queue(), ^{
            if (adapter_) {
                [adapter_ onDisconnected];
            }
        });
    }
    
    void event(const Event &ev) override {
        @try {
            printf("[IOSOpenVPNClient] 📢 Event received: %s - %s\n", ev.name.c_str(), ev.info.c_str());
            NSLog(@"[IOSOpenVPNClient] 📢 Event: %s - %s", ev.name.c_str(), ev.info.c_str());
            
            // CRITICAL: Save event to UserDefaults IMMEDIATELY
            @try {
                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                NSString *eventName = [NSString stringWithUTF8String:ev.name.c_str()];
                NSString *eventInfo = ev.info.empty() ? @"" : [NSString stringWithUTF8String:ev.info.c_str()];
                NSString *eventMsg = eventInfo.length > 0 ? [NSString stringWithFormat:@"[IOSOpenVPNClient] 📢 Event: %@ - %@", eventName, eventInfo] : [NSString stringWithFormat:@"[IOSOpenVPNClient] 📢 Event: %@", eventName];
                [logs addObject:@{
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"level": @"INFO",
                    @"message": eventMsg
                }];
                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                [[NSUserDefaults standardUserDefaults] synchronize];
            } @catch (...) {}
            
            NSString *eventName = [NSString stringWithUTF8String:ev.name.c_str()];
            NSString *eventInfo = [NSString stringWithUTF8String:ev.info.c_str()];
            
            if (ev.name == "CONNECTED") {
                printf("[IOSOpenVPNClient] ✅ CONNECTED event received\n");
                NSLog(@"[IOSOpenVPNClient] ✅ CONNECTED event received");
                
                // CRITICAL: Save CONNECTED event to UserDefaults IMMEDIATELY
                @try {
                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": @"[IOSOpenVPNClient] ✅ CONNECTED event received"
                    }];
                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                } @catch (...) {}
                
                // DIAGNOSTIC: Verify CFSocket and run loop state after CONNECTED
                @try {
                    CFRunLoopRef currentRunLoop = CFRunLoopGetCurrent();
                    BOOL isWaiting = CFRunLoopIsWaiting(currentRunLoop);
                    BOOL isCurrent = CFRunLoopGetCurrent() == currentRunLoop;
                    CFRunLoopMode currentMode = CFRunLoopCopyCurrentMode(currentRunLoop);
                    // Create a copy of the string before releasing CFString to avoid use-after-release
                    NSString *modeStr = currentMode ? [NSString stringWithString:(__bridge NSString *)currentMode] : @"unknown";
                    if (currentMode) CFRelease(currentMode);
                    
                    BOOL socketValid = packetFlowSocket_ ? CFSocketIsValid(packetFlowSocket_) : NO;
                    NSString *connectedCheckMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 After CONNECTED: RunLoop=%p (waiting=%d, current=%d, mode=%@), Socket valid=%d", 
                                                   currentRunLoop, isWaiting, isCurrent, modeStr, socketValid];
                    NSLog(@"%@", connectedCheckMsg);
                    printf("%s\n", [connectedCheckMsg UTF8String]);
                    fflush(stdout);
                    saveLogToUserDefaults("INFO", [connectedCheckMsg UTF8String]);
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    
                    // CRITICAL: Check if there's data available in the socket using select()
                    // This helps diagnose if OpenVPN3 is writing data but CFSocket callback isn't firing
                    if (packetFlowSocket_ && socketValid) {
                        CFSocketNativeHandle nativeFD = CFSocketGetNative(packetFlowSocket_);
                        if (nativeFD != -1) {
                            fd_set readfds;
                            struct timeval timeout;
                            FD_ZERO(&readfds);
                            FD_SET(nativeFD, &readfds);
                            timeout.tv_sec = 0;
                            timeout.tv_usec = 100000; // 100ms timeout
                            
                            int selectResult = select(nativeFD + 1, &readfds, NULL, NULL, &timeout);
                            if (selectResult > 0 && FD_ISSET(nativeFD, &readfds)) {
                                NSString *dataAvailableMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ DATA AVAILABLE in socket but callback not called! FD=%d, selectResult=%d", nativeFD, selectResult];
                                NSLog(@"%@", dataAvailableMsg);
                                printf("%s\n", [dataAvailableMsg UTF8String]);
                                fflush(stdout);
                                saveLogToUserDefaults("WARNING", [dataAvailableMsg UTF8String]);
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } else if (selectResult == 0) {
                                NSString *noDataMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 No data available in socket (FD=%d) - OpenVPN3 may not have written yet", nativeFD];
                                NSLog(@"%@", noDataMsg);
                                printf("%s\n", [noDataMsg UTF8String]);
                                fflush(stdout);
                                saveLogToUserDefaults("INFO", [noDataMsg UTF8String]);
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } else {
                                NSString *selectErrorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ select() error: %s (FD=%d)", strerror(errno), nativeFD];
                                NSLog(@"%@", selectErrorMsg);
                                printf("%s\n", [selectErrorMsg UTF8String]);
                                fflush(stdout);
                                saveLogToUserDefaults("WARNING", [selectErrorMsg UTF8String]);
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            }
                        } else {
                            NSString *noFDMsg = @"[IOSOpenVPNClient] ⚠️ Could not get native FD from CFSocket";
                            NSLog(@"%@", noFDMsg);
                            printf("%s\n", [noFDMsg UTF8String]);
                            fflush(stdout);
                            saveLogToUserDefaults("WARNING", [noFDMsg UTF8String]);
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        }
                    }
                    
                    // Schedule delayed check (2 seconds) to see if data arrives
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        @try {
                            if (packetFlowSocket_ && CFSocketIsValid(packetFlowSocket_)) {
                                CFSocketNativeHandle nativeFD = CFSocketGetNative(packetFlowSocket_);
                                if (nativeFD != -1) {
                                    fd_set readfds;
                                    struct timeval timeout;
                                    FD_ZERO(&readfds);
                                    FD_SET(nativeFD, &readfds);
                                    timeout.tv_sec = 0;
                                    timeout.tv_usec = 500000; // 500ms timeout
                                    
                                    int selectResult = select(nativeFD + 1, &readfds, NULL, NULL, &timeout);
                                    if (selectResult > 0 && FD_ISSET(nativeFD, &readfds)) {
                                        NSString *delayedDataMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ DELAYED CHECK (2s): Data AVAILABLE but callback not called! FD=%d", nativeFD];
                                        NSLog(@"%@", delayedDataMsg);
                                        printf("%s\n", [delayedDataMsg UTF8String]);
                                        fflush(stdout);
                                        saveLogToUserDefaults("WARNING", [delayedDataMsg UTF8String]);
                                        [[NSUserDefaults standardUserDefaults] synchronize];
                                    } else {
                                        NSString *delayedNoDataMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] 🔍 DELAYED CHECK (2s): No data in socket (FD=%d) - OpenVPN3 may not be writing", nativeFD];
                                        NSLog(@"%@", delayedNoDataMsg);
                                        printf("%s\n", [delayedNoDataMsg UTF8String]);
                                        fflush(stdout);
                                        saveLogToUserDefaults("INFO", [delayedNoDataMsg UTF8String]);
                                        [[NSUserDefaults standardUserDefaults] synchronize];
                                    }
                                }
                            }
                        } @catch (NSException *e) {
                            NSString *delayedErrorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ DELAYED CHECK error: %@", e.reason];
                            NSLog(@"%@", delayedErrorMsg);
                            printf("%s\n", [delayedErrorMsg UTF8String]);
                            fflush(stdout);
                            saveLogToUserDefaults("WARNING", [delayedErrorMsg UTF8String]);
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        }
                    });
                } @catch (NSException *e) {
                    NSString *errorMsg = [NSString stringWithFormat:@"[IOSOpenVPNClient] ⚠️ Failed to check run loop state: %@", e.reason];
                    NSLog(@"%@", errorMsg);
                    printf("%s\n", [errorMsg UTF8String]);
                    fflush(stdout);
                    saveLogToUserDefaults("WARNING", [errorMsg UTF8String]);
                    [[NSUserDefaults standardUserDefaults] synchronize];
                }
                
                @try {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        @try {
                            if (adapter_) {
                                [adapter_ onConnected];
                            } else {
                                NSLog(@"[IOSOpenVPNClient] ⚠️ CONNECTED event: adapter_ is nil!");
                                printf("[IOSOpenVPNClient] ⚠️ CONNECTED event: adapter_ is nil!\n");
                                
                                // Save error to UserDefaults
                                @try {
                                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                    [logs addObject:@{
                                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                        @"level": @"WARNING",
                                        @"message": @"[IOSOpenVPNClient] ⚠️ CONNECTED event: adapter_ is nil!"
                                    }];
                                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                    [[NSUserDefaults standardUserDefaults] synchronize];
                                } @catch (...) {}
                            }
                        } @catch (NSException *e) {
                            NSLog(@"[IOSOpenVPNClient] ❌ EXCEPTION in onConnected dispatch: %@", e);
                            printf("[IOSOpenVPNClient] ❌ EXCEPTION in onConnected: %s\n", [e.reason UTF8String]);
                            
                            // Save exception to UserDefaults
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"ERROR",
                                    @"message": [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION in onConnected: %@", e.reason]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                        }
                    });
                } @catch (NSException *e) {
                    NSLog(@"[IOSOpenVPNClient] ❌ EXCEPTION scheduling CONNECTED handler: %@", e);
                    printf("[IOSOpenVPNClient] ❌ EXCEPTION scheduling CONNECTED: %s\n", [e.reason UTF8String]);
                    
                    // Save exception to UserDefaults
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"ERROR",
                            @"message": [NSString stringWithFormat:@"[IOSOpenVPNClient] ❌ EXCEPTION scheduling CONNECTED: %@", e.reason]
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                }
            } else if (ev.name == "DISCONNECTED") {
                printf("[IOSOpenVPNClient] 🔴 DISCONNECTED event received\n");
                NSLog(@"[IOSOpenVPNClient] 🔴 DISCONNECTED event received");
                @try {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        @try {
                            if (adapter_) {
                                [adapter_ onDisconnected];
                            } else {
                                NSLog(@"[IOSOpenVPNClient] ⚠️ DISCONNECTED event: adapter_ is nil!");
                            }
                        } @catch (NSException *e) {
                            NSLog(@"[IOSOpenVPNClient] ❌ EXCEPTION in onDisconnected dispatch: %@", e);
                        }
                    });
                } @catch (NSException *e) {
                    NSLog(@"[IOSOpenVPNClient] ❌ EXCEPTION scheduling DISCONNECTED handler: %@", e);
                }
            } else if (ev.name == "RECONNECTING") {
                printf("[IOSOpenVPNClient] 🔄 RECONNECTING event received\n");
                NSLog(@"[IOSOpenVPNClient] 🔄 RECONNECTING event received");
            } else if (ev.name == "RESOLVE") {
                printf("[IOSOpenVPNClient] 🔍 RESOLVE event: %s\n", ev.info.c_str());
                NSLog(@"[IOSOpenVPNClient] 🔍 RESOLVE event: %@", eventInfo);
            } else if (ev.name == "WAIT") {
                printf("[IOSOpenVPNClient] ⏳ WAIT event: %s\n", ev.info.c_str());
                NSLog(@"[IOSOpenVPNClient] ⏳ WAIT event: %@", eventInfo);
            } else if (ev.name == "AUTH_FAILED") {
                printf("[IOSOpenVPNClient] ❌ AUTH_FAILED event: %s\n", ev.info.c_str());
                NSLog(@"[IOSOpenVPNClient] ❌ AUTH_FAILED event: %@", eventInfo);
            } else if (ev.name == "CONNECTION_TIMEOUT") {
                printf("[IOSOpenVPNClient] ⏱️ CONNECTION_TIMEOUT event: %s\n", ev.info.c_str());
                NSLog(@"[IOSOpenVPNClient] ⏱️ CONNECTION_TIMEOUT event: %@", eventInfo);
            } else {
                printf("[IOSOpenVPNClient] ℹ️ Unknown event: %s - %s\n", ev.name.c_str(), ev.info.c_str());
                NSLog(@"[IOSOpenVPNClient] ℹ️ Unknown event: %@ - %@", eventName, eventInfo);
            }
        } @catch (NSException *e) {
            printf("[IOSOpenVPNClient] ❌ FATAL EXCEPTION in event() handler: %s\n", [e.reason UTF8String]);
            NSLog(@"[IOSOpenVPNClient] ❌ FATAL EXCEPTION in event() handler: %@", e);
            NSLog(@"[IOSOpenVPNClient] Stack trace: %@", e.callStackSymbols);
        }
    }
    
    void log(const LogInfo &log) override {
        NSString *logText = [NSString stringWithUTF8String:log.text.c_str()];
        NSLog(@"[IOSOpenVPNClient] 📝 %@", logText);
    }
    
    bool socket_protect(openvpn_io::detail::socket_type socket, std::string remote, bool ipv6) override {
        // iOS Network Extension handles socket protection automatically
        NSLog(@"[IOSOpenVPNClient] 🔒 socket_protect(socket=%d, remote=%s, ipv6=%d)", socket, remote.c_str(), ipv6);
        return true;
    }
    
    // Required pure virtual methods from OpenVPNClient
    bool pause_on_connection_timeout() override {
        NSLog(@"[IOSOpenVPNClient] ⏸️ pause_on_connection_timeout() called");
        return true; // Pause instead of disconnecting on timeout
    }
    
    void acc_event(const AppCustomControlMessageEvent &event) override {
        NSString *eventName = [NSString stringWithUTF8String:event.protocol.c_str()];
        NSString *eventPayload = [NSString stringWithUTF8String:event.payload.c_str()];
        NSLog(@"[IOSOpenVPNClient] 📨 ACC Event: %@ - %@", eventName, eventPayload);
    }
    
    void external_pki_cert_request(ExternalPKICertRequest &req) override {
        NSLog(@"[IOSOpenVPNClient] 🔑 external_pki_cert_request() - not implemented");
        req.error = true;
        req.errorText = "External PKI not supported";
    }
    
    void external_pki_sign_request(ExternalPKISignRequest &req) override {
        NSLog(@"[IOSOpenVPNClient] ✍️ external_pki_sign_request() - not implemented");
        req.error = true;
        req.errorText = "External PKI not supported";
    }
    
    // Getters for network settings
    std::string getIPv4Address() const { return ipv4_address_; }
    int getIPv4Prefix() const { return ipv4_prefix_; }
    std::string getIPv4Gateway() const { return ipv4_gateway_; }
    std::string getIPv6Address() const { return ipv6_address_; }
    int getIPv6Prefix() const { return ipv6_prefix_; }
    std::string getIPv6Gateway() const { return ipv6_gateway_; }
    std::string getRemoteAddress() const { return remote_address_; }
    bool getRerouteIPv4() const { return reroute_ipv4_; }
    bool getRerouteIPv6() const { return reroute_ipv6_; }
    unsigned int getRerouteFlags() const { return reroute_flags_; }
    const std::vector<RouteInfo>& getRoutes() const { return routes_; }
    const DnsOptions& getDnsOptions() const { return dns_options_; }
    int getMTU() const { return mtu_; }
    
private:
    __weak OpenVPNAdapter *adapter_;
    
    // Network settings storage
    std::string remote_address_;
    bool remote_ipv6_ = false;
    
    std::string ipv4_address_;
    int ipv4_prefix_ = 0;
    std::string ipv4_gateway_;
    
    std::string ipv6_address_;
    int ipv6_prefix_ = 0;
    std::string ipv6_gateway_;
    
    bool reroute_ipv4_ = false;
    bool reroute_ipv6_ = false;
    unsigned int reroute_flags_ = 0;
    
    std::vector<RouteInfo> routes_;
    
    DnsOptions dns_options_;
    int mtu_ = 1500;
    
    // Socket pair for bridging NEPacketTunnelFlow and OpenVPN3
    // Based on OpenVPNAdapter implementation pattern
    CFSocketRef packetFlowSocket_ = nullptr;  // Socket connected to NEPacketTunnelFlow
    CFSocketRef openVPNSocket_ = nullptr;      // Socket passed to OpenVPN3
    int openVPNSocketFD_ = -1;                 // Native FD for OpenVPN3 (returned by tun_builder_establish)
    // Diagnostic: last packet we sent to OpenVPN3 (to detect echo / wrong fd)
    std::mutex lastSentPacketMutex_;
    std::vector<uint8_t> lastSentPacket_;
};

@interface OpenVPNAdapter () {
    std::unique_ptr<IOSOpenVPNClient> client_;
    BOOL isConnecting_;
}

@end

@implementation OpenVPNAdapter

- (instancetype)init {
    printf("[OpenVPNAdapter] init() called\n");
    NSLog(@"🔧 [OpenVPNAdapter] init() called");
    @try {
        self = [super init];
        if (self) {
            isConnecting_ = NO;
            printf("[OpenVPNAdapter] init() completed successfully\n");
            NSLog(@"🔧 [OpenVPNAdapter] init() completed successfully");
        } else {
            printf("[OpenVPNAdapter] init() FAILED - self is nil!\n");
            NSLog(@"❌ [OpenVPNAdapter] init() FAILED - self is nil!");
        }
    } @catch (NSException *exception) {
        printf("[OpenVPNAdapter] init() EXCEPTION: %s\n", exception.reason.UTF8String);
        NSLog(@"❌ [OpenVPNAdapter] init() EXCEPTION: %@", exception);
        NSLog(@"❌ [OpenVPNAdapter] Stack trace: %@", exception.callStackSymbols);
    }
    return self;
}

- (void)startWithConfig:(NSString *)configContent {
    // CRITICAL: Initialize PSA Crypto for mbedTLS 3.6+ (required for TLS 1.3)
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
    static bool psa_initialized = false;
    if (!psa_initialized) {
        psa_status_t status = psa_crypto_init();
        if (status == PSA_SUCCESS) {
            printf("[OpenVPNAdapter] ✅ PSA Crypto initialized successfully\n");
            NSLog(@"[OpenVPNAdapter] ✅ PSA Crypto initialized successfully");
            psa_initialized = true;
        } else {
            printf("[OpenVPNAdapter] ⚠️ PSA Crypto init returned: %d\n", (int)status);
            NSLog(@"[OpenVPNAdapter] ⚠️ PSA Crypto init returned: %d", (int)status);
        }
    }
#endif
    
    // CRITICAL: Log immediately at the very start
    printf("========================================\n");
    printf("[OpenVPNAdapter] ====== startWithConfig CALLED ======\n");
    printf("[OpenVPNAdapter] self: %p\n", (__bridge void *)self);
    printf("[OpenVPNAdapter] Config length: %lu bytes\n", (unsigned long)configContent.length);
    printf("[OpenVPNAdapter] Thread: %s\n", [[NSThread currentThread].description UTF8String]);
    printf("[OpenVPNAdapter] Timestamp: %s\n", [[NSDate date].description UTF8String]);
    printf("========================================\n");
    
    // Save log to UserDefaults immediately - CRITICAL for visibility
    @try {
        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
        [logs addObject:@{
            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
            @"level": @"INFO",
            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ====== startWithConfig CALLED ====== (config: %lu bytes)", (unsigned long)configContent.length]
        }];
        // Keep only last 100 entries
        if (logs.count > 100) {
            [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)];
        }
        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
        [[NSUserDefaults standardUserDefaults] synchronize];
        printf("[OpenVPNAdapter] ✅ Log saved to UserDefaults\n");
    } @catch (NSException *e) {
        printf("[OpenVPNAdapter] ❌ Failed to save log: %s\n", [e.reason UTF8String]);
    }
    
    if (isConnecting_) {
        NSLog(@"[OpenVPNAdapter] ⚠️ Already connecting, ignoring start request");
        printf("[OpenVPNAdapter] Already connecting, ignoring start request\n");
        return;
    }
    
    NSLog(@"[OpenVPNAdapter] 🚀 Starting with config (%lu bytes)", (unsigned long)configContent.length);
    NSLog(@"[OpenVPNAdapter] 📄 Config preview (first 500 chars):\n%@", 
          [configContent substringToIndex:MIN(500, configContent.length)]);
    
    isConnecting_ = YES;
    
    // Run OpenVPN3 connection in background thread
    // Use a named queue so we can identify it in crash reports
    dispatch_queue_t openvpnQueue = dispatch_queue_create("com.datagate.openvpn", DISPATCH_QUEUE_SERIAL);
    dispatch_async(openvpnQueue, ^{
        // CRITICAL: Log immediately at the very start of dispatch_async block
        printf("========================================\n");
        printf("[OpenVPNAdapter] ====== DISPATCH_ASYNC BLOCK STARTED ======\n");
        printf("[OpenVPNAdapter] Thread: %s\n", [[NSThread currentThread].description UTF8String]);
        printf("[OpenVPNAdapter] Timestamp: %s\n", [[NSDate date].description UTF8String]);
        printf("========================================\n");
        
        // Save to UserDefaults immediately
        @try {
            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
            [logs addObject:@{
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"level": @"INFO",
                @"message": @"[OpenVPNAdapter] ====== DISPATCH_ASYNC BLOCK STARTED ======"
            }];
            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        } @catch (...) {}
        
        @autoreleasepool {
            @try {
                // Set thread name for debugging
                NSLog(@"[OpenVPNAdapter] Step 1: Setting thread name...");
                printf("[OpenVPNAdapter] Step 1: Setting thread name...\n");
                [[NSThread currentThread] setName:@"OpenVPN3-Connection"];
                NSLog(@"[OpenVPNAdapter] ✅ Thread name set: %@", [NSThread currentThread].name);
                printf("[OpenVPNAdapter] ✅ Thread name set: %s\n", [[NSThread currentThread].name UTF8String]);
                
                // Install thread-specific terminate handler for uncaught C++ exceptions
                NSLog(@"[OpenVPNAdapter] Step 2: Installing terminate handler...");
                std::set_terminate([]() {
                    @try {
                        NSLog(@"❌ [OpenVPNAdapter] FATAL: std::terminate() called - uncaught C++ exception!");
                        NSLog(@"❌ [OpenVPNAdapter] Timestamp: %@", [NSDate date]);
                        NSString *errorMsg = @"Uncaught C++ exception in OpenVPN3 thread";
                        NSDictionary *errorDict = @{
                            @"domain": @"OpenVPNAdapter",
                            @"code": @(9998),
                            @"description": errorMsg,
                            @"timestamp": @([[NSDate date] timeIntervalSince1970])
                        };
                        [[NSUserDefaults standardUserDefaults] setObject:errorDict forKey:@"DataGateVPNExtension.LastCrash"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                        NSLog(@"❌ [OpenVPNAdapter] Crash info saved to UserDefaults");
                    } @catch (...) {
                        printf("[OpenVPNAdapter] FATAL: Even terminate handler failed!\n");
                    }
                    std::abort(); // Terminate process to generate crash report
                });
                NSLog(@"[OpenVPNAdapter] ✅ Terminate handler installed");
                
                try {
                    printf("[OpenVPNAdapter] Step 3: Creating OpenVPN3 client...\n");
                    NSLog(@"[OpenVPNAdapter] Step 3: Creating OpenVPN3 client...");
                    NSLog(@"[OpenVPNAdapter] 🔧 Creating IOSOpenVPNClient...");
                    
                    // CRITICAL: Check packetFlow before creating client
                    NSLog(@"[OpenVPNAdapter] 🔍 Checking packetFlow before creating client...");
                    printf("[OpenVPNAdapter] 🔍 Checking packetFlow before creating client...\n");
                    if (!self.packetFlow) {
                        NSLog(@"[OpenVPNAdapter] ⚠️ WARNING: packetFlow is nil before creating client!");
                        printf("[OpenVPNAdapter] ⚠️ WARNING: packetFlow is nil before creating client!\n");
                    } else {
                        NSLog(@"[OpenVPNAdapter] ✅ packetFlow is not nil: %p", (__bridge void *)self.packetFlow);
                        printf("[OpenVPNAdapter] ✅ packetFlow is not nil: %p\n", (__bridge void *)self.packetFlow);
                    }
                    
                    // Save log to UserDefaults
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": self.packetFlow ? @"INFO" : @"WARNING",
                            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] Step 3: Creating OpenVPN3 client... (packetFlow: %@)", self.packetFlow ? @"✅ set" : @"⚠️ nil"]
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                    
                    // Create client
                    self->client_ = std::make_unique<IOSOpenVPNClient>(self);
                    printf("[OpenVPNAdapter] ✅ Client created successfully, pointer: %p\n", self->client_.get());
                    NSLog(@"[OpenVPNAdapter] ✅ Client created successfully");
                    NSLog(@"[OpenVPNAdapter] Client pointer: %p", self->client_.get());
                    
                    // Save log to UserDefaults
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"INFO",
                            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ✅ Client created successfully, pointer: %p", self->client_.get()]
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                
                // Parse config
                NSLog(@"[OpenVPNAdapter] Step 4: Parsing config...");
                NSLog(@"[OpenVPNAdapter]    Config length: %lu bytes", (unsigned long)configContent.length);
                NSLog(@"[OpenVPNAdapter]    Timestamp: %@", [NSDate date]);
                
                // Validate config content
                if (!configContent || configContent.length == 0) {
                    NSString *errorMsg = @"Config content is empty";
                    NSLog(@"[OpenVPNAdapter] ❌ %@", errorMsg);
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                             code:0 
                                                         userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                        [self.delegate openVPNAdapter:self didFailWithError:error];
                        self->isConnecting_ = NO;
                    });
                    return;
                }
                
                // Log config preview (first 500 chars)
                NSLog(@"[OpenVPNAdapter]    Config preview (first 500 chars):\n%@", 
                      [configContent substringToIndex:MIN(500, configContent.length)]);
                
                NSLog(@"[OpenVPNAdapter] Step 4.1: Converting config to UTF-8...");
                Config config;
                std::string configStr = std::string([configContent UTF8String]);
                NSLog(@"[OpenVPNAdapter]    Config string length: %zu bytes", configStr.length());
                
                // Validate UTF-8 conversion
                if (configStr.length() == 0 && configContent.length > 0) {
                    NSString *errorMsg = @"Failed to convert config to UTF-8";
                    NSLog(@"[OpenVPNAdapter] ❌ %@", errorMsg);
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                             code:0 
                                                         userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                        [self.delegate openVPNAdapter:self didFailWithError:error];
                        self->isConnecting_ = NO;
                    });
                    return;
                }
                NSLog(@"[OpenVPNAdapter] ✅ UTF-8 conversion successful");
                
                // Check for CA certificate in config
                NSLog(@"[OpenVPNAdapter] Step 4.2: Analyzing config structure...");
                size_t caPos = configStr.find("<ca>");
                size_t caEndPos = configStr.find("</ca>");
                if (caPos != std::string::npos && caEndPos != std::string::npos) {
                    NSLog(@"[OpenVPNAdapter]    ✅ Found <ca> tag at position %zu", caPos);
                    NSLog(@"[OpenVPNAdapter]    ✅ Found </ca> tag at position %zu", caEndPos);
                    
                    size_t caCertStart = configStr.find("-----BEGIN CERTIFICATE-----", caPos);
                    size_t caCertEnd = configStr.find("-----END CERTIFICATE-----", caPos);
                    if (caCertStart != std::string::npos && caCertEnd != std::string::npos) {
                        size_t caCertLen = caCertEnd - caCertStart + strlen("-----END CERTIFICATE-----");
                        NSLog(@"[OpenVPNAdapter]    ✅ Found CA certificate: %zu bytes (pos %zu-%zu)", 
                              caCertLen, caCertStart, caCertEnd);
                        std::string caCert = configStr.substr(caCertStart, caCertLen);
                        NSLog(@"[OpenVPNAdapter]    CA cert full content (%zu bytes):\n%s", 
                              caCert.length(), caCert.c_str());
                        
                        // Check for newlines in certificate
                        size_t newlineCount = std::count(caCert.begin(), caCert.end(), '\n');
                        NSLog(@"[OpenVPNAdapter]    CA cert has %zu newlines", newlineCount);
                    } else {
                        NSLog(@"[OpenVPNAdapter]    ⚠️ CA tag found but certificate markers not found");
                        NSLog(@"[OpenVPNAdapter]    BEGIN marker at: %zu", caCertStart);
                        NSLog(@"[OpenVPNAdapter]    END marker at: %zu", caCertEnd);
                    }
                } else {
                    NSLog(@"[OpenVPNAdapter]    ⚠️ CA certificate section not found in config");
                    NSLog(@"[OpenVPNAdapter]    <ca> tag at: %zu", caPos);
                    NSLog(@"[OpenVPNAdapter]    </ca> tag at: %zu", caEndPos);
                }
                
                NSLog(@"[OpenVPNAdapter] Step 4.3: Following DataGateWin approach - NO normalization");
                // CRITICAL: Following DataGateWin/VpnClient.cpp implementation (line 130)
                // They pass config AS-IS: cfg.content = ovpnContent; (no normalization!)
                // OpenVPN3 will handle CA cert parsing itself via opt.cat("ca") and load_ca()
                // We do the same - pass original config without any modifications
                
                NSLog(@"[OpenVPNAdapter] Step 4.4: Setting config parameters...");
                // CRITICAL: Following DataGateWin implementation - pass config AS-IS without any normalization
                // In DataGateWin/VpnClient.cpp line 130: cfg.content = ovpnContent; (no normalization!)
                // OpenVPN3 will handle CA cert parsing itself via opt.cat("ca") and load_ca()
                config.content = configStr; // Pass original config directly, just like Windows version
                printf("[OpenVPNAdapter] ✅ Using ORIGINAL config (no normalization, like DataGateWin), length = %zu bytes\n", configStr.length());
                NSLog(@"[OpenVPNAdapter] ✅ Using ORIGINAL config (no normalization, like DataGateWin), length = %zu bytes", configStr.length());
                config.serverOverride = ""; // Use server from config
                config.connTimeout = 30;
                config.protoOverride = ""; // Use protocol from config (udp/tcp)
                config.allowLocalDnsResolvers = true;
                NSLog(@"[OpenVPNAdapter] ✅ Config parameters set");
                NSLog(@"[OpenVPNAdapter]    serverOverride: (empty)");
                NSLog(@"[OpenVPNAdapter]    connTimeout: 30");
                NSLog(@"[OpenVPNAdapter]    protoOverride: (empty)");
                NSLog(@"[OpenVPNAdapter]    allowLocalDnsResolvers: true");
                
                printf("[OpenVPNAdapter] Step 5: Evaluating config with OpenVPN3...\n");
                printf("[OpenVPNAdapter] Config string length: %zu bytes\n", configStr.length());
                NSLog(@"[OpenVPNAdapter] Step 5: Evaluating config with OpenVPN3...");
                NSLog(@"[OpenVPNAdapter] 🔍 Calling client_->eval_config()...");
                printf("[OpenVPNAdapter] 🔍 Calling client_->eval_config()...\n");
                
                // Save log to UserDefaults
                @try {
                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] Step 5: Evaluating config with OpenVPN3... (config length: %zu bytes)", configStr.length()]
                    }];
                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                } @catch (...) {}
                
                // Log original config CA certificate format before eval_config (for diagnostics only)
                // Following DataGateWin - we pass config AS-IS, but log for debugging
                // Reuse caPos and caEndPos from Step 4.2 above
                if (caPos != std::string::npos && caEndPos != std::string::npos) {
                    size_t caCertStart = configStr.find("-----BEGIN CERTIFICATE-----", caPos);
                    size_t caCertEnd = configStr.find("-----END CERTIFICATE-----", caPos);
                    if (caCertStart != std::string::npos && caCertEnd != std::string::npos) {
                        std::string caCertRaw = configStr.substr(caCertStart, caCertEnd - caCertStart + strlen("-----END CERTIFICATE-----"));
                        printf("========================================\n");
                        printf("[OpenVPNAdapter] ORIGINAL CA CERTIFICATE (will be passed to OpenVPN3 AS-IS, like DataGateWin)\n");
                        printf("[OpenVPNAdapter] CA cert length: %zu bytes\n", caCertRaw.length());
                        printf("[OpenVPNAdapter] CA cert full content:\n%s\n", caCertRaw.c_str());
                        
                        // Count newlines after END marker
                        size_t endMarkerPos = caCertRaw.find("-----END CERTIFICATE-----");
                        if (endMarkerPos != std::string::npos) {
                            std::string afterEnd = caCertRaw.substr(endMarkerPos + strlen("-----END CERTIFICATE-----"));
                            size_t newlineCount = std::count(afterEnd.begin(), afterEnd.end(), '\n');
                            size_t crCount = std::count(afterEnd.begin(), afterEnd.end(), '\r');
                            printf("[OpenVPNAdapter] Newlines after END: %zu, CRs: %zu\n", newlineCount, crCount);
                            printf("[OpenVPNAdapter] After END marker (hex): ");
                            for (size_t i = 0; i < std::min(afterEnd.length(), (size_t)10); i++) {
                                printf("%02x ", (unsigned char)afterEnd[i]);
                            }
                            printf("\n");
                            
                            // Note: opt.cat("ca") will extract this and pass to load_ca()
                            printf("[OpenVPNAdapter] OpenVPN3 will extract via opt.cat(\"ca\") and pass to load_ca()\n");
                        }
                        printf("========================================\n");
                        
                        // Save to UserDefaults
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] Original CA cert: %zu bytes, %zu newlines after END", caCertRaw.length(), std::count(caCertRaw.begin() + caCertRaw.find("-----END CERTIFICATE-----") + strlen("-----END CERTIFICATE-----"), caCertRaw.end(), '\n')]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                    }
                }
                
                // Evaluate config - wrap in try/catch to catch C++ exceptions from openvpn3
                EvalConfig evalConfig;
                try {
                    printf("[OpenVPNAdapter] About to call eval_config()...\n");
                    evalConfig = self->client_->eval_config(config);
                    printf("[OpenVPNAdapter] ✅ eval_config() completed successfully\n");
                    NSLog(@"[OpenVPNAdapter] ✅ eval_config() completed");
                    
                    // Save log to UserDefaults
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"INFO",
                            @"message": @"[OpenVPNAdapter] ✅ eval_config() completed successfully"
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                } catch (const std::exception &e) {
                    NSString *errorMsg = [NSString stringWithFormat:@"Config evaluation exception: %s", e.what()];
                    printf("========================================\n");
                    printf("[OpenVPNAdapter] ❌ CONFIG EVALUATION C++ EXCEPTION\n");
                    printf("[OpenVPNAdapter] Exception message: %s\n", e.what());
                    printf("========================================\n");
                    NSLog(@"[OpenVPNAdapter] ❌ Config evaluation C++ exception: %@", errorMsg);
                    printf("[OpenVPNAdapter] Config evaluation C++ exception: %s\n", e.what());
                    
                    // Save error log to UserDefaults
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"ERROR",
                            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ Config evaluation C++ exception: %s", e.what()]
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                             code:2 
                                                         userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                        [self.delegate openVPNAdapter:self didFailWithError:error];
                        self->isConnecting_ = NO;
                    });
                    return;
                } catch (...) {
                    NSString *errorMsg = @"Config evaluation unknown C++ exception";
                    NSLog(@"[OpenVPNAdapter] ❌ Config evaluation unknown C++ exception");
                    printf("[OpenVPNAdapter] Config evaluation unknown C++ exception\n");
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                             code:3 
                                                         userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                        [self.delegate openVPNAdapter:self didFailWithError:error];
                        self->isConnecting_ = NO;
                    });
                    return;
                }
                
                if (evalConfig.error) {
                    NSString *errorMsg = [NSString stringWithUTF8String:evalConfig.message.c_str()];
                    printf("========================================\n");
                    printf("[OpenVPNAdapter] ❌ CONFIG EVALUATION ERROR\n");
                    printf("[OpenVPNAdapter] Error message: %s\n", evalConfig.message.c_str());
                    printf("[OpenVPNAdapter] Profile: %s\n", evalConfig.profileName.c_str());
                    printf("========================================\n");
                    NSLog(@"[OpenVPNAdapter] ❌ Config evaluation error: %@", errorMsg);
                    NSLog(@"[OpenVPNAdapter]    Error details: profileName=%@, userlockedUsername=%@", 
                          [NSString stringWithUTF8String:evalConfig.profileName.c_str()],
                          [NSString stringWithUTF8String:evalConfig.userlockedUsername.c_str()]);
                    
                    // Save error log to UserDefaults
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"ERROR",
                            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ Config evaluation error: %@ (profile: %@)", errorMsg, [NSString stringWithUTF8String:evalConfig.profileName.c_str()]]
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                    
                    // Log error to Extension logs (if PacketTunnelProvider has access)
                    NSString *fullErrorMsg = [NSString stringWithFormat:@"Config evaluation failed: %@ (profile: %@)", 
                                              errorMsg,
                                              [NSString stringWithUTF8String:evalConfig.profileName.c_str()]];
                    NSLog(@"[OpenVPNAdapter] ❌ %@", fullErrorMsg);
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                             code:1 
                                                         userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                        [self.delegate openVPNAdapter:self didFailWithError:error];
                        self->isConnecting_ = NO;
                    });
                    return;
                }
                
                NSLog(@"[OpenVPNAdapter] ✅ Config evaluated successfully");
                NSLog(@"[OpenVPNAdapter]    Profile: %s", evalConfig.profileName.c_str());
                NSLog(@"[OpenVPNAdapter]    Remote: %s:%s", evalConfig.remoteHost.c_str(), evalConfig.remotePort.c_str());
                NSString *protoStr = [NSString stringWithUTF8String:evalConfig.remoteProto.c_str()];
                NSLog(@"[OpenVPNAdapter]    Protocol: %@", protoStr);
                
                // CRITICAL: Log CA certificate content that will be passed to mbedTLS during connect()
                NSLog(@"[OpenVPNAdapter] 🔍 Starting CA certificate analysis before connect()...");
                printf("========================================\n");
                printf("[OpenVPNAdapter] 🔍 CA CERTIFICATE ANALYSIS BEFORE CONNECT()\n");
                printf("========================================\n");
                
                // Verify configStr hasn't changed after eval_config() (for diagnostics)
                printf("[OpenVPNAdapter] ⚠️ VERIFYING configStr after eval_config()\n");
                printf("[OpenVPNAdapter] configStr length: %zu bytes\n", configStr.length());
                
                // Check if <ca> tag exists
                size_t checkCaBeforeSearch = configStr.find("<ca>");
                printf("[OpenVPNAdapter] Quick check: <ca> tag found at %zu\n", checkCaBeforeSearch);
                
                // Log configStr state (first/last 500 chars)
                printf("[OpenVPNAdapter] configStr first 500 chars:\n%.500s\n", configStr.c_str());
                if (configStr.length() > 500) {
                    printf("[OpenVPNAdapter] configStr last 500 chars:\n%s\n", configStr.substr(configStr.length() - 500).c_str());
                }
                
                // Save log to UserDefaults immediately - CRITICAL for debugging
                @try {
                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] 🔍 Starting CA certificate analysis before connect()... configStr length: %zu bytes", configStr.length()]
                    }];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] Quick check: <ca> tag found at %zu", checkCaBeforeSearch]
                    }];
                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    printf("[OpenVPNAdapter] ✅ Pre-search logs saved to UserDefaults (total logs: %zu)\n", (size_t)logs.count);
                } @catch (NSException *e) {
                    printf("[OpenVPNAdapter] ❌ Failed to save pre-search logs: %s\n", [e.reason UTF8String]);
                }
                
                size_t finalCaPos = configStr.find("<ca>");
                size_t finalCaEndPos = configStr.find("</ca>");
                
                printf("[OpenVPNAdapter] ⚠️ SEARCH RESULTS: <ca> at %zu, </ca> at %zu\n", finalCaPos, finalCaEndPos);
                
                printf("[OpenVPNAdapter] Searching for <ca> tag: found at %zu\n", finalCaPos);
                printf("[OpenVPNAdapter] Searching for </ca> tag: found at %zu\n", finalCaEndPos);
                
                // Save search results to UserDefaults
                @try {
                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] Searching for <ca> tag: found at %zu", finalCaPos]
                    }];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] Searching for </ca> tag: found at %zu", finalCaEndPos]
                    }];
                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                } @catch (...) {}
                
                if (finalCaPos != std::string::npos && finalCaEndPos != std::string::npos) {
                    NSLog(@"[OpenVPNAdapter] ✅ Found CA section in config");
                    printf("[OpenVPNAdapter] ✅ CA section found: <ca> at %zu, </ca> at %zu\n", finalCaPos, finalCaEndPos);
                    
                    // Log config around CA tags
                    size_t previewStart = finalCaPos > 100 ? finalCaPos - 100 : 0;
                    size_t previewLen = MIN(500, configStr.length() - previewStart);
                    printf("[OpenVPNAdapter] Config around <ca> tag (pos %zu):\n%.*s\n", finalCaPos, (int)previewLen, configStr.c_str() + previewStart);
                    
                    size_t finalCaSectionStart = finalCaPos + 4; // After "<ca>"
                    size_t finalCaSectionEnd = finalCaEndPos;
                    
                    if (finalCaSectionEnd <= finalCaSectionStart) {
                        printf("[OpenVPNAdapter] ❌ ERROR: finalCaSectionEnd (%zu) <= finalCaSectionStart (%zu)\n", finalCaSectionEnd, finalCaSectionStart);
                        NSLog(@"[OpenVPNAdapter] ❌ ERROR: Invalid CA section boundaries");
                        
                        // Save error to UserDefaults
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"ERROR",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ ERROR: Invalid CA section boundaries: finalCaSectionEnd (%zu) <= finalCaSectionStart (%zu)", finalCaSectionEnd, finalCaSectionStart]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                    } else {
                        std::string finalCaSection = configStr.substr(finalCaSectionStart, finalCaSectionEnd - finalCaSectionStart);
                        
                        printf("[OpenVPNAdapter] CA section length: %zu bytes\n", finalCaSection.length());
                        printf("[OpenVPNAdapter] CA section starts at: %zu, ends at: %zu\n", finalCaSectionStart, finalCaSectionEnd);
                        printf("[OpenVPNAdapter] CA section full content:\n%s\n", finalCaSection.c_str());
                        
                        // Save CA section info to UserDefaults
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] CA section found: length %zu bytes, starts at %zu, ends at %zu", finalCaSection.length(), finalCaSectionStart, finalCaSectionEnd]
                            }];
                            NSString *caSectionStr = [NSString stringWithUTF8String:finalCaSection.c_str()];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] CA section full content (%zu bytes):\n%@", finalCaSection.length(), caSectionStr]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        // Find certificate boundaries
                        size_t finalBeginPos = finalCaSection.find("-----BEGIN CERTIFICATE-----");
                        size_t finalEndPos = finalCaSection.find("-----END CERTIFICATE-----");
                        
                        // Log certificate marker search results
                        printf("[OpenVPNAdapter] Searching for BEGIN marker in CA section: found at %zu\n", finalBeginPos);
                        printf("[OpenVPNAdapter] Searching for END marker in CA section: found at %zu\n", finalEndPos);
                        
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] Searching for BEGIN marker in CA section: found at %zu", finalBeginPos]
                            }];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] Searching for END marker in CA section: found at %zu", finalEndPos]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        // CRITICAL: Declare finalCaCert OUTSIDE the if block so it's accessible later
                        std::string finalCaCert;
                        bool certExtracted = false;
                        
                        if (finalBeginPos != std::string::npos && finalEndPos != std::string::npos) {
                        // CRITICAL: Calculate certificate length correctly
                        size_t finalCertLen = finalEndPos - finalBeginPos + strlen("-----END CERTIFICATE-----");
                        printf("[OpenVPNAdapter] ⚠️ EXTRACTING CERTIFICATE:\n");
                        printf("[OpenVPNAdapter] finalBeginPos: %zu\n", finalBeginPos);
                        printf("[OpenVPNAdapter] finalEndPos: %zu\n", finalEndPos);
                        printf("[OpenVPNAdapter] END marker length: %zu\n", strlen("-----END CERTIFICATE-----"));
                        printf("[OpenVPNAdapter] Calculated cert length: %zu bytes\n", finalCertLen);
                        printf("[OpenVPNAdapter] CA section length: %zu bytes\n", finalCaSection.length());
                        
                        // Save extraction calculation to UserDefaults
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] EXTRACTING: BEGIN at %zu, END at %zu, calculated length %zu, CA section length %zu", finalBeginPos, finalEndPos, finalCertLen, finalCaSection.length()]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        // Check bounds
                        if (finalBeginPos + finalCertLen > finalCaSection.length()) {
                            printf("[OpenVPNAdapter] ❌ ERROR: finalBeginPos (%zu) + finalCertLen (%zu) = %zu > finalCaSection.length() (%zu)\n", 
                                   finalBeginPos, finalCertLen, finalBeginPos + finalCertLen, finalCaSection.length());
                            finalCertLen = finalCaSection.length() - finalBeginPos; // Adjust to fit
                            printf("[OpenVPNAdapter] Adjusted cert length to: %zu bytes\n", finalCertLen);
                            
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"ERROR",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ BOUNDS ERROR: Adjusted cert length to %zu bytes", finalCertLen]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                        }
                        
                        // Extract certificate
                        printf("[OpenVPNAdapter] ШАГ 1: Начинаю извлечение сертификата\n");
                        NSLog(@"[OpenVPNAdapter] ШАГ 1: Начинаю извлечение сертификата");
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": @"[OpenVPNAdapter] ШАГ 1: Начинаю извлечение сертификата"
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        finalCaCert = finalCaSection.substr(finalBeginPos, finalCertLen);
                        printf("[OpenVPNAdapter] ШАГ 2: Извлечен сертификат, длина = %zu байт\n", finalCaCert.length());
                        NSLog(@"[OpenVPNAdapter] ШАГ 2: Извлечен сертификат, длина = %zu байт", finalCaCert.length());
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 2: Извлечен сертификат, длина = %zu байт", finalCaCert.length()]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        // CRITICAL: Remove leading newline if present (CA section starts with \n)
                        if (!finalCaCert.empty() && finalCaCert[0] == '\n') {
                            printf("[OpenVPNAdapter] ШАГ 3: Удаляю начальный \\n\n");
                            NSLog(@"[OpenVPNAdapter] ШАГ 3: Удаляю начальный \\n");
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": @"[OpenVPNAdapter] ШАГ 3: Удаляю начальный \\n"
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            finalCaCert = finalCaCert.substr(1);
                            printf("[OpenVPNAdapter] ШАГ 4: После удаления начального \\n, длина = %zu байт\n", finalCaCert.length());
                            NSLog(@"[OpenVPNAdapter] ШАГ 4: После удаления начального \\n, длина = %zu байт", finalCaCert.length());
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 4: После удаления начального \\n, длина = %zu байт", finalCaCert.length()]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                        } else {
                            printf("[OpenVPNAdapter] ШАГ 3: Начального \\n нет, пропускаю\n");
                            NSLog(@"[OpenVPNAdapter] ШАГ 3: Начального \\n нет, пропускаю");
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": @"[OpenVPNAdapter] ШАГ 3: Начального \\n нет, пропускаю"
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                        }
                        
                        // CRITICAL: Remove trailing newline if present
                        if (!finalCaCert.empty() && finalCaCert[finalCaCert.length() - 1] == '\n') {
                            printf("[OpenVPNAdapter] ШАГ 5: Удаляю конечный \\n\n");
                            NSLog(@"[OpenVPNAdapter] ШАГ 5: Удаляю конечный \\n");
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": @"[OpenVPNAdapter] ШАГ 5: Удаляю конечный \\n"
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            finalCaCert = finalCaCert.substr(0, finalCaCert.length() - 1);
                            printf("[OpenVPNAdapter] ШАГ 6: После удаления конечного \\n, длина = %zu байт\n", finalCaCert.length());
                            NSLog(@"[OpenVPNAdapter] ШАГ 6: После удаления конечного \\n, длина = %zu байт", finalCaCert.length());
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 6: После удаления конечного \\n, длина = %zu байт", finalCaCert.length()]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                        } else {
                            printf("[OpenVPNAdapter] ШАГ 5: Конечного \\n нет, пропускаю\n");
                            NSLog(@"[OpenVPNAdapter] ШАГ 5: Конечного \\n нет, пропускаю");
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": @"[OpenVPNAdapter] ШАГ 5: Конечного \\n нет, пропускаю"
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                        }
                        
                        certExtracted = true;
                        printf("[OpenVPNAdapter] ШАГ 7: certExtracted = true, длина сертификата = %zu байт\n", finalCaCert.length());
                        NSLog(@"[OpenVPNAdapter] ШАГ 7: certExtracted = true, длина сертификата = %zu байт", finalCaCert.length());
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 7: certExtracted = true, длина сертификата = %zu байт", finalCaCert.length()]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        printf("[OpenVPNAdapter] CA cert first 50 chars: ");
                        for (size_t i = 0; i < MIN(50, finalCaCert.length()); i++) {
                            printf("%c", finalCaCert[i]);
                        }
                        printf("\n");
                        
                        // CRITICAL: Save to UserDefaults IMMEDIATELY with printf to ensure it's logged
                        printf("[OpenVPNAdapter] 🔍 SAVING TO USERDEFAULTS: certExtracted = %d, finalCaCert.length() = %zu\n", certExtracted, finalCaCert.length());
                        NSLog(@"[OpenVPNAdapter] 🔍 SAVING TO USERDEFAULTS: certExtracted = %d, finalCaCert.length() = %zu", certExtracted, finalCaCert.length());
                        
                        // Save extraction info to UserDefaults IMMEDIATELY
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ✅ IMMEDIATELY AFTER EXTRACTION: CA cert length = %zu bytes", finalCaCert.length()]
                            }];
                            NSString *certFirst50 = [NSString stringWithUTF8String:finalCaCert.substr(0, MIN(50, finalCaCert.length())).c_str()];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] CA cert first 50 chars: %@", certFirst50]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        // EXPERIMENT: REMOVED test mbedTLS parsing - let OpenVPN3 handle it
                        // OpenVPN3 will extract CA cert via opt.cat("ca") and parse it itself
                        // Our test parsing may interfere or use different mbedTLS context
                        printf("[OpenVPNAdapter] ⚠️ EXPERIMENT: Skipping test mbedTLS parsing - letting OpenVPN3 handle CA cert parsing\n");
                        NSLog(@"[OpenVPNAdapter] ⚠️ EXPERIMENT: Skipping test mbedTLS parsing - letting OpenVPN3 handle CA cert parsing");
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": @"[OpenVPNAdapter] ⚠️ EXPERIMENT: Skipping test mbedTLS parsing - letting OpenVPN3 handle CA cert parsing"
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        printf("[OpenVPNAdapter] CA cert extracted: certExtracted = %d, finalCaCert.length() = %zu\n", certExtracted, finalCaCert.length());
                        NSLog(@"[OpenVPNAdapter] CA cert extracted: certExtracted = %d, finalCaCert.length() = %zu", certExtracted, finalCaCert.length());
                        
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] AFTER mbedTLS TEST: certExtracted = %d, finalCaCert.length() = %zu", certExtracted, finalCaCert.length()]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        // Log full CA cert ONLY if it's not empty
                        if (!finalCaCert.empty()) {
                            printf("[OpenVPNAdapter] CA cert full content (%zu bytes):\n", finalCaCert.length());
                            for (size_t i = 0; i < finalCaCert.length(); i++) {
                                char c = finalCaCert[i];
                                if (c >= 32 && c <= 126) {
                                    printf("%c", c);
                                } else if (c == '\n') {
                                    printf("\\n");
                                } else if (c == '\r') {
                                    printf("\\r");
                                } else {
                                    printf("\\x%02x", (unsigned char)c);
                                }
                            }
                            printf("\n");
                        } else {
                            printf("[OpenVPNAdapter] ❌ CA cert is EMPTY after mbedTLS test!\n");
                            NSLog(@"[OpenVPNAdapter] ❌ CA cert is EMPTY after mbedTLS test!");
                        }
                        
                        // CRITICAL: Verify certExtracted flag and finalCaCert state BEFORE using it
                        printf("[OpenVPNAdapter] ШАГ 14: ПЕРЕД подсчетом символов: certExtracted = %d, finalCaCert.length() = %zu\n", certExtracted, finalCaCert.length());
                        NSLog(@"[OpenVPNAdapter] ШАГ 14: ПЕРЕД подсчетом символов: certExtracted = %d, finalCaCert.length() = %zu", certExtracted, finalCaCert.length());
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"INFO",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 14: ПЕРЕД подсчетом символов: certExtracted = %d, finalCaCert.length() = %zu", certExtracted, finalCaCert.length()]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        if (!certExtracted || finalCaCert.empty()) {
                            printf("[OpenVPNAdapter] ШАГ 15: ОШИБКА! finalCaCert пустой! certExtracted = %d, length = %zu\n", certExtracted, finalCaCert.length());
                            NSLog(@"[OpenVPNAdapter] ШАГ 15: ОШИБКА! finalCaCert пустой! certExtracted = %d, length = %zu", certExtracted, finalCaCert.length());
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"ERROR",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 15: ОШИБКА! finalCaCert пустой! certExtracted = %d, length = %zu", certExtracted, finalCaCert.length()]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"ERROR",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ CRITICAL ERROR: finalCaCert is empty! certExtracted = %d, length = %zu", certExtracted, finalCaCert.length()]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                        } else {
                            printf("[OpenVPNAdapter] ШАГ 16: Сертификат НЕ пустой, начинаю подсчет символов\n");
                            NSLog(@"[OpenVPNAdapter] ШАГ 16: Сертификат НЕ пустой, начинаю подсчет символов");
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": @"[OpenVPNAdapter] ШАГ 16: Сертификат НЕ пустой, начинаю подсчет символов"
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            // Count characters after END marker
                            size_t endMarkerEnd = finalEndPos + strlen("-----END CERTIFICATE-----");
                            size_t trailingChars = 0;
                            if (endMarkerEnd < finalCaCert.length()) {
                                trailingChars = finalCaCert.length() - endMarkerEnd;
                            } else {
                                printf("[OpenVPNAdapter] ШАГ 17: Предупреждение: endMarkerEnd (%zu) >= cert length (%zu)\n", endMarkerEnd, finalCaCert.length());
                                NSLog(@"[OpenVPNAdapter] ШАГ 17: Предупреждение: endMarkerEnd (%zu) >= cert length (%zu)", endMarkerEnd, finalCaCert.length());
                                @try {
                                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                    [logs addObject:@{
                                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                        @"level": @"WARNING",
                                        @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 17: Предупреждение: endMarkerEnd (%zu) >= cert length (%zu)", endMarkerEnd, finalCaCert.length()]
                                    }];
                                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                    [[NSUserDefaults standardUserDefaults] synchronize];
                                } @catch (...) {}
                            }
                            printf("[OpenVPNAdapter] ШАГ 18: Символов после END маркера: %zu\n", trailingChars);
                            NSLog(@"[OpenVPNAdapter] ШАГ 18: Символов после END маркера: %zu", trailingChars);
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 18: Символов после END маркера: %zu", trailingChars]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            if (trailingChars > 0) {
                                printf("[OpenVPNAdapter] Trailing content: ");
                                for (size_t i = endMarkerEnd; i < finalCaCert.length(); i++) {
                                    char c = finalCaCert[i];
                                    if (c == '\n') {
                                        printf("\\n");
                                    } else if (c == '\r') {
                                        printf("\\r");
                                    } else if (c == ' ') {
                                        printf("SPACE");
                                    } else if (c == '\t') {
                                        printf("TAB");
                                    } else {
                                        printf("\\x%02x", (unsigned char)c);
                                    }
                                }
                                printf("\n");
                            }
                            
                            // Count newlines
                            printf("[OpenVPNAdapter] ШАГ 19: Подсчитываю символы \\n и \\r\n");
                            NSLog(@"[OpenVPNAdapter] ШАГ 19: Подсчитываю символы \\n и \\r");
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": @"[OpenVPNAdapter] ШАГ 19: Подсчитываю символы \\n и \\r"
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            size_t newlineCount = std::count(finalCaCert.begin(), finalCaCert.end(), '\n');
                            size_t crCount = std::count(finalCaCert.begin(), finalCaCert.end(), '\r');
                            printf("[OpenVPNAdapter] ШАГ 20: Newlines (\\n): %zu, CRs (\\r): %zu\n", newlineCount, crCount);
                            NSLog(@"[OpenVPNAdapter] ШАГ 20: Newlines (\\n): %zu, CRs (\\r): %zu", newlineCount, crCount);
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 20: Newlines (\\n): %zu, CRs (\\r): %zu", newlineCount, crCount]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            
                            // Build detailed log message
                            printf("[OpenVPNAdapter] ШАГ 21: Формирую финальное сообщение о сертификате\n");
                            NSLog(@"[OpenVPNAdapter] ШАГ 21: Формирую финальное сообщение о сертификате");
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": @"[OpenVPNAdapter] ШАГ 21: Формирую финальное сообщение о сертификате"
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            NSString *caCertInfo = [NSString stringWithFormat:@"[OpenVPNAdapter] CA cert before connect: %zu bytes, %zu newlines, %zu CRs, %zu trailing chars after END", 
                                                   finalCaCert.length(), newlineCount, crCount, trailingChars];
                            NSLog(@"%@", caCertInfo);
                            printf("[OpenVPNAdapter] ШАГ 22: Финальное сообщение создано, длина сертификата = %zu байт\n", finalCaCert.length());
                            NSLog(@"[OpenVPNAdapter] ШАГ 22: Финальное сообщение создано, длина сертификата = %zu байт", finalCaCert.length());
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ШАГ 22: Финальное сообщение создано, длина сертификата = %zu байт", finalCaCert.length()]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                            } @catch (...) {}
                            
                            // Log full CA cert
                            NSString *fullCaCert = [NSString stringWithUTF8String:finalCaCert.c_str()];
                            NSLog(@"[OpenVPNAdapter] CA cert full content (%zu bytes):\n%@", finalCaCert.length(), fullCaCert);
                            
                            // Save to UserDefaults with full certificate
                            @try {
                                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": caCertInfo
                                }];
                                [logs addObject:@{
                                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                    @"level": @"INFO",
                                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] CA cert full content (%zu bytes):\n%@", finalCaCert.length(), fullCaCert]
                                }];
                                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                                [[NSUserDefaults standardUserDefaults] synchronize];
                                NSLog(@"[OpenVPNAdapter] ✅ CA cert analysis saved to UserDefaults");
                            } @catch (...) {
                                NSLog(@"[OpenVPNAdapter] ❌ Failed to save CA cert analysis to UserDefaults");
                            }
                        }
                    } else {
                        printf("[OpenVPNAdapter] ⚠️ CA certificate markers not found in final config\n");
                        printf("[OpenVPNAdapter] CA section content (%zu bytes):\n%s\n", finalCaSection.length(), finalCaSection.c_str());
                        NSLog(@"[OpenVPNAdapter] ⚠️ CA certificate markers not found in CA section");
                        
                        // Save error to UserDefaults
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"ERROR",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ⚠️ CA certificate markers not found in CA section (%zu bytes): %@", finalCaSection.length(), [NSString stringWithUTF8String:finalCaSection.c_str()]]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                    }
                    } // Close else block for finalCaSectionEnd check
                } else {
                    printf("[OpenVPNAdapter] ⚠️ CA section not found in final config\n");
                    printf("[OpenVPNAdapter] configStr length: %zu bytes\n", configStr.length());
                    printf("[OpenVPNAdapter] Searching for '<ca>' substring...\n");
                    
                    // Try case-insensitive search
                    std::string lowerConfig = configStr;
                    std::transform(lowerConfig.begin(), lowerConfig.end(), lowerConfig.begin(), ::tolower);
                    size_t lowerCaPos = lowerConfig.find("<ca>");
                    printf("[OpenVPNAdapter] Case-insensitive search for '<ca>': found at %zu\n", lowerCaPos);
                    
                    // Log a sample of the config to see what's there
                    size_t sampleStart = configStr.length() > 1000 ? configStr.length() - 1000 : 0;
                    printf("[OpenVPNAdapter] Last 1000 chars of configStr:\n%s\n", configStr.substr(sampleStart).c_str());
                    
                    NSLog(@"[OpenVPNAdapter] ⚠️ CA section not found in final config (length: %zu bytes)", configStr.length());
                    
                    // Save error to UserDefaults
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"ERROR",
                            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ⚠️ CA section not found in final config (length: %zu bytes)", configStr.length()]
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                }
                printf("========================================\n");
                
                // Connect (this blocks until disconnect)
                NSLog(@"[OpenVPNAdapter] 🔌 Connecting to server...");
                printf("[OpenVPNAdapter] 🔌 About to call client_->connect()...\n");
                printf("[OpenVPNAdapter] This is where mbedTLS will parse CA certificate\n");
                
                // Save log to UserDefaults IMMEDIATELY before connect()
                @try {
                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": @"[OpenVPNAdapter] 🔌 About to call client_->connect()..."
                    }];
                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    NSLog(@"[OpenVPNAdapter] ✅ Pre-connect log saved to UserDefaults");
                } @catch (...) {
                    NSLog(@"[OpenVPNAdapter] ❌ Failed to save pre-connect log");
                }
                
                Status status;
                status.error = true; // Initialize to error state
                status.message = "Unknown error";
                status.status = "Unknown";
                
                // CRITICAL: Log that we're about to call connect()
                // Clear any old errors from UserDefaults before starting new connection
                @try {
                    [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"DataGateVPNExtension.LastError"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    NSLog(@"[OpenVPNAdapter] 🧹 Cleared old error from UserDefaults before connect()");
                } @catch (...) {}
                
                @try {
                    NSLog(@"[OpenVPNAdapter] ⚠️ CALLING client_->connect() NOW - mbedTLS will parse CA cert");
                    printf("[OpenVPNAdapter] ⚠️ CALLING client_->connect() NOW\n");
                    
                    // Save log BEFORE calling connect()
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"INFO",
                            @"message": @"[OpenVPNAdapter] ⚠️ CALLING client_->connect() NOW - mbedTLS will parse CA cert"
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                    
                    try {
                        printf("[OpenVPNAdapter] 🔌 Calling client_->connect()...\n");
                        NSLog(@"[OpenVPNAdapter] 🔌 Calling client_->connect()...");
                        status = self->client_->connect();
                        printf("[OpenVPNAdapter] ✅ connect() returned successfully\n");
                        NSLog(@"[OpenVPNAdapter] ✅ connect() returned successfully");
                        printf("[OpenVPNAdapter] ⚠️ NOTE: connect() may have started async event loop\n");
                        NSLog(@"[OpenVPNAdapter] ⚠️ NOTE: connect() may have started async event loop");
                    } catch (const std::exception &e) {
                        NSString *errorMsg = [NSString stringWithFormat:@"Connection C++ exception: %s", e.what()];
                        NSLog(@"[OpenVPNAdapter] ❌ Connection C++ exception: %@", errorMsg);
                        printf("[OpenVPNAdapter] ❌ Connection C++ exception: %s\n", e.what());
                        
                        // Save exception to UserDefaults IMMEDIATELY
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"ERROR",
                                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ C++ exception in connect(): %@", errorMsg]
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        dispatch_async(dispatch_get_main_queue(), ^{
                            NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                                 code:4 
                                                             userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                            [self.delegate openVPNAdapter:self didFailWithError:error];
                            self->isConnecting_ = NO;
                        });
                        return;
                    } catch (...) {
                        NSString *errorMsg = @"Connection unknown C++ exception";
                        NSLog(@"[OpenVPNAdapter] ❌ Connection unknown C++ exception");
                        printf("[OpenVPNAdapter] ❌ Connection unknown C++ exception\n");
                        
                        // Save exception to UserDefaults IMMEDIATELY
                        @try {
                            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                            [logs addObject:@{
                                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                                @"level": @"ERROR",
                                @"message": @"[OpenVPNAdapter] ❌ Unknown C++ exception in connect()"
                            }];
                            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                        } @catch (...) {}
                        
                        dispatch_async(dispatch_get_main_queue(), ^{
                            NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                                 code:5 
                                                             userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                            [self.delegate openVPNAdapter:self didFailWithError:error];
                            self->isConnecting_ = NO;
                        });
                        return;
                    }
                } @catch (NSException *exception) {
                    NSString *errorMsg = [NSString stringWithFormat:@"Objective-C exception in connect(): %@", exception.reason];
                    NSLog(@"[OpenVPNAdapter] ❌ Objective-C exception: %@", errorMsg);
                    printf("[OpenVPNAdapter] ❌ Objective-C exception: %s\n", [exception.reason UTF8String]);
                    
                    // Save exception to UserDefaults IMMEDIATELY
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"ERROR",
                            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ Objective-C exception: %@", exception.reason]
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                             code:6 
                                                         userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                        [self.delegate openVPNAdapter:self didFailWithError:error];
                        self->isConnecting_ = NO;
                    });
                    return;
                }
                
                NSLog(@"[OpenVPNAdapter] ✅ client_->connect() returned");
                printf("[OpenVPNAdapter] ✅ client_->connect() returned\n");
                printf("[OpenVPNAdapter] Status error: %s\n", status.error ? "YES" : "NO");
                
                // CRITICAL: Check error status and log IMMEDIATELY
                if (status.error) {
                    // Get error message FIRST before anything else
                    std::string errorMsgStr = status.message;
                    std::string statusStrStr = status.status;
                    
                    printf("[OpenVPNAdapter] ⚠️ ERROR DETECTED!\n");
                    printf("[OpenVPNAdapter] Status message: %s\n", errorMsgStr.c_str());
                    printf("[OpenVPNAdapter] Status status: %s\n", statusStrStr.c_str());
                    
                    // Convert to NSString safely
                    NSString *errorMsg = errorMsgStr.empty() ? @"(empty)" : [NSString stringWithUTF8String:errorMsgStr.c_str()];
                    NSString *statusStr = statusStrStr.empty() ? @"(empty)" : [NSString stringWithUTF8String:statusStrStr.c_str()];
                    
                    NSLog(@"[OpenVPNAdapter] ❌ Connection error from status: %@", errorMsg);
                    NSLog(@"[OpenVPNAdapter] ❌ Status string: %@", statusStr);
                    
                    // Save error details to UserDefaults IMMEDIATELY - CRITICAL!
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"ERROR",
                            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ connect() ERROR: %@", errorMsg]
                        }];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"ERROR",
                            @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ connect() STATUS: %@", statusStr]
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                        NSLog(@"[OpenVPNAdapter] ✅ Error details saved to UserDefaults");
                        printf("[OpenVPNAdapter] ✅ Error saved: %s\n", errorMsgStr.c_str());
                    } @catch (NSException *e) {
                        NSLog(@"[OpenVPNAdapter] ❌ Failed to save error details: %@", e.reason);
                        printf("[OpenVPNAdapter] ❌ Failed to save: %s\n", [e.reason UTF8String]);
                    }
                } else {
                    // Save success log
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"INFO",
                            @"message": @"[OpenVPNAdapter] ✅ client_->connect() returned, error: NO"
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        
                        // Clear old error from UserDefaults on success
                        [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"DataGateVPNExtension.LastError"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                        NSLog(@"[OpenVPNAdapter] ✅ Cleared old error from UserDefaults (successful connection)");
                    } @catch (...) {}
                }
                
                if (status.error) {
                    NSString *errorMsg = [NSString stringWithUTF8String:status.message.c_str()];
                    NSString *statusStr = [NSString stringWithUTF8String:status.status.c_str()];
                    NSLog(@"[OpenVPNAdapter] ❌ Connection error: %@", errorMsg);
                    NSLog(@"[OpenVPNAdapter]    Status: %@", statusStr);
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
                        userInfo[NSLocalizedDescriptionKey] = errorMsg;
                        if (statusStr.length > 0) {
                            userInfo[@"status"] = statusStr;
                        }
                        
                        NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                             code:2 
                                                         userInfo:userInfo];
                        [self.delegate openVPNAdapter:self didFailWithError:error];
                        self->isConnecting_ = NO;
                    });
                } else {
                    printf("[OpenVPNAdapter] ✅ Connection completed successfully\n");
                    NSLog(@"[OpenVPNAdapter] ✅ Connection completed successfully");
                    printf("[OpenVPNAdapter] ⚠️ NOTE: connect() returned success, but connection is async - waiting for CONNECTED event\n");
                    NSLog(@"[OpenVPNAdapter] ⚠️ NOTE: connect() returned success, but connection is async - waiting for CONNECTED event");
                    
                    // CRITICAL: Save log immediately after successful connect()
                    @try {
                        NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                        [logs addObject:@{
                            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                            @"level": @"INFO",
                            @"message": @"[OpenVPNAdapter] ✅ Connection completed successfully, waiting for CONNECTED event..."
                        }];
                        if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                        [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    } @catch (...) {}
                }
                
                } catch (const std::exception &e) {
                    NSString *errorMsg = [NSString stringWithUTF8String:e.what()];
                    NSLog(@"[OpenVPNAdapter] 💥 C++ Exception: %@", errorMsg);
                    NSLog(@"[OpenVPNAdapter]    Exception type: %s", typeid(e).name());
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        @try {
                            NSDictionary *userInfo = @{
                                NSLocalizedDescriptionKey: errorMsg,
                                @"exceptionType": [NSString stringWithUTF8String:typeid(e).name()]
                            };
                            NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                                 code:3 
                                                             userInfo:userInfo];
                            if (self.delegate) {
                                [self.delegate openVPNAdapter:self didFailWithError:error];
                            } else {
                                NSLog(@"⚠️ [OpenVPNAdapter] Delegate is nil, cannot report error");
                            }
                            self->isConnecting_ = NO;
                        } @catch (NSException *nsException) {
                            NSLog(@"❌ [OpenVPNAdapter] EXCEPTION in error handler: %@", nsException);
                        }
                    });
                } catch (...) {
                    NSLog(@"[OpenVPNAdapter] 💥 Unknown C++ exception caught");
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        @try {
                            NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                                 code:4 
                                                             userInfo:@{NSLocalizedDescriptionKey: @"Unknown C++ exception occurred"}];
                            if (self.delegate) {
                                [self.delegate openVPNAdapter:self didFailWithError:error];
                            } else {
                                NSLog(@"⚠️ [OpenVPNAdapter] Delegate is nil, cannot report error");
                            }
                            self->isConnecting_ = NO;
                        } @catch (NSException *nsException) {
                            NSLog(@"❌ [OpenVPNAdapter] EXCEPTION in error handler: %@", nsException);
                        }
                    });
                }
            } @catch (NSException *nsException) {
                // Catch Objective-C exceptions that might occur during C++ operations
                NSString *errorMsg = [NSString stringWithFormat:@"Objective-C exception: %@", nsException.reason];
                NSLog(@"[OpenVPNAdapter] 💥 Objective-C Exception: %@", errorMsg);
                NSLog(@"[OpenVPNAdapter]    Stack trace: %@", nsException.callStackSymbols);
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    @try {
                        NSError *error = [NSError errorWithDomain:@"OpenVPNAdapter" 
                                                             code:5 
                                                         userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                        if (self.delegate) {
                            [self.delegate openVPNAdapter:self didFailWithError:error];
                        } else {
                            NSLog(@"⚠️ [OpenVPNAdapter] Delegate is nil, cannot report error");
                        }
                        self->isConnecting_ = NO;
                    } @catch (NSException *innerException) {
                        NSLog(@"❌ [OpenVPNAdapter] FATAL: Exception in exception handler: %@", innerException);
                    }
                });
            }
        }
    });
}

- (void)stop {
    NSLog(@"[OpenVPNAdapter] 🛑 Stopping...");
    
    if (client_) {
        NSLog(@"[OpenVPNAdapter] 🔴 Calling client_->stop()");
        client_->stop();
        NSLog(@"[OpenVPNAdapter] 🗑️ Resetting client");
        client_.reset();
        NSLog(@"[OpenVPNAdapter] ✅ Client stopped");
    } else {
        NSLog(@"[OpenVPNAdapter] ⚠️ No client to stop");
    }
    
    isConnecting_ = NO;
    _isConnected = NO;
}

- (void)handlePacketFromTunnel:(NSData *)packet {
    // Packet from iOS tunnel - send to OpenVPN3
    NSLog(@"[OpenVPNAdapter] 📥 Received packet from tunnel (%lu bytes)", (unsigned long)packet.length);
    
    if (!client_) {
        NSLog(@"[OpenVPNAdapter] ⚠️ Cannot forward packet - no client");
        return;
    }
    
    // TODO: Forward packet to OpenVPN3
    // OpenVPN3 needs to receive packets through tun_recv callback
    // But we don't have a real TUN interface, so we need to use ExternalTun or similar
    // For now, just log
    NSLog(@"[OpenVPNAdapter] ⚠️ Packet forwarding not yet implemented");
}

- (void)handlePacketFromVPN:(NSData *)packet {
    // Packet from VPN server - send to iOS tunnel
    NSLog(@"[OpenVPNAdapter] 📤 Received packet from VPN (%lu bytes)", (unsigned long)packet.length);
    
    // Forward to delegate to send through packetFlow
    if ([self.delegate respondsToSelector:@selector(openVPNAdapter:needsSendPacket:)]) {
        [self.delegate openVPNAdapter:self needsSendPacket:packet];
    }
}

- (void)onConnected {
    @try {
        printf("[OpenVPNAdapter] ✅ onConnected() called\n");
        NSLog(@"[OpenVPNAdapter] ✅ Connected!");
        
        // CRITICAL: Save to UserDefaults IMMEDIATELY
        @try {
            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
            [logs addObject:@{
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"level": @"INFO",
                @"message": @"[OpenVPNAdapter] ✅ onConnected() called"
            }];
            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        } @catch (...) {}
        
        _isConnected = YES;
        isConnecting_ = NO;
        
        // Get connection info SAFELY
        @try {
            if (client_) {
                printf("[OpenVPNAdapter] Getting connection info...\n");
                ConnectionInfo info = client_->connection_info();
                NSLog(@"[OpenVPNAdapter] 📊 Connection Info:");
                NSLog(@"[OpenVPNAdapter]    Server: %s:%s", info.serverHost.c_str(), info.serverPort.c_str());
                NSLog(@"[OpenVPNAdapter]    Protocol: %s", info.serverProto.c_str());
                NSLog(@"[OpenVPNAdapter]    Server IP: %s", info.serverIp.c_str());
                NSLog(@"[OpenVPNAdapter]    Client IP: %s", info.clientIp.c_str());
                printf("[OpenVPNAdapter] ✅ Connection info retrieved successfully\n");
                
                // Save connection info to UserDefaults
                @try {
                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] 📊 Connection Info: Server=%s:%s, Protocol=%s", info.serverHost.c_str(), info.serverPort.c_str(), info.serverProto.c_str()]
                    }];
                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                } @catch (...) {}
            } else {
                NSLog(@"[OpenVPNAdapter] ⚠️ client_ is nil, skipping connection info");
                printf("[OpenVPNAdapter] ⚠️ client_ is nil\n");
                
                // Save warning to UserDefaults
                @try {
                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"WARNING",
                        @"message": @"[OpenVPNAdapter] ⚠️ client_ is nil, skipping connection info"
                    }];
                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                } @catch (...) {}
            }
        } @catch (NSException *e) {
            NSLog(@"[OpenVPNAdapter] ❌ EXCEPTION getting connection info: %@", e);
            printf("[OpenVPNAdapter] ❌ EXCEPTION getting connection info: %s\n", [e.reason UTF8String]);
            
            // Save exception to UserDefaults
            @try {
                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                [logs addObject:@{
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"level": @"ERROR",
                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ EXCEPTION getting connection info: %@", e.reason]
                }];
                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                [[NSUserDefaults standardUserDefaults] synchronize];
            } @catch (...) {}
        } @catch (...) {
            NSLog(@"[OpenVPNAdapter] ❌ C++ EXCEPTION getting connection info");
            printf("[OpenVPNAdapter] ❌ C++ EXCEPTION getting connection info\n");
            
            // Save C++ exception to UserDefaults
            @try {
                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                [logs addObject:@{
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"level": @"ERROR",
                    @"message": @"[OpenVPNAdapter] ❌ C++ EXCEPTION getting connection info"
                }];
                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                [[NSUserDefaults standardUserDefaults] synchronize];
            } @catch (...) {}
        }
        
        // Notify delegate SAFELY
        @try {
            if ([self.delegate respondsToSelector:@selector(openVPNAdapterDidConnect:)]) {
                printf("[OpenVPNAdapter] Calling delegate openVPNAdapterDidConnect...\n");
                [self.delegate openVPNAdapterDidConnect:self];
                printf("[OpenVPNAdapter] ✅ Delegate notified successfully\n");
                
                // Save success to UserDefaults
                @try {
                    NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                    [logs addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"level": @"INFO",
                        @"message": @"[OpenVPNAdapter] ✅ Delegate notified successfully"
                    }];
                    if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                    [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                } @catch (...) {}
            } else {
                NSLog(@"[OpenVPNAdapter] ⚠️ Delegate does not respond to openVPNAdapterDidConnect:");
                printf("[OpenVPNAdapter] ⚠️ Delegate does not respond\n");
            }
        } @catch (NSException *e) {
            NSLog(@"[OpenVPNAdapter] ❌ EXCEPTION notifying delegate: %@", e);
            printf("[OpenVPNAdapter] ❌ EXCEPTION notifying delegate: %s\n", [e.reason UTF8String]);
            
            // Save exception to UserDefaults
            @try {
                NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
                [logs addObject:@{
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"level": @"ERROR",
                    @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ EXCEPTION notifying delegate: %@", e.reason]
                }];
                if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
                [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
                [[NSUserDefaults standardUserDefaults] synchronize];
            } @catch (...) {}
        }
    } @catch (NSException *e) {
        NSLog(@"[OpenVPNAdapter] ❌ FATAL EXCEPTION in onConnected: %@", e);
        printf("[OpenVPNAdapter] ❌ FATAL EXCEPTION in onConnected: %s\n", [e.reason UTF8String]);
        NSLog(@"[OpenVPNAdapter] Stack trace: %@", e.callStackSymbols);
        
        // Save fatal exception to UserDefaults
        @try {
            NSMutableArray *logs = [[[NSUserDefaults standardUserDefaults] objectForKey:@"DataGateVPNExtension.Logs"] mutableCopy] ?: [NSMutableArray array];
            [logs addObject:@{
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"level": @"ERROR",
                @"message": [NSString stringWithFormat:@"[OpenVPNAdapter] ❌ FATAL EXCEPTION in onConnected: %@", e.reason]
            }];
            if (logs.count > 100) { [logs removeObjectsInRange:NSMakeRange(0, logs.count - 100)]; }
            [[NSUserDefaults standardUserDefaults] setObject:logs forKey:@"DataGateVPNExtension.Logs"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        } @catch (...) {}
    }
}

- (void)onDisconnected {
    NSLog(@"[OpenVPNAdapter] 🔴 Disconnected");
    _isConnected = NO;
    isConnecting_ = NO;
    
    if ([self.delegate respondsToSelector:@selector(openVPNAdapterDidDisconnect:)]) {
        [self.delegate openVPNAdapterDidDisconnect:self];
    }
}

- (void)tunnelEstablished {
    NSLog(@"[OpenVPNAdapter] 🏗️ Tunnel established - updating network settings");
    [self updateNetworkSettings];
}

- (void)updateNetworkSettings {
    if (!client_) {
        NSLog(@"[OpenVPNAdapter] ⚠️ Cannot update network settings - no client");
        return;
    }
    
    NSLog(@"[OpenVPNAdapter] 🔧 Building network settings from tun_builder data...");
    
    // Get network settings from client
    std::string ipv4Addr = client_->getIPv4Address();
    int ipv4Prefix = client_->getIPv4Prefix();
    std::string ipv4Gw = client_->getIPv4Gateway();
    std::string remoteAddr = client_->getRemoteAddress();
    const DnsOptions& dns = client_->getDnsOptions();
    int mtu = client_->getMTU();
    
    NSLog(@"[OpenVPNAdapter]    IPv4: %s/%d gateway=%s", ipv4Addr.c_str(), ipv4Prefix, ipv4Gw.c_str());
    NSLog(@"[OpenVPNAdapter]    Remote: %s", remoteAddr.c_str());
    NSLog(@"[OpenVPNAdapter]    MTU: %d", mtu);
    NSLog(@"[OpenVPNAdapter]    DNS servers: %zu", dns.servers.size());
    
    // Build NEPacketTunnelNetworkSettings — use virtual gateway (e.g. 10.8.0.1), not physical server IP
    NSString *remoteAddress = !ipv4Gw.empty() ? [NSString stringWithUTF8String:ipv4Gw.c_str()] : @"10.8.0.1";
    NEPacketTunnelNetworkSettings *settings = [[NEPacketTunnelNetworkSettings alloc] 
        initWithTunnelRemoteAddress:remoteAddress];
    
    // Configure IPv4 - always set so we never overwrite tunnel with no-IPv4 (which would break routing)
    NSString *address;
    int prefixLen;
    if (!ipv4Addr.empty()) {
        address = [NSString stringWithUTF8String:ipv4Addr.c_str()];
        prefixLen = ipv4Prefix > 0 ? ipv4Prefix : 24;
    } else {
        // Fallback: OpenVPN may not have pushed address yet (e.g. DNS pushed first); keep tunnel usable
        address = @"10.8.0.2";
        prefixLen = 24;
        NSLog(@"[OpenVPNAdapter]    Using fallback IPv4 %@ (server has not pushed address yet)", address);
    }
    NSString *subnetMask = [self subnetMaskFromPrefix:prefixLen];
    NEIPv4Settings *ipv4Settings = [[NEIPv4Settings alloc] 
        initWithAddresses:@[address] 
        subnetMasks:@[subnetMask]];
    
    // Always add default route so traffic goes through VPN (full-tunnel). Without this, no internet.
    NSMutableArray<NEIPv4Route *> *routes = [NSMutableArray array];
    [routes addObject:[NEIPv4Route defaultRoute]];
    NSLog(@"[OpenVPNAdapter]    Adding default IPv4 route (full-tunnel)");
    
    // Add server-pushed routes (skip default route — we already added it; duplicate can cause SIGABRT)
    const auto& routeList = client_->getRoutes();
    for (const auto& route : routeList) {
        if (route.ipv6 || route.exclude) continue;
        NSString *routeAddr = [NSString stringWithUTF8String:route.address.c_str()];
        if (route.prefix_length <= 0 && [routeAddr isEqualToString:@"0.0.0.0"])
            continue; // default route already added
        NSString *routeMask = [self subnetMaskFromPrefix:route.prefix_length];
        NEIPv4Route *ipv4Route = [[NEIPv4Route alloc] initWithDestinationAddress:routeAddr 
                                                                      subnetMask:routeMask];
        [routes addObject:ipv4Route];
        NSLog(@"[OpenVPNAdapter]    Added route: %@/%@", routeAddr, routeMask);
    }
    
    ipv4Settings.includedRoutes = routes;
    settings.IPv4Settings = ipv4Settings;
    
    // Configure DNS
    if (dns.servers.size() > 0) {
        NSMutableArray<NSString *> *dnsServers = [NSMutableArray array];
        for (const auto& [priority, server] : dns.servers) {
            if (!server.addresses.empty()) {
                NSString *dnsAddr = [NSString stringWithUTF8String:server.addresses[0].to_string().c_str()];
                [dnsServers addObject:dnsAddr];
                NSLog(@"[OpenVPNAdapter]    DNS: %@", dnsAddr);
            }
        }
        
        if (dnsServers.count > 0) {
            NEDNSSettings *dnsSettings = [[NEDNSSettings alloc] initWithServers:dnsServers];
            dnsSettings.matchDomains = @[@"."];  // "." = all domains (same as working OpenVPN clients)
            
            // Add search domains
            NSMutableArray<NSString *> *searchDomains = [NSMutableArray array];
            for (const auto& domain : dns.search_domains) {
                NSString *domainStr = [NSString stringWithUTF8String:domain.domain.c_str()];
                [searchDomains addObject:domainStr];
            }
            if (searchDomains.count > 0) {
                dnsSettings.searchDomains = searchDomains;
            }
            
            settings.DNSSettings = dnsSettings;
        }
    } else {
        // Fallback DNS
        NEDNSSettings *dnsSettings = [[NEDNSSettings alloc] initWithServers:@[@"8.8.8.8", @"8.8.4.4"]];
        dnsSettings.matchDomains = @[@"."];  // "." = all domains
        settings.DNSSettings = dnsSettings;
    }
    
    // Configure MTU
    if (mtu > 0) {
        settings.MTU = @(mtu);
    } else {
        settings.MTU = @(1500);
    }
    
    // Notify delegate
    if ([self.delegate respondsToSelector:@selector(openVPNAdapter:needsNetworkSettings:)]) {
        [self.delegate openVPNAdapter:self needsNetworkSettings:settings];
    }
}

- (NSString *)subnetMaskFromPrefix:(int)prefix {
    // Convert prefix length to subnet mask
    if (prefix <= 0 || prefix > 32) return @"255.255.255.0";
    
    uint32_t mask = 0xFFFFFFFF << (32 - prefix);
    return [NSString stringWithFormat:@"%d.%d.%d.%d",
            (mask >> 24) & 0xFF,
            (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,
            mask & 0xFF];
}

// Restore warnings for our code
#pragma clang diagnostic pop

@end

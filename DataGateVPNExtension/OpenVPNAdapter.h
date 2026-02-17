//
//  OpenVPNAdapter.h
//  DataGateVPNExtension
//
//  Objective-C++ adapter for OpenVPN3 C++ library
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

@class OpenVPNAdapter;

/// Delegate for OpenVPN adapter events
@protocol OpenVPNAdapterDelegate <NSObject>

/// Called when VPN connection is established
- (void)openVPNAdapterDidConnect:(OpenVPNAdapter *)adapter;

/// Called when VPN connection fails
- (void)openVPNAdapter:(OpenVPNAdapter *)adapter didFailWithError:(NSError *)error;

/// Called when VPN connection is disconnected
- (void)openVPNAdapterDidDisconnect:(OpenVPNAdapter *)adapter;

/// Called when network settings need to be updated
- (void)openVPNAdapter:(OpenVPNAdapter *)adapter 
    needsNetworkSettings:(NEPacketTunnelNetworkSettings *)settings;

/// Called when a packet needs to be sent to the VPN server
- (void)openVPNAdapter:(OpenVPNAdapter *)adapter needsSendPacket:(NSData *)packet;

@end

/// OpenVPN3 adapter for iOS Network Extension
@interface OpenVPNAdapter : NSObject

@property (nonatomic, weak, nullable) id<OpenVPNAdapterDelegate> delegate;
@property (nonatomic, readonly) BOOL isConnected;
@property (nonatomic, weak, nullable) NEPacketTunnelFlow *packetFlow;

/// Initialize adapter
- (instancetype)init;

/// Start VPN connection with OpenVPN config content
/// @param configContent Full .ovpn file content as string
- (void)startWithConfig:(NSString *)configContent;

/// Stop VPN connection
- (void)stop;

/// Handle packet received from iOS (to be sent to VPN server)
- (void)handlePacketFromTunnel:(NSData *)packet;

/// Handle packet received from VPN server (to be sent to iOS)
- (void)handlePacketFromVPN:(NSData *)packet;

/// Internal callback when VPN connects (called from C++ code)
- (void)onConnected;

/// Internal callback when VPN disconnects (called from C++ code)
- (void)onDisconnected;

/// Internal callback when tunnel is established (called from C++ code)
- (void)tunnelEstablished;

/// Update network settings from tun_builder data
- (void)updateNetworkSettings;

@end

NS_ASSUME_NONNULL_END

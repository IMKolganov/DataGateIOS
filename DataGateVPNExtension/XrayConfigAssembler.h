//
//  XrayConfigAssembler.h
//  DataGateVPNExtension
//
//  Merges libXray share-link outbounds with SOCKS + TUN inbounds for the packet tunnel.
//  Objective-C port of DataGateMac's XrayConfigAssembler.swift; keep both in sync.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface XrayConfigAssembler : NSObject

@property (class, nonatomic, readonly) NSInteger socksListenPort;

/// Runtime Xray JSON for libXray `runXray`. `tunFileDescriptor` < 0 means no TUN inbound.
+ (nullable NSString *)runtimeConfigWithShareConfig:(NSDictionary *)shareConfig
                                  tunFileDescriptor:(int)tunFileDescriptor
                                              error:(NSError * _Nullable * _Nullable)error;

/// libXray stores the share-link remark in `sendThrough`; anything that is not an IP bind address is dropped.
+ (NSDictionary *)prepareOutbound:(NSDictionary *)outbound fallbackTag:(NSString *)fallbackTag;

+ (BOOL)isIpBindAddress:(NSString *)value;

@end

NS_ASSUME_NONNULL_END

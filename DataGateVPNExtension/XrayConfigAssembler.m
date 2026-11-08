//
//  XrayConfigAssembler.m
//  DataGateVPNExtension
//

#import "XrayConfigAssembler.h"

#include <arpa/inet.h>

static NSString *const kXrayConfigErrorDomain = @"XrayConfigAssembler";

@implementation XrayConfigAssembler

+ (NSInteger)socksListenPort {
    return 10808;
}

+ (nullable NSString *)runtimeConfigWithShareConfig:(NSDictionary *)shareConfig
                                  tunFileDescriptor:(int)tunFileDescriptor
                                              error:(NSError * _Nullable * _Nullable)error {
    NSMutableDictionary *config = [shareConfig mutableCopy];
    NSArray *rawOutbounds = [config[@"outbounds"] isKindOfClass:[NSArray class]] ? config[@"outbounds"] : @[];
    if (rawOutbounds.count == 0) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:kXrayConfigErrorDomain
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Converted Xray share link has no outbounds."}];
        }
        return nil;
    }

    NSMutableArray *outbounds = [NSMutableArray array];
    [rawOutbounds enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        if (![obj isKindOfClass:[NSDictionary class]]) {
            return;
        }
        NSString *tag = idx == 0 ? @"proxy" : [NSString stringWithFormat:@"proxy-%lu", (unsigned long)idx];
        [outbounds addObject:[self prepareOutbound:obj fallbackTag:tag]];
    }];
    BOOL hasFreedom = NO;
    BOOL hasDnsOut = NO;
    for (NSDictionary *outbound in outbounds) {
        if ([[outbound[@"protocol"] description].lowercaseString isEqualToString:@"freedom"]) {
            hasFreedom = YES;
        }
        if ([outbound[@"tag"] isEqual:@"dns-out"]) {
            hasDnsOut = YES;
        }
    }
    if (!hasFreedom) {
        [outbounds addObject:@{@"protocol": @"freedom", @"tag": @"direct"}];
    }
    if (!hasDnsOut) {
        [outbounds addObject:@{@"protocol": @"dns", @"tag": @"dns-out"}];
    }
    config[@"outbounds"] = outbounds;

    NSDictionary *sniffing = @{@"enabled": @YES, @"destOverride": @[@"http", @"tls", @"quic", @"fakedns"]};
    NSMutableArray *inbounds = [NSMutableArray arrayWithObject:@{
        @"tag": @"socks-in",
        @"listen": @"127.0.0.1",
        @"port": @(self.socksListenPort),
        @"protocol": @"socks",
        @"settings": @{@"udp": @YES, @"auth": @"noauth"},
        @"sniffing": sniffing,
    }];
    if (tunFileDescriptor >= 0) {
        [inbounds addObject:@{
            @"tag": @"tun-in",
            @"protocol": @"tun",
            @"settings": @{@"mtu": @1500, @"autoOutboundsInterface": @"auto"},
            @"sniffing": @{
                @"enabled": @YES,
                @"destOverride": @[@"http", @"tls", @"quic", @"fakedns"],
                @"metadataOnly": @NO,
            },
        }];
    }
    config[@"inbounds"] = inbounds;

    if (config[@"log"] == nil) {
        config[@"log"] = @{@"loglevel": @"warning"};
    }
    // App DNS is UDP/53 into the tunnel. VLESS/xHTTP often cannot carry UDP, so hijack
    // those queries to FakeDNS and restore the name via sniffing instead.
    config[@"dns"] = @{@"queryStrategy": @"UseIPv4", @"servers": @[@"fakedns", @"1.1.1.1"]};
    config[@"fakeDns"] = @{@"ipPool": @"198.18.0.0/15", @"poolSize": @65535};
    config[@"routing"] = @{
        @"domainStrategy": @"AsIs",
        @"rules": @[
            @{@"type": @"field", @"port": @53, @"network": @"udp", @"outboundTag": @"dns-out"},
            @{@"type": @"field", @"ip": @[@"198.18.0.0/15"], @"outboundTag": @"proxy"},
            @{@"type": @"field", @"outboundTag": @"direct",
              @"ip": @[@"10.0.0.0/8", @"127.0.0.0/8", @"169.254.0.0/16", @"172.16.0.0/12", @"192.168.0.0/16"]},
        ],
    };

    if (tunFileDescriptor >= 0) {
        NSMutableDictionary *env = [config[@"env"] isKindOfClass:[NSDictionary class]] ? [config[@"env"] mutableCopy] : [NSMutableDictionary dictionary];
        NSString *fd = [NSString stringWithFormat:@"%d", tunFileDescriptor];
        env[@"xray.tun.fd"] = fd;
        env[@"XRAY_TUN_FD"] = fd;
        config[@"env"] = env;
    }

    NSError *encodeError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:config options:0 error:&encodeError];
    NSString *json = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
    if (json == nil) {
        if (error != NULL) {
            *error = encodeError ?: [NSError errorWithDomain:kXrayConfigErrorDomain
                                                        code:2
                                                    userInfo:@{NSLocalizedDescriptionKey: @"Failed to encode Xray JSON configuration."}];
        }
        return nil;
    }
    return json;
}

+ (NSDictionary *)prepareOutbound:(NSDictionary *)outbound fallbackTag:(NSString *)fallbackTag {
    NSMutableDictionary *result = [outbound mutableCopy];
    NSString *sendThrough = [outbound[@"sendThrough"] isKindOfClass:[NSString class]] ? outbound[@"sendThrough"] : nil;
    NSString *trimmed = [sendThrough stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (trimmed.length > 0 && ![self isIpBindAddress:trimmed]) {
        [result removeObjectForKey:@"sendThrough"];
    }
    NSString *tag = [outbound[@"tag"] isKindOfClass:[NSString class]] ? outbound[@"tag"] : @"";
    if ([tag stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length == 0) {
        result[@"tag"] = fallbackTag;
    }
    return result;
}

+ (BOOL)isIpBindAddress:(NSString *)value {
    NSString *host = [value componentsSeparatedByString:@"/"].firstObject ?: value;
    if (host.length == 0) {
        return NO;
    }
    struct in_addr addr4;
    if (inet_pton(AF_INET, host.UTF8String, &addr4) == 1) {
        return YES;
    }
    struct in6_addr addr6;
    return inet_pton(AF_INET6, host.UTF8String, &addr6) == 1;
}

@end

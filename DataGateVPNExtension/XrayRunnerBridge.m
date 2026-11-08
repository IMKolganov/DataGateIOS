//
//  XrayRunnerBridge.m
//  DataGateVPNExtension
//
//  Same libXray CGoInvoke wrapper as DataGateMac (apiVersion 1).
//

#import "XrayRunnerBridge.h"

#import "libXray.h"

#include <stdlib.h>
#include <string.h>

static NSString *const kXrayRunnerErrorDomain = @"XrayRunnerBridge";

@implementation XrayRunnerBridge {
    void (^_logHandler)(NSString *);
}

- (instancetype)initWithLogHandler:(void (^)(NSString *message))logHandler {
    self = [super init];
    if (self) {
        _logHandler = [logHandler copy];
    }
    return self;
}

- (void)log:(NSString *)message {
    if (_logHandler) {
        _logHandler(message);
    }
}

- (nullable NSDictionary *)invokeMethod:(NSString *)method
                                payload:(nullable NSDictionary *)payload
                                  error:(NSError * _Nullable * _Nullable)error {
    NSMutableDictionary *request = [NSMutableDictionary dictionary];
    request[@"apiVersion"] = @1;
    request[@"method"] = method;
    if (payload != nil) {
        request[@"payload"] = payload;
    }

    NSError *encodeError = nil;
    NSData *requestData = [NSJSONSerialization dataWithJSONObject:request options:0 error:&encodeError];
    if (requestData == nil) {
        if (error != NULL) {
            *error = encodeError;
        }
        return nil;
    }

    NSString *requestJSON = [[NSString alloc] initWithData:requestData encoding:NSUTF8StringEncoding];
    if (requestJSON.length == 0) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:kXrayRunnerErrorDomain
                                         code:-1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to encode libXray request JSON"}];
        }
        return nil;
    }

    char *requestCStr = strdup([requestJSON UTF8String]);
    if (requestCStr == NULL) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:kXrayRunnerErrorDomain
                                         code:-1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to copy libXray request JSON"}];
        }
        return nil;
    }
    char *responseCStr = CGoInvoke(requestCStr);
    free(requestCStr);
    if (responseCStr == NULL) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:kXrayRunnerErrorDomain
                                         code:-2
                                     userInfo:@{NSLocalizedDescriptionKey: @"libXray returned a null response"}];
        }
        return nil;
    }

    NSString *responseJSON = [NSString stringWithUTF8String:responseCStr];
    CGoFree(responseCStr);
    if (responseJSON.length == 0) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:kXrayRunnerErrorDomain
                                         code:-3
                                     userInfo:@{NSLocalizedDescriptionKey: @"libXray returned an empty response"}];
        }
        return nil;
    }

    NSData *responseData = [responseJSON dataUsingEncoding:NSUTF8StringEncoding];
    NSError *decodeError = nil;
    id parsed = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:&decodeError];
    if (![parsed isKindOfClass:[NSDictionary class]]) {
        if (error != NULL) {
            *error = decodeError ?: [NSError errorWithDomain:kXrayRunnerErrorDomain
                                                        code:-4
                                                    userInfo:@{NSLocalizedDescriptionKey: @"libXray response is not a JSON object"}];
        }
        return nil;
    }

    NSDictionary *response = (NSDictionary *)parsed;
    NSNumber *success = response[@"success"];
    if (![success isKindOfClass:[NSNumber class]] || !success.boolValue) {
        NSString *message = response[@"error"];
        if (![message isKindOfClass:[NSString class]] || message.length == 0) {
            message = @"libXray invoke failed";
        }
        if (error != NULL) {
            *error = [NSError errorWithDomain:kXrayRunnerErrorDomain
                                         code:-5
                                     userInfo:@{NSLocalizedDescriptionKey: message}];
        }
        return nil;
    }

    id data = response[@"data"];
    if ([data isKindOfClass:[NSDictionary class]]) {
        return (NSDictionary *)data;
    }
    if (data == nil || data == [NSNull null]) {
        return @{};
    }
    return @{@"value": data};
}

- (BOOL)convertShareLink:(NSString *)shareLink
          outboundConfig:(NSDictionary * _Nullable * _Nullable)outboundConfig
                   error:(NSError * _Nullable * _Nullable)error {
    NSError *invokeError = nil;
    NSDictionary *data = [self invokeMethod:@"convertShareLinksToXrayJson"
                                    payload:@{@"text": shareLink ?: @""}
                                      error:&invokeError];
    if (data == nil) {
        if (error != NULL) {
            *error = invokeError;
        }
        return NO;
    }

    id config = data[@"config"];
    if (![config isKindOfClass:[NSDictionary class]] && [data[@"outbounds"] isKindOfClass:[NSArray class]]) {
        config = data;
    }
    if (![config isKindOfClass:[NSDictionary class]]) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:kXrayRunnerErrorDomain
                                         code:-6
                                     userInfo:@{NSLocalizedDescriptionKey: @"libXray did not return a share-link config object"}];
        }
        return NO;
    }

    NSNumber *usable = data[@"usableCount"];
    if (usable != nil) {
        [self log:[NSString stringWithFormat:@"[Xray] convertShareLinks usable=%@ failed=%@",
                   usable, data[@"failedCount"] ?: @0]];
    } else {
        NSArray *outbounds = [(NSDictionary *)config objectForKey:@"outbounds"];
        [self log:[NSString stringWithFormat:@"[Xray] convertShareLinks outbounds=%lu", (unsigned long)([outbounds isKindOfClass:[NSArray class]] ? outbounds.count : 0)]];
    }
    if (outboundConfig != NULL) {
        *outboundConfig = (NSDictionary *)config;
    }
    return YES;
}

- (BOOL)runXrayJson:(NSString *)xrayJson error:(NSError * _Nullable * _Nullable)error {
    NSError *invokeError = nil;
    NSDictionary *data = [self invokeMethod:@"runXrayFromJson"
                                    payload:@{@"configJSON": xrayJson ?: @""}
                                      error:&invokeError];
    if (data == nil) {
        if (error != NULL) {
            *error = invokeError;
        }
        return NO;
    }
    [self log:@"[Xray] runXray OK"];
    return YES;
}

- (void)stopXray {
    NSError *invokeError = nil;
    (void)[self invokeMethod:@"stopXray" payload:@{} error:&invokeError];
    if (invokeError != nil) {
        [self log:[NSString stringWithFormat:@"[Xray] stopXray: %@", invokeError.localizedDescription]];
    } else {
        [self log:@"[Xray] stopXray OK"];
    }
}

@end

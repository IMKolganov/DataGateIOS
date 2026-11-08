#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Thin wrapper around libXray `CGoInvoke` / `CGoFree` (apiVersion 1).
@interface XrayRunnerBridge : NSObject

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)new NS_UNAVAILABLE;

- (instancetype)initWithLogHandler:(void (^)(NSString *message))logHandler NS_DESIGNATED_INITIALIZER;

/// Invoke a libXray method. `payload` is encoded as the request `payload` object.
- (nullable NSDictionary *)invokeMethod:(NSString *)method
                                payload:(nullable NSDictionary *)payload
                                  error:(NSError * _Nullable * _Nullable)error;

- (BOOL)convertShareLink:(NSString *)shareLink
          outboundConfig:(NSDictionary * _Nullable * _Nullable)outboundConfig
                   error:(NSError * _Nullable * _Nullable)error;

- (BOOL)runXrayJson:(NSString *)xrayJson error:(NSError * _Nullable * _Nullable)error;
- (void)stopXray;

@end

NS_ASSUME_NONNULL_END

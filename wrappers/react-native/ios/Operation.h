// Inspired by @see https://raw.githubusercontent.com/Emurgo/react-native-cardano/master/ios/RNCSafeOperation.h

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>

NS_ASSUME_NONNULL_BEGIN

@interface RnBaseOperation<In, Out> : NSObject

- (Out)exec:(In)param error:(NSError **)error;

- (void)exec:(In)param withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject;

@end

@interface Operation<In, Out> : RnBaseOperation<In, Out>

+ (RnBaseOperation<In, Out> *)new:(Out(^)(In param, NSError** error))cb;

@end

NS_ASSUME_NONNULL_END

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Convert : NSObject

+ (NSData *)dataFromByteArray:(NSArray *)data;

+ (NSArray *)dataArrayFromArrayOfByteArrays:(NSArray *)array;

+ (NSArray *)byteArrayFromData:(NSData *)data;

@end

NS_ASSUME_NONNULL_END

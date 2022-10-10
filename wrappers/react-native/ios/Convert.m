#import "Convert.h"

@implementation Convert

+ (NSData *)dataFromByteArray:(NSArray *)array
{
    NSMutableData* data = [NSMutableData dataWithLength:[array count]];
    unsigned char *bytes = [data mutableBytes];
    for (NSUInteger index = 0; index < [array count]; index++) {
        bytes[index] = [[array objectAtIndex:index] unsignedCharValue];
    }
    return data;
}

+ (NSArray *)byteArrayFromData:(NSData *)data
{
    NSMutableArray *array = [[NSMutableArray alloc] initWithCapacity:[data length]];
    const unsigned char *bytes = [data bytes];
    for (NSUInteger index = 0; index < [data length]; index++) {
        [array addObject: [NSNumber numberWithChar:(unsigned char)bytes[index]]];
    }
    return array;
}

+ (NSArray *)dataArrayFromArrayOfByteArrays:(NSArray *)array
{
    NSMutableArray *result = [[NSMutableArray alloc] initWithCapacity:[array count]];
    for (NSUInteger index = 0; index < [array count]; index++) {
        [result addObject: [Convert dataFromByteArray:[array objectAtIndex:index]]];
    }
    return result;
}

@end

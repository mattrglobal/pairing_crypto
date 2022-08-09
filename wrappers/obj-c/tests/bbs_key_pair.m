#import <XCTest/XCTest.h>
#import "../pairing_crypto/pairing_crypto.h"
#import "../pairing_crypto/bbs_key_pair.h"

@interface BbsKeyPairTests : XCTestCase

@end

@implementation BbsKeyPairTests

- (void)testGenerateKeyPairWithKeyInfo {
    NSError *error = nil;
    NSData *expectedPublicKey = [[NSData alloc] initWithBase64EncodedString:@"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36" options:0];
    NSData *expectedSecretKey = [[NSData alloc] initWithBase64EncodedString:@"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=" options:0];
    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];

    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    XCTAssertEqualObjects(keyPair.publicKey, expectedPublicKey);
    XCTAssertEqualObjects(keyPair.secretKey, expectedSecretKey);

    XCTAssertEqual(keyPair.publicKey.length, BBS_BLS12381_PUBLIC_KEY_SIZE);
    XCTAssertEqual(keyPair.secretKey.length, BBS_BLS12381_SECRET_KEY_SIZE);
}

- (void)testGenerateKeyPairWithoutKeyInfo {
    NSError *error = nil;
    NSData *expectedPublicKey = [[NSData alloc] initWithBase64EncodedString:@"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36" options:0];
    NSData *expectedSecretKey = [[NSData alloc] initWithBase64EncodedString:@"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=" options:0];
    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = nil;

    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    XCTAssertEqualObjects(keyPair.publicKey, expectedPublicKey);
    XCTAssertEqualObjects(keyPair.secretKey, expectedSecretKey);

    XCTAssertEqual(keyPair.publicKey.length, BBS_BLS12381_PUBLIC_KEY_SIZE);
    XCTAssertEqual(keyPair.secretKey.length, BBS_BLS12381_SECRET_KEY_SIZE);
}

@end

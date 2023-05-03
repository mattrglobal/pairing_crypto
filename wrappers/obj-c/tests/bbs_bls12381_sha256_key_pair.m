#import <XCTest/XCTest.h>
#import "../pairing_crypto/pairing_crypto_bbs.h"
#import "../pairing_crypto/bbs_bls12381_sha256_key_pair.h"

@interface PCLBbsKeyPairTests : XCTestCase

@end

@implementation PCLBbsKeyPairTests

- (void)testGenerateKeyPairWithKeyInfo {
    NSError *error = nil;
    NSData *expectedPublicKey = [[NSData alloc] initWithBase64EncodedString:@"rEW2pImx3fpJke6rwy0s5mUjXm7mlV3y8dly/tvHzTJgqt+sK1mquSjw+1msfkmsCQyMtVTmj02uUV10pR97qjHXbHhzmQ6FyWtKzpVYg/LcbErldi5Xa4r4575H9eJE" options:0];
    NSData *expectedSecretKey = [[NSData alloc] initWithBase64EncodedString:@"ITGNO/Nkz0VlQ72HecUWwxMip3ezANJRyPRevqDmKv0=" options:0];
    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];

    PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    XCTAssertEqualObjects(keyPair.publicKey, expectedPublicKey);
    XCTAssertEqualObjects(keyPair.secretKey, expectedSecretKey);

    XCTAssertEqual(keyPair.publicKey.length, BBS_BLS12381_PUBLIC_KEY_SIZE);
    XCTAssertEqual(keyPair.secretKey.length, BBS_BLS12381_SECRET_KEY_SIZE);
}

- (void)testGenerateKeyPairWithoutKeyInfo {
    NSError *error = nil;
    NSData *expectedPublicKey = [[NSData alloc] initWithBase64EncodedString:@"qOh/NYDb9/mORDFsQxWnrg1zao7cipqjU8C78ctlYhfRn6pq/eWm/DtM4VucAhzuBdqOHjn/xr03qBKGiMjUMWVXMJTrtasNwNNbjDipGTZgWh7F4vI4+wVy4l4v8XzO" options:0];
    NSData *expectedSecretKey = [[NSData alloc] initWithBase64EncodedString:@"LngYzW4JNd5WG0NfuMJOpp5h3W/o2hUVAujQ2ApzprU=" options:0];
    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = nil;

    PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    XCTAssertEqualObjects(keyPair.publicKey, expectedPublicKey);
    XCTAssertEqualObjects(keyPair.secretKey, expectedSecretKey);

    XCTAssertEqual(keyPair.publicKey.length, BBS_BLS12381_PUBLIC_KEY_SIZE);
    XCTAssertEqual(keyPair.secretKey.length, BBS_BLS12381_SECRET_KEY_SIZE);
}

@end

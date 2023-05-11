#import <XCTest/XCTest.h>
#import "../pairing_crypto/pairing_crypto_bbs.h"
#import "../pairing_crypto/bbs_bls12381_sha256_key_pair.h"
#import "../pairing_crypto/bbs_bls12381_sha256_signature.h"

@interface PCLBbsSignatureTests : XCTestCase

@end

@implementation PCLBbsSignatureTests

- (void)testSignSingleMessage {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];

    PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] sign:keyPair.secretKey
                                               publicKey:keyPair.publicKey
                                                  header:header
                                                messages:messages
                                               withError:&error];

    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
}

- (void)testSignMultipleMessages {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];

    PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] sign:keyPair.secretKey
                                               publicKey:keyPair.publicKey
                                                  header:header
                                                messages:messages
                                               withError:&error];

    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
}

- (void)testSignAndVerifySingleMessage {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];

    PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] sign:keyPair.secretKey
                                               publicKey:keyPair.publicKey
                                                  header:header
                                                messages:messages
                                               withError:&error];

    bool isVerified = [signature verify:keyPair.publicKey
                                 header:header
                               messages:messages
                              withError:&error];

    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
    XCTAssertTrue(isVerified);
}

- (void)testSignAndVerifyMultipleMessages {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];

    PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] sign:keyPair.secretKey
                                               publicKey:keyPair.publicKey
                                                  header:header
                                                messages:messages
                                               withError:&error];

    bool isVerified = [signature verify:keyPair.publicKey
                                 header:header
                               messages:messages
                              withError:&error];

    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
    XCTAssertTrue(isVerified);
}

- (void)testSignThrowErrorWithWrongSingleMessage {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];

    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"kTV8dar9xLWQZ5EzaWYqTRmgA6dw6wcrUw5c///crRD2QQPXX9Di+lgCPCXAA5D8Pytuh6bNSx6k4NZTR9KfSNdaejKl2zTU9poRfzZ2SIskdgSHTZ2y7jLm/UEGKsAs3tticBVj1Pm2GNhQI/OlXQ==" options:0];
    PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];

    bool isVerified = [signature verify:keyPair.publicKey
                                 header:header
                               messages:messages
                              withError:&error];

    XCTAssertFalse(isVerified);
    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
}

- (void)testSignThrowErrorWithWrongMessages {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];

    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"iWIbLh10y1BkB6h+6ILXg6pJTKanCcE5C+IaRlxeNqk4GpygZywGxopHgnGD7KNUW8kT4rslyHoud5gML2luEiSqT0MsX63OTysfj2Y2nXM=" options:0];
    PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];

    bool isVerified = [signature verify:keyPair.publicKey
                                 header:header
                               messages:messages
                              withError:&error];

    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
    XCTAssertFalse(isVerified);
}

@end

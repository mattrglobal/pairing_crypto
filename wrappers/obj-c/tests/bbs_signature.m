#import <XCTest/XCTest.h>
#import "../pairing_crypto/bbs_key_pair.h"
#import "../pairing_crypto/bbs_signature.h"
#import "../pairing_crypto/pairing_crypto.h"

@interface BbsSignatureTests : XCTestCase

@end

@implementation BbsSignatureTests

- (void)testSignSingleMessage {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:keyPair
                                                  header:header
                                                messages:messages
                                               withError:&error];
    
    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
}

- (void)testSignMultipleMessages {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];
    
    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:keyPair
                                                  header:header
                                                messages:messages
                                               withError:&error];
    
    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
}

- (void)testSignAndVerifySingleMessage {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:keyPair
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
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:keyPair
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
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"kTV8dar9xLWQZ5EzaWYqTRmgA6dw6wcrUw5c///crRD2QQPXX9Di+lgCPCXAA5D8Pytuh6bNSx6k4NZTR9KfSNdaejKl2zTU9poRfzZ2SIskdgSHTZ2y7jLm/UEGKsAs3tticBVj1Pm2GNhQI/OlXQ==" options:0];
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];
    
    bool isVerified = [signature verify:keyPair.publicKey
                                 header:header
                               messages:messages
                              withError:&error];
    
    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
    XCTAssertFalse(isVerified);
}

- (void)testSignThrowErrorWithWrongMessages {
    NSError *error = nil;

    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];
    
    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"jYidhsdqxvAyNXMV4/vNfGM/4AULfSyfvQiwh+dDd4JtnT5xHnwpzMYdLdHzBYwXaGE1k6ln/pwtI4RwQZpl03SCv/mT/3AdK8PB2y43MGdMSeGTyZGfZf+rUrEDEs3lTfmPK54E+JBzd96gnrF2iQ==" options:0];
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];
    
    bool isVerified = [signature verify:keyPair.publicKey
                                 header:header
                               messages:messages
                              withError:&error];
    
    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
    XCTAssertFalse(isVerified);
}

@end

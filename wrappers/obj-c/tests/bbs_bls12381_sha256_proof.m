#import <XCTest/XCTest.h>
#import "../pairing_crypto/pairing_crypto_bbs.h"
#import "../pairing_crypto/bbs_bls12381_sha256_key_pair.h"
#import "../pairing_crypto/bbs_bls12381_sha256_signature.h"
#import "../pairing_crypto/bbs_bls12381_sha256_proof.h"

@interface BbsProofTests : XCTestCase

@end

@implementation BbsProofTests

- (void) testProof {
    NSError *error = nil;
    bool isVerified = false;
    NSData *header = [@"Test-Header" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *presentationMessage = [@"Test-Presentation-Message" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"SjQyQXhoY2lPVmtFOXc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"UE5NbkFSV0lIUCtzMmc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"dGk5V1loaEVlajg1anc9PQ==" options:0], nil];
    NSData *ikm = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *keyInfo = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsBls12381Sha256KeyPair *keyPair = [[BbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                               withError:&error];

    BbsBls12381Sha256Signature *signature = [[BbsBls12381Sha256Signature alloc] sign:keyPair.secretKey
                                               publicKey:keyPair.publicKey
                                                  header:header
                                                messages:messages
                                               withError:&error];

    isVerified = [signature verify:keyPair.publicKey
                                 header:header
                               messages:messages
                              withError:&error];

    XCTAssertEqual(signature.value.length, BBS_BLS12381_SIGNATURE_SIZE);
    XCTAssertTrue(isVerified);

    // Start with all hidden messages
    NSMutableSet *disclosedIndices = [[NSMutableSet alloc] init];

    for (int i = 0; i < [messages count]; i++ ) {
        BbsBls12381Sha256Proof *proof = [[BbsBls12381Sha256Proof alloc] createProof:keyPair.publicKey
                                                               header:header
                                                  presentationMessage:presentationMessage
                                                            signature:signature
                                                     disclosedIndices:disclosedIndices
                                                             messages:messages
                                                            withError:&error];

        NSMutableDictionary *disclosedMessages = [[NSMutableDictionary alloc] init];
        for (int j = 0; j < i; j++) {
            [disclosedMessages setObject:[messages objectAtIndex:j] forKey:[NSNumber numberWithInt:j]];
        }

        isVerified = false;
        isVerified = [proof verifyProof:keyPair.publicKey
                                  header:header
                     presentationMessage:presentationMessage
                     total_message_count:messages.count
                                messages:disclosedMessages
                               withError:&error];

        XCTAssertTrue(isVerified);
        [disclosedIndices addObject:[NSNumber numberWithInt:i]];
    }
}

@end

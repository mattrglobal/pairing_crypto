#import <Foundation/Foundation.h>

#import "include/bbs/bbs_signature.h"
#import "pairing_crypto_bbs.h"
#import "include/PairingCryptoError.h"

/** @brief BBS Signature */
@interface BbsSignature ()

/** @brief signature */
@property(nonatomic, readwrite) NSData *value;

@end

/** @brief BBS Signature */
@implementation BbsSignature

/**
* @brief Create a BBS signature from the raw bytes.
*/
- (nullable instancetype)initWithBytes:(NSData* _Nonnull)bytes
                             withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createFromBytes:bytes
                withError:errorPtr];
    return self;
}

/**
* @brief Create a BBS signature.
*/
- (nullable instancetype)sign:(NSData *_Nonnull)secretKey
                    publicKey:(NSData *_Nonnull)publicKey
                       header:(NSData *_Nullable)header
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createSignature:secretKey
                publicKey:publicKey
                   header:header
                 messages:messages
                withError:errorPtr];
    return self;
}

/**
* @Verifiy the BBS signature.
*/
- (bool)verify:(NSData *_Nonnull)publicKey
        header:(NSData *_Nullable)header
      messages:(NSArray *_Nullable)messages
     withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    return [self verifySignature:publicKey
                          header:header
                        messages:messages
                       withError:errorPtr];
}

- (nullable instancetype)createFromBytes:(NSData* _Nonnull)bytes
                               withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    self.value = [[NSData alloc] initWithData:bytes];
    return self;
}

- (void) createSignature:(BbsKeyPair* _Nonnull)keyPair
                  header:(NSData *_Nullable)header
                messages:(NSArray *_Nullable)messages
               withError:(NSError* _Nullable*_Nullable)errorPtr {

                [self doesNotRecognizeSelector:_cmd];
}

- (bool)verifySignature:(NSData *_Nonnull)publicKey
                 header:(NSData *_Nullable)header
               messages:(NSArray *_Nullable)messages
              withError:(NSError *_Nullable*_Nullable)errorPtr {

                [self doesNotRecognizeSelector:_cmd];
    return false;
}

@end

#ifndef bbs_signature_h
#define bbs_signature_h

#include "bbs_key_pair.h"

/** @brief BBS Signature */
@interface BbsSignature : NSObject

/** @brief signature */
@property(strong, atomic, readwrite) NSData *_Nonnull value;

/**
 * @brief Creates a BBS signature from the raw bytes
 */
- (nullable instancetype)initWithBytes:(NSData *_Nonnull)bytes
                             withError:(NSError *_Nullable *_Nullable)errorPtr;

/**
 * @brief Creates a BBS signature
 */
- (nullable instancetype)sign:(NSData *_Nonnull)secretKey
                    publicKey:(NSData *_Nonnull)publicKey
                       header:(NSData *_Nullable)header
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr;

/**
 * @Verifies the BBS signature
 */
- (bool)verify:(NSData *_Nonnull)publicKey
        header:(NSData *_Nullable)header
      messages:(NSArray *_Nullable)messages
     withError:(NSError *_Nullable *_Nullable)errorPtr;

- (void)createSignature:(NSData *_Nonnull)secretKey
              publicKey:(NSData *_Nonnull)publicKey
                 header:(NSData *_Nullable)header
               messages:(NSArray *_Nullable)messages
              withError:(NSError *_Nullable *_Nullable)errorPtr;

- (bool)verifySignature:(NSData *_Nonnull)publicKey
                 header:(NSData *_Nullable)header
               messages:(NSArray *_Nullable)messages
              withError:(NSError *_Nullable *_Nullable)errorPtr;

@end

#endif /* bbs_signature_h */

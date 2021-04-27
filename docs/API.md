# APIs

The following document defines the conventions and concrete API structure for this library

## Conventions

The APIs use the following namespacing to indicate the operations a caller would like to perform:

curve.\[scheme\].\[ciphersuite\].operation(inputs) -> output

Curves are the elliptic curve to be used to execute underlying cryptographic operations such as: bn256, bls12831, tweedle.

Scheme if included is the crypto primitive to use such as: bls, bbs, cdlnt, accumulator, bulletproof.

Ciphersuite if included specifies the suite to use for that system and operation like hashes, salts, and tags.

Operation is the function to be executed such as: key_gen, sign, verify, blind_sign, gen_proof, verify_proof, update.

## Curve Operations

1. {curve}.keygen(ikm, is_vt) -> kp = {pk, sk} says use the BLS12-381 curve for the BLS signature to create a new secret key using the provided input key material and corresponding public key in G1 or the variant G2.

## Schemes

1. Accumulator
1. BLS
1. BBS

### BLS Operations

1. {curve}.bls.sign(kp, msg) -> &sigma;
1. {curve}.bls.verify(pk, msg, &sigma;) -> true or false
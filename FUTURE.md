The APIs use the following namespacing to indicate the operations a caller would like to perform:

parameters.scheme.ciphersuite.operation(inputs) -> output

Parameters are the system to be used to execute underlying cryptographic operations such as: bn256, bls12831, tweedle.

Scheme is the crypto primitive to use such as: bls, bbs, cdlnt, accumulator, bulletproof.

Ciphersuite specifies the suite to use for that system and operation like hashes, salts, and tags.

Operation is the function to be executed such as: key_gen, sign, verify, blind_sign, gen_proof, verify_proof, update.

For example

1. bls12381.keygen(ikm, is_vt) -> kp = {pk, sk} says use the BLS12-381 curve for the BLS signature to create a new secret key using the provided input key material and corresponding public key in G1 or the variant G2.
1. bls12381.bls.sign(kp, msg) -> 
1. bls12381.bls.verify(pk, msg, &sigma;) ->
   

1. bls12381.bls.augmented.sign(kp, msg) ->
1. bls12381.bls.possession.sign(kp, msg) ->
1. bls12381.bls.augmented.verify(pk, msg, &sigma;) ->
1. bls12381.bls.possession.verify(pk, msg, &sigma;) ->
1. bls12381.bls.augment.aggregate(\[&sigma;...\]) ->
1. bls12381.bls.possession.aggregate(\[&sigma;...\]) ->
1. bls12381.bls.augment.aggregate_verify(\[&sigma;...\]) ->
1. bls12381.bls.possession.aggregate_verify(\[&sigma;...\]) ->

# BLS

The BLS signature scheme defines the following API ciphersuites and operations

## Ciphersuites

The cipher suites are as defined in the [IETF spec](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1) section 4

1. basic - the basic or nul suite
1. augment - message augmentation suite
1. possess - proof of possession suite

## Operations 

1. key_gen(ikm) -> sk: create a new secret key using the provided input key material. If 0 &le; length(ikm) &lt; 32, it is ignored and a random value is used, otherwise the provided value is used to seed the key generation operation.
1. to_pk(sk) -> pk &isin; G1: get the corresponding public key in G1 from the secret key
1. to_pk_vt(sk) -> pk &isin; G2: get the corresponding public key in G2 from the secret key
1. sign(sk, msg) -> &sigma; &isin; G2: create a signature in G2 over msg using the secret key
1. sign_vt(sk, msg) -> &sigma; &isin; G1: create a signature in G1 over msg using the secret key
1. verify(pk, msg, &sigma;) -> TRUE or FALSE: verify a signature is over msg using the public key
1. aggregate([&sigma;<sub>1</sub>,...]) -> &sigmaf;: combine multiple signatures into one assuming the signatures are over unique messages
1. aggregate_verify([(pk<sub>1</sub>, msg<sub>1</sub>),...], &sigmaf;) -> TRUE or FALSE: verify an aggregated signature over multiple public key and message pairs. Each message is unique.
1. combine([&sigma;<sub>1</sub>,...]) -> &phi;: create a multisignature using multiple signatures into one assuming the signatures are over the same message
1. combine_verify([pk<sub>1</sub>...], msg, &phi;) -> TRUE or FALSE: verify a multisignature from multiple public keys is over the specified message
1. proof(sk) -> &theta; &isin; G2: create a proof of possession in G2
1. proof_vt(sk) -> &theta; &isin; G1: create a proof of possession in G1

# BBS+

1. key_gen(ikm) -> sk: create a new secret key using the provided input key material. If 0 &le; length(ikm) &lt; 32, it is ignored and a random value is used, otherwise the provided value is used to seed the key generation operation.
1. to_pk(sk) -> pk &isin; G2: get the corresponding public key in G1 from the secret key.
1. **FUTURE** get_message_generators(pk, L) -> \[H<sub>1</sub>,...,H<sub>L</sub>\] 
1. sign(sk, msgs) -> &sigma;
1. verify(pk, msgs, &sigma;) -> true or false
1. derive_proof(pk, msgs, A<sub>r</sub>, &sigma;) -> &pi;: A<sub>r</sub> is the indices of all the revealed attributes
1. verify_proof(pk, A<sub>r</sub>, msgs<sub>r</sub>, &pi;) -> true or false

# CDLNT

# Accumulator

# Bulletproofs
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pairing_crypto.h"


int main(int argc, char** argv) {
    ByteArray* seed = (ByteArray*) malloc(sizeof(ByteArray));
    ByteArray* public_key = (ByteArray*) malloc(sizeof(ByteArray));
    ByteArray* secret_key = (ByteArray*) malloc(sizeof(ByteArray));

    const int message_count = 5;
    ByteArray* message;
    ByteArray** messages = (ByteArray**) malloc(message_count * sizeof(ByteArray*));
    ByteArray* signature = (ByteArray*) malloc(sizeof(ByteArray));

    ExternError* err = (ExternError*) malloc(sizeof(ExternError));

    uint64_t handle;
    int i;

    seed->length = 0;
    seed->data = NULL;

    printf("Create BLS12381 G2 key pair...");
    fflush(stdout);

    if (bls12381_generate_g2_key(*seed, (ByteBuffer*) public_key, (ByteBuffer*) secret_key, err) != 0) {
        // TODO need to check the actual value of the populated public key and secret key
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");
    
    printf("Create BLS12381 G1 key pair...");
    fflush(stdout);

    if (bls12381_generate_g1_key(*seed, (ByteBuffer*) public_key, (ByteBuffer*) secret_key, err) != 0) {
        // TODO need to check the actual value of the populated public key and secret key
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    for (i = 0; i < message_count; i++) {
        message = (ByteArray*) malloc(sizeof(ByteArray));
        message->length = 10;
        message->data = (uint8_t *)malloc(10);
        memset((uint8_t *)message->data, i+1, 10);
        messages[i] = message;
    }

    printf("Create sign context...");
    fflush(stdout);
    handle = bls12381_bbs_sign_context_init(err);

    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set secret key in sign context...");
    fflush(stdout);
    if (bls12381_bbs_sign_context_set_secret_key(handle, *secret_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set messages sign context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++) {
        if (bls12381_bbs_sign_context_set_message(handle, *messages[i], err) != 0) {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Sign %d messages ...", message_count);
    fflush(stdout);
    if (bls12381_bbs_sign_context_finish(handle, (ByteBuffer*)signature, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");    

    printf("Signature is correct size...");
    if (signature->length != 112) { // TODO dont hardcode
        printf("fail\n");
        printf("Expected %d, found %lu\n", 112, signature->length);
        goto Exit;
    }
    printf("pass\n");


    printf("Create new verify signature context...");
    fflush(stdout);
    handle = bls12381_bbs_verify_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set messages in verify signature context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++) {
        if (bls12381_bbs_verify_context_set_message(handle, *messages[i], err) != 0) {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Set public key in verify signature context...");
    fflush(stdout);
    if (bls12381_bbs_verify_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set signature in verify signature context...");
    fflush(stdout);
    if (bls12381_bbs_verify_context_set_signature(handle, *signature, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Verifying signature...");
    fflush(stdout);
    if (bls12381_bbs_verify_context_finish(handle, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Tests Passed\n");

    goto Exit;
Fail:
    printf("Error Message = %s\n", err->message);
    printf("Tests Failed\n");
Exit:
    pairing_crypto_byte_buffer_free(*(ByteBuffer*)seed);
    pairing_crypto_byte_buffer_free(*(ByteBuffer*)public_key);
    pairing_crypto_byte_buffer_free(*(ByteBuffer*)secret_key);
   
    free(err);
    free(seed);
    free(public_key);
    free(secret_key);
}
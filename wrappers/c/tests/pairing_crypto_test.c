#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pairing_crypto.h"

int main(int argc, char **argv)
{
    const uint8_t *IKM = "12345678123456781234567812345678";
    ByteArray *ikm = (ByteArray *)malloc(sizeof(ByteArray));
    ByteArray *key_info = (ByteArray *)malloc(sizeof(ByteArray));
    ByteArray *secret_key = (ByteArray *)malloc(sizeof(ByteArray));
    ByteArray *public_key = (ByteArray *)malloc(sizeof(ByteArray));

    ByteArray *header = (ByteArray *)malloc(sizeof(ByteArray));

    const int message_count = 5;
    ByteArray *message;
    ByteArray **messages = (ByteArray **)malloc(message_count * sizeof(ByteArray *));
    ByteArray *signature = (ByteArray *)malloc(sizeof(ByteArray));

    ByteArray *presentation_message = (ByteArray *)malloc(sizeof(ByteArray));
    ByteArray *proof = (ByteArray *)malloc(sizeof(ByteArray));

    ExternError *err = (ExternError *)malloc(sizeof(ExternError));

    uint64_t handle;
    int i;

    ikm->length = 32;
    ikm->data = (uint8_t *)malloc(32);
    memcpy((void *)ikm->data, IKM, 32);

    key_info->length = 0;
    key_info->data = NULL;

    header->length = 16;
    header->data = (uint8_t *)malloc(60);
    memset((uint8_t *)header->data, 0xA, 16);

    presentation_message->length = 16;
    presentation_message->data = (uint8_t *)malloc(60);
    memset((uint8_t *)presentation_message->data, 15, 16);

    printf("Create BLS12381 key pair...");
    fflush(stdout);

    if (bls12381_generate_key_pair(*ikm, *key_info, (ByteBuffer *)secret_key, (ByteBuffer *)public_key, err) != 0)
    {
        // TODO need to check the actual value of the populated public key and secret key
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");
#if 1
    for (i = 0; i < message_count; i++)
    {
        message = (ByteArray *)malloc(sizeof(ByteArray));
        message->length = 10;
        message->data = (uint8_t *)malloc(10);
        memset((uint8_t *)message->data, i + 1, 10);
        messages[i] = message;
    }

    printf("Create sign context...");
    fflush(stdout);
    handle = bls12381_bbs_sign_context_init(err);

    if (handle == 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set secret key in sign context...");
    fflush(stdout);
    if (bls12381_bbs_sign_context_set_secret_key(handle, *secret_key, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in sign context...");
    fflush(stdout);
    if (bls12381_bbs_sign_context_set_public_key(handle, *public_key, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set header in sign context...");
    fflush(stdout);
    if (bls12381_bbs_sign_context_set_header(handle, *header, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set messages sign context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++)
    {
        if (bls12381_bbs_sign_context_add_message(handle, *messages[i], err) != 0)
        {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Sign %d messages ...", message_count);
    fflush(stdout);
    if (bls12381_bbs_sign_context_finish(handle, (ByteBuffer *)signature, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Signature is correct size...");
    if (signature->length != 112)
    { // TODO dont hardcode
        printf("fail\n");
        printf("Expected %d, found %lu\n", 112, signature->length);
        goto Exit;
    }
    printf("pass\n");

    printf("Create new verify signature context...");
    fflush(stdout);
    handle = bls12381_bbs_verify_context_init(err);
    if (handle == 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in verify signature context...");
    fflush(stdout);
    if (bls12381_bbs_verify_context_set_public_key(handle, *public_key, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set header in verify context...");
    fflush(stdout);
    if (bls12381_bbs_verify_context_set_header(handle, *header, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set messages in verify signature context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++)
    {
        if (bls12381_bbs_verify_context_set_message(handle, *messages[i], err) != 0)
        {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Set signature in verify signature context...");
    fflush(stdout);
    if (bls12381_bbs_verify_context_set_signature(handle, *signature, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Verifying signature...");
    fflush(stdout);
    if (bls12381_bbs_verify_context_finish(handle, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Create new derive proof context...");
    fflush(stdout);
    handle = bls12381_bbs_derive_proof_context_init(err);
    if (handle == 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set header in proof context...");
    fflush(stdout);
    if (bls12381_bbs_derive_proof_context_set_header(handle, *header, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Adding messages to proof context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++)
    {
        if (bls12381_bbs_derive_proof_context_add_message(handle, messages[i], true, err) != 0)
        {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Setting signature in proof context...");
    fflush(stdout);
    if (bls12381_bbs_derive_proof_context_set_signature(handle, *signature, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in proof context...");
    fflush(stdout);
    if (bls12381_bbs_derive_proof_context_set_public_key(handle, *public_key, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set presentation message in proof context...");
    fflush(stdout);
    if (bls12381_bbs_derive_proof_context_set_presentation_message(handle, *presentation_message, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Creating proof...");
    fflush(stdout);
    if (bls12381_bbs_derive_proof_context_finish(handle, (ByteBuffer *)proof, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Create new verify proof context...");
    fflush(stdout);
    handle = bls12381_bbs_verify_proof_context_init(err);
    if (handle == 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set header in proof context...");
    fflush(stdout);
    if (bls12381_bbs_verify_proof_context_set_header(handle, *header, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Adding messages to proof context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++)
    {
        if (bls12381_bbs_verify_proof_context_add_message(handle, messages[i], true, err) != 0)
        {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Setting proof in proof context...");
    fflush(stdout);
    if (bls12381_bbs_verify_proof_context_set_proof(handle, *proof, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in proof context...");
    fflush(stdout);
    if (bls12381_bbs_verify_proof_context_set_public_key(handle, *public_key, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set presentation message in proof context...");
    fflush(stdout);
    if (bls12381_bbs_verify_proof_context_set_presentation_message(handle, *presentation_message, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Verifying proof...");
    fflush(stdout);
    if (bls12381_bbs_verify_proof_context_finish(handle, err) != 0)
    {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Tests Passed\n");

    goto Exit;
#endif
Fail:
    printf("Error Message = %s\n", err->message);
    printf("Tests Failed\n");
Exit:
    pairing_crypto_byte_buffer_free(*(ByteBuffer *)public_key);
    pairing_crypto_byte_buffer_free(*(ByteBuffer *)secret_key);

    free(err);
    free(ikm);
    free(key_info);
    free(public_key);
    free(secret_key);
}
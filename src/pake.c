#include <stddef.h>
#include <stdint.h>
#include "ciphertext.h"
#include "indcpa.h"
#include "io.h"
#include "kem.h"
#include "pack.h"
#include "pake.h"
#include "parameters.h"
#include "poly.h"
#include "rng.h"
#include "aes.h"
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 16


void encryptData(const uint8_t *key, uint8_t *data, size_t dataSize) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    for (size_t i = 0; i < dataSize; i += BLOCK_SIZE) {
        AES_ECB_encrypt(&ctx, data + i);
    }
}

void decryptData(const uint8_t *key, uint8_t *data, size_t dataSize) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    for (size_t i = 0; i < dataSize; i += BLOCK_SIZE) {
        AES_ECB_decrypt(&ctx, data + i);
    }
}
void printData(const uint8_t *data, size_t dataSize) {
    for (size_t i = 0; i < dataSize; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


int pake_a0(uint8_t *pw, uint8_t *ssid, uint8_t *send_a0, uint8_t *state_1, uint8_t *pk, uint8_t *sk) {
    int i;

    uint8_t key[16] = "my_128_bit_key";
    uint8_t conc[PAKE_A0_SEND];
    uint8_t conc1[PAKE_A0_SEND];
   
    
    crypto_kem_keypair(pk, sk);
    

    for(i = 0; i < ID_BYTES ; i++ ){
    	conc[i] = ssid[i];
    } 
    
    for(i = 0; i < PW_BYTES ; i++ ){
    	conc[i + ID_BYTES] = pw[i];
    } 
    
    for(i = 0; i < PUBLICKEY_BYTES ; i++ ){
    	conc[i + ID_BYTES + PW_BYTES] = pk[i];
    } 

    encryptData(key, conc, PAKE_A0_SEND);
    memcpy(send_a0, conc, PAKE_A0_SEND);
 

    return 1;
}

int pake_b0(uint8_t *send_a0, uint8_t *pw, uint8_t *a_id,  uint8_t *b_id, uint8_t *ssid, uint8_t *send_b0,uint8_t *state_2,uint8_t *ct, uint8_t *key_b){
    printf("\n ******************PAKE B0****************** \n");
    uint8_t key[16] = "my_128_bit_key";
    int AUTH_SIZE = ID_BYTES*3 + PW_BYTES + AES_BLOCK_SIZE + CIPHERTEXT_BYTES + CRYPTO_BYTES;

    int i;
    const char *keyData = "my_128_bit_key";

    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t auth[AUTH_SIZE];

    decryptData(key, send_a0, PAKE_A0_SEND);


    for(i = 0 ; i < PUBLICKEY_BYTES ; i++){
        pk[i] = send_a0[ID_BYTES + PW_BYTES + i];
    }
    
    crypto_kem_encap(ct, key_b, pk);

    printf("keyB:");
    printData(key_b, 32);
   

    for(i = 0; i < ID_BYTES ; i++ ){
    	auth[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES ; i++ ){
    	auth[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES ; i++ ){
    	auth[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PW_BYTES ; i++ ){
    	auth[i + ID_BYTES*3] = b_id[i];
    } 

    for(i = 0; i < AES_BLOCK_SIZE ; i++ ){
    	auth[i + ID_BYTES*3 + PW_BYTES] = send_a0[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES ; i++ ){
    	auth[i + ID_BYTES*3 + PW_BYTES + AES_BLOCK_SIZE] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
    	auth[i + ID_BYTES*3 + PW_BYTES + AES_BLOCK_SIZE + CIPHERTEXT_BYTES] = key_b[i];
    } 


    hash_h(send_b0, auth, AUTH_SIZE);


}


int pake_a1(uint8_t *pk, uint8_t *sk, uint8_t *send_a0, uint8_t *ssid, uint8_t *pw, uint8_t *a_id, uint8_t *b_id, uint8_t *ct, uint8_t *send_b0, uint8_t *key_a){
    uint8_t k_prime[CRYPTO_BYTES];
    int i;

    crypto_kem_decap(k_prime, sk, pk, ct);

    printf("k_prime:");
    printData(k_prime, 32);
    
}



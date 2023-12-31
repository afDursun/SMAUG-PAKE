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


void pake_a0(const unsigned char *pw, const uint8_t *ssid, uint8_t *epk, uint8_t *pk, uint8_t *sk) {
    printf("\n****************PAKE-A0****************");
    int i;
    const uint8_t key[16] = "my_128_bit_key";
    uint8_t components[PAKE_A0_SEND];
    
    crypto_kem_keypair(pk, sk);
    printf("\npk size:%d\n" , PUBLICKEY_BYTES);
    printf("sk size:%d\n" , KEM_SECRETKEY_BYTES);
    

    for(i = 0; i < ID_BYTES ; i++ ){
        components[i] = ssid[i];
    } 
    
    for(i = 0; i < PW_BYTES ; i++ ){
        components[i + ID_BYTES] = pw[i];
    } 
    
    for(i = 0; i < PUBLICKEY_BYTES ; i++ ){
        components[i + ID_BYTES + PW_BYTES] = pk[i];
    } 


    encryptData(key, components, PAKE_A0_SEND);
    memcpy(epk, components, PAKE_A0_SEND);

    
    printf("\nA0 ---> B0:   ");
    printf("A(%d), epk(%d) \nTotal Send %d bytes",ID_BYTES,PAKE_A0_SEND, ID_BYTES+PAKE_A0_SEND);
    printf("\n***************************************\n\n\n");

}

void pake_b0(const unsigned char *pw, const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id,  
                    uint8_t *epk, uint8_t *send_b0,uint8_t *ct,uint8_t *k,uint8_t *auth_b){
    printf("\n****************PAKE-B0****************");
    uint8_t key[16] = "my_128_bit_key";
    int i;
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t components[PAKE_A0_SEND];
    
    memcpy(components, epk, PAKE_A0_SEND);
    decryptData(key, components, PAKE_A0_SEND);


    for(i = 0 ; i < PUBLICKEY_BYTES ; i++){
        pk[i] = components[ID_BYTES + PW_BYTES + i];
    }
    
    crypto_kem_encap(ct, k, pk);

    for(i = 0; i < ID_BYTES ; i++ ){
        auth_b[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES ; i++ ){
        auth_b[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES ; i++ ){
        auth_b[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PW_BYTES ; i++ ){
        auth_b[i + ID_BYTES*3] = pw[i];
    } 

    for(i = 0; i < PAKE_A0_SEND ; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES] = epk[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES ; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND + CIPHERTEXT_BYTES] = k[i];
    } 

    hash_h(send_b0, auth_b, AUTH_SIZE);

    
    printf("\nA1 <--- B0:   ");
    printf("B(%d), c(%d), Auth(%d) \nTotal Send %d bytes",ID_BYTES,CIPHERTEXT_BYTES,AUTH_SIZE,ID_BYTES+CIPHERTEXT_BYTES+AUTH_SIZE);
    printf("\n***************************************\n\n\n");

}


void pake_a1(const unsigned char *pw, uint8_t *pk, uint8_t *sk, uint8_t *epk, uint8_t *send_b0, const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id, uint8_t *ct, uint8_t *key_a){
    printf("\n****************PAKE-A1****************");
    uint8_t k_prime[CRYPTO_BYTES];
    int i;
    int HASH_SIZE = ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES + AUTH_SIZE +CRYPTO_BYTES;
    uint8_t auth[AUTH_SIZE];
    uint8_t control_auth[SHA3_256_HashSize];
    uint8_t hash_array[HASH_SIZE];

    crypto_kem_decap(k_prime, sk, pk, ct);

    //bunu parametre olarak gönder
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
        auth[i + ID_BYTES*3] = pw[i];
    } 

    for(i = 0; i < PAKE_A0_SEND ; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES] = epk[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES ; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND + CIPHERTEXT_BYTES] = k_prime[i];
    } 


    hash_h(control_auth, auth, AUTH_SIZE);

    if (memcmp(control_auth, send_b0, SHA3_256_HashSize) == 0) {
        for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i] = ssid[i];
        } 
        
        for(i = 0; i < ID_BYTES ; i++ ){
            hash_array[i + ID_BYTES] = a_id[i];
        } 

        for(i = 0; i < ID_BYTES ; i++ ){
            hash_array[i + ID_BYTES*2] = b_id[i];
        } 

        for(i = 0; i < PAKE_A0_SEND ; i++ ){
            hash_array[i + ID_BYTES*3 ] = epk[i];
        } 

        for(i = 0; i < CIPHERTEXT_BYTES ; i++ ){
            hash_array[i + ID_BYTES*3  + PAKE_A0_SEND] = ct[i];
        } 

        for(i = 0; i < AUTH_SIZE ; i++ ){
            hash_array[i + ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES] = auth[i];
        } 

        for(i = 0; i < CRYPTO_BYTES ; i++ ){
            hash_array[i + ID_BYTES*3  + PAKE_A0_SEND + CIPHERTEXT_BYTES+ AUTH_SIZE] = k_prime[i];
        } 
        
        hash_h(key_a, hash_array, HASH_SIZE);

        printf("\nsuccess...");
        printf("\nSession Key A:");
        printData(key_a,SHA3_256_HashSize);
        printf("***************************************\n\n\n");
    } else {
        printf("Auth Failed....\n");
    }
    
    

}

void pake_b1(const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id, uint8_t *epk, uint8_t *ct, uint8_t *auth_b, uint8_t *k, uint8_t *key_b){
    printf("\n****************PAKE-B1****************");
    int HASH_SIZE = ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES + AUTH_SIZE +CRYPTO_BYTES;
    uint8_t hash_array[HASH_SIZE];
    int i;

    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PAKE_A0_SEND ; i++ ){
        hash_array[i + ID_BYTES*3 ] = epk[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES ; i++ ){
        hash_array[i + ID_BYTES*3  + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < AUTH_SIZE ; i++ ){
        hash_array[i + ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES] = auth_b[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
        hash_array[i + ID_BYTES*3  + PAKE_A0_SEND + CIPHERTEXT_BYTES+ AUTH_SIZE] = k[i];
    } 

    hash_h(key_b, hash_array, HASH_SIZE);

    printf("\nsuccess...");
    printf("\nSession Key B:");
    printData(key_b,SHA3_256_HashSize);
    printf("***************************************\n\n\n");
}

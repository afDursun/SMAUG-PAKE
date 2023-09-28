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


int pake_a0(uint8_t *pw, uint8_t *ssid, uint8_t *send_a0, uint8_t *pk, uint8_t *sk) {
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

    printf("\n_____PAKE-A0_____");
    printf("\nA0 ---> B0:   ");
    printf("A(%d), Epk(%d)\n\n",ID_BYTES,PAKE_A0_SEND);

    return 1;
}

int pake_b0(uint8_t *send_a0, uint8_t *pw, uint8_t *a_id,  uint8_t *b_id, uint8_t *ssid, uint8_t *send_b0,uint8_t *ct,uint8_t *k,uint8_t *auth_b){
    
    uint8_t key[16] = "my_128_bit_key";
    int i;
    uint8_t pk[PUBLICKEY_BYTES] = {0};

    decryptData(key, send_a0, PAKE_A0_SEND);


    for(i = 0 ; i < PUBLICKEY_BYTES ; i++){
        pk[i] = send_a0[ID_BYTES + PW_BYTES + i];
    }
    
    crypto_kem_encap(ct, k, pk);

    encryptData(key, send_a0, PAKE_A0_SEND);
   

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
    	auth_b[i + ID_BYTES*3 + PW_BYTES] = send_a0[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES ; i++ ){
    	auth_b[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
    	auth_b[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND + CIPHERTEXT_BYTES] = k[i];
    } 

    hash_h(send_b0, auth_b, AUTH_SIZE);

    printf("\n_____PAKE-B0_____");
    printf("\nA1 <--- B0:   ");
    printf("B(%d), c(%d), Auth(%d)\n\n",ID_BYTES,CIPHERTEXT_BYTES,AUTH_SIZE);
 

}


int pake_a1(uint8_t *pk, uint8_t *sk, uint8_t *send_a0, uint8_t *ssid, uint8_t *pw, uint8_t *a_id, uint8_t *b_id, uint8_t *ct, uint8_t *send_b0, uint8_t *key_a){
    uint8_t k_prime[CRYPTO_BYTES];
    int i;
    int HASH_SIZE = ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES + AUTH_SIZE +CRYPTO_BYTES;
    uint8_t auth[AUTH_SIZE];
    uint8_t control_auth[SHA3_256_HashSize];
    uint8_t hash_array[HASH_SIZE];

    crypto_kem_decap(k_prime, sk, pk, ct);




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
    	auth[i + ID_BYTES*3 + PW_BYTES] = send_a0[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES ; i++ ){
    	auth[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
    	auth[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND + CIPHERTEXT_BYTES] = k_prime[i];
    } 


    hash_h(control_auth, auth, AUTH_SIZE);

    
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
    	hash_array[i + ID_BYTES*3 ] = send_a0[i];
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

    printf("\n\n\n_____PAKE-A1_____");
    printf("\nsuccess...");
    printf("\nSession Key A:");
    printData(key_a,SHA3_256_HashSize);

  
    
}


int pake_b1(uint8_t *ssid, uint8_t *a_id, uint8_t *b_id, uint8_t *send_a0, uint8_t *ct, uint8_t *auth_b, uint8_t *k, uint8_t *key_b){
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
    	hash_array[i + ID_BYTES*3 ] = send_a0[i];
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

    printf("\n\n\n_____PAKE-B1_____");
    printf("\nsuccess...");
    printf("\nSession Key B:");
    printData(key_b,SHA3_256_HashSize);
    printf("\n\n\n");
}

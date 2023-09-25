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
#include <stdio.h>
#include <openssl/aes.h>


int pake_a0(uint8_t *pw, uint8_t *cid, uint8_t *sid, uint8_t *send_a0, uint8_t *state_1, uint8_t *pk, uint8_t *sk) {
    int i;
    
    AES_KEY key;
    const char *keyData = "my_128_bit_key";
    unsigned char encryptedText[AES_BLOCK_SIZE];
    
    crypto_kem_keypair(pk, sk);
    
    printf("\n ******************PAKE A0****************** \n");
    printf("\n pk: ");
    for (int i = 0; i < 100; i++){
    	printf("%02X", pk[i]);
    }
    printf("\n");
    printf("\n sk: ");
    for (int i = 0; i < 200; i++){
    	printf("%02X", sk[i]);
    }
    printf("\n");
    
    uint8_t conc[ID_BYTES + PW_BYTES + PUBLICKEY_BYTES];
    
    for(i = 0; i < ID_BYTES ; i++ ){
    	conc[i] = sid[i];
    } 
    
    for(i = 0; i < PW_BYTES ; i++ ){
    	conc[i + ID_BYTES] = pw[i];
    } 
    
    for(i = 0; i < PUBLICKEY_BYTES ; i++ ){
    	conc[i + ID_BYTES + PW_BYTES] = pk[i];
    } 
    
    printf("\n");
    printf("\n Epk: ");
    for (int i = 0; i < 150; i++) {
        printf("%02x", conc[i]);
    }
    printf("\n");
    
    
    AES_set_encrypt_key((const unsigned char *)keyData, 128, &key);
    AES_encrypt(conc, send_a0, &key);
    
    
    
    printf("\n");
    printf("\n Epk-Encrepted-A0: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", send_a0[i]);
    }
    printf("\n");
    printf("\n");
    printf("\n");
    printf("\n");
    return 1;
}

int pake_b0(uint8_t *send_a0, uint8_t *sid, uint8_t *send_b0, uint8_t *state_2, uint8_t *ct, uint8_t *key_a){
    printf("\n ******************PAKE B0****************** \n");
    
    AES_KEY key;
    const char *keyData = "my_128_bit_key";
    uint8_t conc[ID_BYTES + PW_BYTES*2 + PUBLICKEY_BYTES];
    
    AES_set_decrypt_key((const unsigned char *)keyData, 128, &key);
    AES_decrypt(send_a0, conc, &key); 
    
    printf("\n");
    printf("\n Epk-Encrepted-B0: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", send_a0[i]);
    }
    printf("\n");
    
    printf("\n");
    printf("\n Epk-Decrepted: ");
    for (int i = 0; i < 150; i++) {
        printf("%02x", conc[i]);
    }
    printf("\n");
}

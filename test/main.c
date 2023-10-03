#include "ciphertext.h"
#include "indcpa.h"
#include "io.h"
#include "kem.h"
#include "aes.h"
#include "pack.h"
#include "pake.h"
#include "parameters.h"
#include "poly.h"
#include "rng.h"
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>

#define m_size 10
#define DATA_SIZE 672
#define BLOCK_SIZE 16

int main(void) {
   

    size_t i = 0; 
    unsigned char pw[32] = "12345678";
    unsigned char a_id[32] = "87654321";
    unsigned char b_id[32] = "55555555";

    const uint8_t ssid[ID_BYTES] = {0};

    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[KEM_SECRETKEY_BYTES] = {0};
    uint8_t k[CRYPTO_BYTES] = {0};
    uint8_t auth_b[AUTH_SIZE];

    uint8_t key_a[CRYPTO_BYTES] = {0};
    uint8_t key_b[CRYPTO_BYTES]= {0};
    uint8_t ct[CIPHERTEXT_BYTES] = {0};
    
    uint8_t send_a0[PAKE_A0_SEND];
    uint8_t send_b0[SHA3_256_HashSize];

    
    uint8_t entropy_input[48] = {0};
    for (i=0 ;i < 48; ++i) {
        entropy_input[i] = i;
    }
    randombytes_init(entropy_input, NULL, 256);

    //SendA0 => Epk
    //SendB0 => Auth

    pake_a0(pw, ssid, send_a0, pk, sk);
  
    pake_b0(pw, ssid, a_id, b_id, send_a0, send_b0, ct, k, auth_b);

    pake_a1(pw, pk, sk, send_a0, send_b0, ssid, a_id, b_id, ct, key_a);

    pake_b1(ssid,a_id,b_id,send_a0,ct,auth_b,k,key_b);

    return 0;
}

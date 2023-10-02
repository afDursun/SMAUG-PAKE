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

int indcpa_test();
int kem_test();



int main(void) {
   

    size_t i = 0; 
    uint8_t pw[PW_BYTES] = {0};
    uint8_t a_id[ID_BYTES] = {0}; 
    uint8_t b_id[ID_BYTES] = {0}; 
    uint8_t ssid[ID_BYTES] = {0};
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[KEM_SECRETKEY_BYTES] = {0};
    uint8_t k[CRYPTO_BYTES] = {0};
    uint8_t auth_b[AUTH_SIZE];

    uint8_t key_a[CRYPTO_BYTES] = {0};
    uint8_t key_b[CRYPTO_BYTES]= {0};
    uint8_t ct[CIPHERTEXT_BYTES] = {0};
    
    uint8_t send_a0[PAKE_A0_SEND];
    uint8_t send_b0[SHA3_256_HashSize];

    
    for(i = 0 ; i < ID_BYTES ; i++){
    	pw[i] = 3;
    	a_id[i] = 1;
        b_id[i] = 2;
    	ssid[i] = 0;
    }
    
    uint8_t entropy_input[48] = {0};
    for (i=0 ;i < 48; ++i) {
        entropy_input[i] = i;
    }
    randombytes_init(entropy_input, NULL, 256);

    //SendA0 => Epk
    //SendB0 => Auth

    pake_a0(pw, ssid, send_a0, pk, sk);
  
    pake_b0(send_a0, pw, a_id, b_id, ssid, send_b0, ct, k, auth_b);

    pake_a1(pk, sk, send_a0, send_b0, ssid, pw, a_id, b_id, ct, key_a);

    pake_b1(ssid,a_id,b_id,send_a0,ct,auth_b,k,key_b);


    return 0;
}

int indcpa_test() {
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[PKE_SECRETKEY_BYTES] = {0};
    uint8_t ctxt[CIPHERTEXT_BYTES] = {0};
    uint8_t mu[DELTA_BYTES] = {0}, mu2[DELTA_BYTES] = {0};
    uint8_t seed[DELTA_BYTES] = {0};

    indcpa_keypair(pk, sk);
    // printf("indcpa_keypair done\n");

    randombytes(mu, DELTA_BYTES);
    randombytes(seed, DELTA_BYTES);

    indcpa_enc(ctxt, pk, mu, seed);
    // printf("indcpa_enc done\n");

    indcpa_dec(mu2, sk, ctxt);
    // printf("indcpa_dec done\n");

    if (memcmp(mu, mu2, DELTA_BYTES) != 0) {
        for (int i = 0; i < m_size; ++i)
            printf("0x%2hx ", mu[i]);
        printf("\n");

        for (int i = 0; i < m_size; ++i)
            printf("0x%2hx ", mu2[i]);
        printf("\n");
        return 1;
    }

    return 0;
}

int kem_test() {
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[KEM_SECRETKEY_BYTES] = {0};

    crypto_kem_keypair(pk, sk);

    uint8_t ctxt[CIPHERTEXT_BYTES] = {0};
    uint8_t ss[CRYPTO_BYTES] = {0}, ss2[CRYPTO_BYTES] = {0};
    crypto_kem_encap(ctxt, ss, pk);
    // printf("Encap done\n");

    int res = crypto_kem_decap(ss2, sk, pk, ctxt);
    // printf("Decap done\n");

    if (memcmp(ss, ss2, CRYPTO_BYTES) != 0) {
        for (int i = 0; i < m_size; ++i) {
            printf("0x%2hx ", ss[i]);
        }
        printf("\n");

        for (int i = 0; i < m_size; ++i) {
            printf("0x%2hx ", ss2[i]);
        }
        printf("\n");
    }

    return res;
}

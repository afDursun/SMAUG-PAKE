#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


int pake_a0(
	uint8_t *pw, 
	uint8_t *ssid, 
	uint8_t *send_a0,
	uint8_t *pk, 
	uint8_t *sk);
	
	
int pake_b0(
	uint8_t *send_a0, 
	uint8_t *pw,
	uint8_t *a_id,
	uint8_t *b_id,
	uint8_t *ssid, 
	uint8_t *send_b0, 
	uint8_t *ct,
	uint8_t *k,
	uint8_t *auth_b);

int pake_a1(
	uint8_t *pk, 
	uint8_t *sk, 
	uint8_t *send_a0, 
	uint8_t *ssid,
	uint8_t *pw,
	uint8_t *a_id,
	uint8_t *b_id, 
	uint8_t *ct, 
	uint8_t *send_b0, 
	uint8_t *key_a);

int pake_b1(
	uint8_t *ssid,
	uint8_t *a_id,
	uint8_t *b_id,
	uint8_t *send_a0,
	uint8_t *ct,
	uint8_t *auth_b,
	uint8_t *k,
	uint8_t *key_b);

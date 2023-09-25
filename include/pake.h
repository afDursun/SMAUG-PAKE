#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


int pake_a0(
	uint8_t *pw, 
	uint8_t *cid, 
	uint8_t *sid, 
	uint8_t *send_a0, 
	uint8_t *state_1, 
	uint8_t *pk, 
	uint8_t *sk);
	
	
int pake_b0(
	uint8_t *send_a0, 
	uint8_t *sid, 
	uint8_t *send_b0, 
	uint8_t *state_2, 
	uint8_t *ct, 
	uint8_t *key_a);


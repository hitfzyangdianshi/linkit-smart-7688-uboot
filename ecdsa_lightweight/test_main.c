//https://github.com/jestan/easy-ecc
#if (defined(_WIN32) || defined(_WIN64))/* Windows */
#include "ecc.h" 
#else/* Windows */
#include "ecc.c" 
#endif/* Windows */

#include<stdio.h>

unsigned char  digest[] = "11111111111111111111111111111111";

int main() {
	int i,re;
	uint8_t p_publicKey[ECC_BYTES + 1], p_privateKey[ECC_BYTES]; //32

	//*******************ecc_make_key*************
	re=ecc_make_key(p_publicKey, p_privateKey);
	if (re == 0) {
		printf("error:ecc_make_key\n");
		return -1;
	}
	printf("p_publicKey:\n");
	for (i = 0; i < ECC_BYTES + 1; i++) {
		printf("%c", p_publicKey[i]);
	}
	printf("\n{");
	for (i = 0; i < ECC_BYTES + 1; i++) {
		if(i== ECC_BYTES)printf("0x%02X ", p_publicKey[i]);
		else printf("0x%02X , ", p_publicKey[i]);
	}
	printf("};\n");

	printf("p_privateKey:\n");
	for (i = 0; i < ECC_BYTES ; i++) {
		printf("%c", p_privateKey[i]);
	}
	printf("\n{");
	for (i = 0; i < ECC_BYTES ; i++) {
		if (i == ECC_BYTES-1)printf("0x%02X ", p_privateKey[i]);
		else printf("0x%02X , ", p_privateKey[i]);
	}
	printf("};\n");
	

	//*******************ecdsa_sign*************
	uint8_t p_signature[ECC_BYTES * 2];
	re=ecdsa_sign(p_privateKey, digest, p_signature);
	if (re == 0) {
		printf("error:ecdsa_sign\n");
		return -2;
	}
	printf("p_signature:\n");
	for (i = 0; i < ECC_BYTES * 2; i++) {
		printf("%c", p_signature[i]);
	}
	printf("\n{");
	for (i = 0; i < ECC_BYTES * 2; i++) {
		if (i == ECC_BYTES * 2 - 1)printf("0x%02X ", p_signature[i]);
		else printf("0x%02X , ", p_signature[i]);
	}
	printf("};\n");

	//*******************ecdsa_sign*************
	re = ecdsa_verify(p_publicKey, digest, p_signature);
	if (re == 1)printf("valid\n");
	else printf("INvalid\n");


	return 0;
}
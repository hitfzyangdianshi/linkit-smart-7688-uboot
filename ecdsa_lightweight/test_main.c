//https://github.com/jestan/easy-ecc
#if (defined(_WIN32) || defined(_WIN64))/* Windows */
#include "ecc.h" 
//typedef unsigned int uint
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



	uint8_t publickey_example1[]= { 0x03 , 0x37 , 0xFE , 0x9A , 0xE4 , 0x85 , 0xEE , 0x20 , 
		0xFE , 0xF2 , 0x1D , 0xD4 , 0x5A , 0x6F , 0x6B , 0x0C ,
		0xB7 , 0xF0 , 0x7E , 0x50 , 0x97 , 0xE2 , 0xF4 , 0xA5 ,
		0x13 , 0x9E , 0x9B , 0x45 , 0xFE , 0x9A , 0x28 , 0xF6 , 
		0x51 };
	uint8_t privatekey_example1[]={0xF1, 0x2B, 0x87, 0x38, 0x9F, 0x88, 0xB4, 0xF7,
		0xF2, 0x11, 0xDB, 0xE9, 0xFA, 0x77, 0x8C, 0xD8, 
		0xC2, 0x92, 0x46, 0xAC, 0x63, 0x42, 0x10, 0x82, 
		0x5A, 0x74, 0x97, 0x69, 0xA2, 0x3C, 0xD1, 0xC0 };
	uint8_t signature_example[]= { 0x81 , 0xB3 , 0xE0 , 0x20 , 0x5B , 0xD5 , 0x3A , 0xCA , 
		0x38 , 0x3C , 0xB3 , 0x08 , 0x49 , 0xDF , 0x7B , 0xE4 , 
		0xA9 , 0xF1 , 0xD9 , 0xE4 , 0xF5 , 0x4E , 0xE6 , 0x3F , 
		0x22 , 0x55 , 0x7C , 0x8D , 0x8D , 0x31 , 0x84 , 0xBC , 
		0x50 , 0xF7 , 0x0A , 0xE7 , 0x84 , 0x96 , 0x9A , 0xCE , 
		0x6F , 0x93 , 0x2C , 0x58 , 0xFF , 0xE6 , 0xCA , 0x9F , 
		0xC3 , 0x99 , 0x34 , 0xAA , 0x90 , 0x9E , 0x03 , 0xEF , 
		0x6A , 0x1A , 0xA8 , 0x9F , 0xEB , 0x35 , 0x3C , 0x50 };
	

	re = ecdsa_verify(publickey_example1, digest, signature_example);
	if (re == 1)printf("eg1 valid\n");
	else printf("eg1 INvalid\n");

	return 0;
}
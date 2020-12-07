//https://github.com/jestan/easy-ecc
//#if (defined(_WIN32) || defined(_WIN64))/* Windows */
//#include "ecc.h" 
//#ifndef NUM_ECC_DIGITS
//#define NUM_ECC_DIGITS (ECC_BYTES/8)
//#endif // !NUM_ECC_DIGITS
//typedef struct EccPoint
//{
//	uint64_t x[NUM_ECC_DIGITS];
//	uint64_t y[NUM_ECC_DIGITS];
//} EccPoint;
////typedef unsigned int uint
//#else/* Windows */
//#include "ecc.c" 
//#endif/* Windows */

#include "ecc.c" 

#if (defined(_WIN32) || defined(_WIN64))/* Windows */
#include<stdio.h>
unsigned char  digest[] = "11111111111111111111111111111111";
unsigned char current_hash_test[] = "e7eb4cd2a61df11fa56bdcb2e8744f668810311676d3d50b205f5ee78b1fdf6f";
#endif/* Windows */

//#define ECC_CURVE secp384r1 
//default: secp256r1

#if (defined(_WIN32) || defined(_WIN64))/* Windows */
int test1() {
	int i, re;
	uint8_t p_publicKey[ECC_BYTES + 1], p_privateKey[ECC_BYTES]; //32

	//*******************ecc_make_key*************
	re = ecc_make_key(p_publicKey, p_privateKey);
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
		if (i == ECC_BYTES)printf("0x%02X ", p_publicKey[i]);
		else printf("0x%02X , ", p_publicKey[i]);
	}
	printf("};\n");

	printf("p_privateKey:\n");
	for (i = 0; i < ECC_BYTES; i++) {
		printf("%c", p_privateKey[i]);
	}
	printf("\n{");
	for (i = 0; i < ECC_BYTES; i++) {
		if (i == ECC_BYTES - 1)printf("0x%02X ", p_privateKey[i]);
		else printf("0x%02X , ", p_privateKey[i]);
	}
	printf("};\n");


	//*******************ecdsa_sign*************
	uint8_t p_signature[ECC_BYTES * 2];
	re = ecdsa_sign(p_privateKey, digest, p_signature);
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

	//*******************ecdsa_verify*************
	re = ecdsa_verify(p_publicKey, digest, p_signature);
	if (re == 1)printf("valid\n");
	else printf("INvalid\n");


	return 0;
}

int test2() {
	int i, re;
	//uint8_t p_publicKey[ECC_BYTES + 1], p_privateKey[ECC_BYTES]; //32

	uint8_t p_publicKey[] = { 0x03 , 0x37 , 0xFE , 0x9A , 0xE4 , 0x85 , 0xEE , 0x20 ,
		0xFE , 0xF2 , 0x1D , 0xD4 , 0x5A , 0x6F , 0x6B , 0x0C ,
		0xB7 , 0xF0 , 0x7E , 0x50 , 0x97 , 0xE2 , 0xF4 , 0xA5 ,
		0x13 , 0x9E , 0x9B , 0x45 , 0xFE , 0x9A , 0x28 , 0xF6 ,
		0x51 };
	uint8_t p_privateKey[] = { 0xF1, 0x2B, 0x87, 0x38, 0x9F, 0x88, 0xB4, 0xF7,
		0xF2, 0x11, 0xDB, 0xE9, 0xFA, 0x77, 0x8C, 0xD8,
		0xC2, 0x92, 0x46, 0xAC, 0x63, 0x42, 0x10, 0x82,
		0x5A, 0x74, 0x97, 0x69, 0xA2, 0x3C, 0xD1, 0xC0 };

	//*******************ecdsa_sign*************
	uint8_t p_signature[ECC_BYTES * 2];
	re = ecdsa_sign(p_privateKey, current_hash_test, p_signature);
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

	//*******************ecdsa_verify*************
	re = ecdsa_verify(p_publicKey, current_hash_test, p_signature);
	if (re == 1)printf("valid\n");
	else printf("INvalid\n");



	uint8_t publickey_example1[] = { 0x03 , 0x37 , 0xFE , 0x9A , 0xE4 , 0x85 , 0xEE , 0x20 ,
		0xFE , 0xF2 , 0x1D , 0xD4 , 0x5A , 0x6F , 0x6B , 0x0C ,
		0xB7 , 0xF0 , 0x7E , 0x50 , 0x97 , 0xE2 , 0xF4 , 0xA5 ,
		0x13 , 0x9E , 0x9B , 0x45 , 0xFE , 0x9A , 0x28 , 0xF6 ,
		0x51 };
	uint8_t privatekey_example1[] = { 0xF1, 0x2B, 0x87, 0x38, 0x9F, 0x88, 0xB4, 0xF7,
		0xF2, 0x11, 0xDB, 0xE9, 0xFA, 0x77, 0x8C, 0xD8,
		0xC2, 0x92, 0x46, 0xAC, 0x63, 0x42, 0x10, 0x82,
		0x5A, 0x74, 0x97, 0x69, 0xA2, 0x3C, 0xD1, 0xC0 };
	/*uint8_t signature_example1[]= { 0x81 , 0xB3 , 0xE0 , 0x20 , 0x5B , 0xD5 , 0x3A , 0xCA ,
		0x38 , 0x3C , 0xB3 , 0x08 , 0x49 , 0xDF , 0x7B , 0xE4 ,
		0xA9 , 0xF1 , 0xD9 , 0xE4 , 0xF5 , 0x4E , 0xE6 , 0x3F ,
		0x22 , 0x55 , 0x7C , 0x8D , 0x8D , 0x31 , 0x84 , 0xBC ,
		0x50 , 0xF7 , 0x0A , 0xE7 , 0x84 , 0x96 , 0x9A , 0xCE ,
		0x6F , 0x93 , 0x2C , 0x58 , 0xFF , 0xE6 , 0xCA , 0x9F ,
		0xC3 , 0x99 , 0x34 , 0xAA , 0x90 , 0x9E , 0x03 , 0xEF ,
		0x6A , 0x1A , 0xA8 , 0x9F , 0xEB , 0x35 , 0x3C , 0x50 };*/

	uint8_t signature_example2[] = { 0x84, 0x5A, 0x12, 0xC2, 0x9C, 0x08, 0x75, 0x0E, 0xFB, 0x16, 0xE4, 0xDF, 0x6E, 0x93, 0x6D, 0xB8, 0xAC, 0x12, 0x19, 0x96, 0xDA, 0x5C, 0x05, 0xC4, 0x93, 0xD1, 0x3E, 0xCB, 0xC3, 0x3F, 0x55, 0x67, 0x32, 0xBC, 0xC2, 0xDD, 0xAC, 0xF3, 0x4F, 0xF4, 0x80, 0x33, 0xB4, 0x7E, 0xEB, 0x3F, 0x2F, 0x3F, 0x33, 0x14, 0x7C, 0xD0, 0x35, 0x88, 0x6D, 0x31, 0xA1, 0x7E, 0x03, 0x2B, 0xD4, 0x99, 0xA4, 0x7E };


	re = ecdsa_verify(publickey_example1, current_hash_test, signature_example2);
	if (re == 1)printf("eg1 valid\n");
	else printf("eg1 INvalid\n");

	return 0;
}
#endif/* Windows */

int printkeys(uint8_t p_publicKey[ECC_BYTES + 1], uint8_t p_privateKey[ECC_BYTES]) {
	int i;
	printf("p_publicKey:\n");
	for (i = 0; i < ECC_BYTES + 1; i++) {
		printf("%c", p_publicKey[i]);
	}
	printf("\n{");
	for (i = 0; i < ECC_BYTES + 1; i++) {
		if (i == ECC_BYTES)printf("0x%02X ", p_publicKey[i]);
		else printf("0x%02X , ", p_publicKey[i]);
	}
	printf("};\n");

	printf("p_privateKey:\n");
	for (i = 0; i < ECC_BYTES; i++) {
		printf("%c", p_privateKey[i]);
	}
	printf("\n{");
	for (i = 0; i < ECC_BYTES; i++) {
		if (i == ECC_BYTES - 1)printf("0x%02X ", p_privateKey[i]);
		else printf("0x%02X , ", p_privateKey[i]);
	}
	printf("};\n");

	return 0;
}

int getpublickey(uint8_t p_publicKey[ECC_BYTES + 1], uint8_t p_privateKey[ECC_BYTES]) {
	uint64_t l_private1[NUM_ECC_DIGITS];
	EccPoint l_public1;
	ecc_bytes2native(l_private1, p_privateKey);
	//uint8_t p_publicKey[ECC_BYTES + 1];

	do
	{
		if (vli_isZero(l_private1))
		{
			continue;
		}

		/* Make sure the private key is in the range [1, n-1].
		   For the supported curves, n is always large enough that we only need to subtract once at most. */
		if (vli_cmp(curve_n, l_private1) != 1)
		{
			vli_sub(l_private1, l_private1, curve_n);
		}

		EccPoint_mult(&l_public1, &curve_G, l_private1, NULL);
	} while (EccPoint_isZero(&l_public1));

	ecc_native2bytes(p_publicKey + 1, l_public1.x);
	p_publicKey[0] = 2 + (l_public1.y[0] & 0x01);

	printkeys(p_publicKey, p_privateKey);
	return 0;
}


int sign_and_print(uint8_t p_privateKey[ECC_BYTES], unsigned char *digest) {
	//*******************ecdsa_sign*************
	int re, i;
	uint8_t p_signature1[ECC_BYTES * 2];
	re = ecdsa_sign(p_privateKey, digest, p_signature1);
	if (re == 0) {
		printf("error:ecdsa_sign\n");
		return -2;
	}
	printf("p_signature:\n");
	for (i = 0; i < ECC_BYTES * 2; i++) {
		printf("%c", p_signature1[i]);
	}
	printf("\n{");
	for (i = 0; i < ECC_BYTES * 2; i++) {
		if (i == ECC_BYTES * 2 - 1)printf("0x%02X ", p_signature1[i]);
		else printf("0x%02X , ", p_signature1[i]);
	}
	printf("};\n");


	return 0;
}

int signature_verify_by_pubkey_33(uint8_t p_publicKey[ECC_BYTES + 1], unsigned char* digest, uint8_t p_signature1[ECC_BYTES * 2]) {

	//*******************ecdsa_verify*************

	int re;
	re = ecdsa_verify(p_publicKey, digest, p_signature1);
	if (re == 1) {
		printf("valid\n");
		return 1;
	}
	else {
		printf("INvalid\n");
		return -1;
	}

	return 0;
}


#if (defined(_WIN32) || defined(_WIN64))/* Windows */
int test3() { 


	uint8_t privatekey_example1[] = { 0x27,0xeb,0xcf,0x70,0xac,0xae,0xcb,0x1c,
									  0x4b,0xd8,0x74,0xe2,0x9e,0x13,0xb7,0xb2,
		0x58,0xb9,0x49,0x8c,0xbd,0xbd,0x1a,0xfd,
		0xb2,0xc0,0x13,0xdf,0x65,0x8f,0xcc,0xb9 };
	uint8_t publickey_example1[ECC_BYTES + 1];
	getpublickey(publickey_example1, privatekey_example1);
	

	uint8_t publickey_example1result[]={0x02, 0x68, 0xC0, 0xC8, 0x1D, 0x72, 0x85, 0x67,
		0x22, 0xE0, 0x37, 0x38, 0xA7, 0xB4, 0x6C, 0x11, 
		0x62, 0x85, 0xC1, 0xA3, 0xA8, 0x50, 0xEE, 0xFC, 
		0x84, 0xA6, 0xE7, 0x47, 0x78, 0x1F, 0x22, 0x1D, 
		0x0A };

	printf("\n\n\n\n");

	//*******************ecdsa_sign*************
	int re,i;
	uint8_t p_signature1[ECC_BYTES * 2];
	re = ecdsa_sign(privatekey_example1, current_hash_test, p_signature1);
	if (re == 0) {
		printf("error:ecdsa_sign\n");
		return -2;
	}
	printf("p_signature:\n");
	for (i = 0; i < ECC_BYTES * 2; i++) {
		printf("%c", p_signature1[i]);
	}
	printf("\n{");
	for (i = 0; i < ECC_BYTES * 2; i++) {
		if (i == ECC_BYTES * 2 - 1)printf("0x%02X ", p_signature1[i]);
		else printf("0x%02X , ", p_signature1[i]);
	}
	printf("};\n");

	//*******************ecdsa_verify*************
	re = ecdsa_verify(publickey_example1, current_hash_test, p_signature1);
	if (re == 1)printf("valid\n");
	else printf("INvalid\n");




	return 0;
}
#endif/* Windows */

#if (defined(_WIN32) || defined(_WIN64))/* Windows */
int main() {
	
	uint8_t privatekey_example1[] = { 0x27,0xeb,0xcf,0x70,0xac,0xae,0xcb,0x1c,
									  0x4b,0xd8,0x74,0xe2,0x9e,0x13,0xb7,0xb2,
		0x58,0xb9,0x49,0x8c,0xbd,0xbd,0x1a,0xfd,
		0xb2,0xc0,0x13,0xdf,0x65,0x8f,0xcc,0xb9 };

	uint8_t publickey_example1[] = { 0x02, 0x68, 0xC0, 0xC8, 0x1D, 0x72, 0x85, 0x67,
		0x22, 0xE0, 0x37, 0x38, 0xA7, 0xB4, 0x6C, 0x11,
		0x62, 0x85, 0xC1, 0xA3, 0xA8, 0x50, 0xEE, 0xFC,
		0x84, 0xA6, 0xE7, 0x47, 0x78, 0x1F, 0x22, 0x1D,
		0x0A };
	uint8_t signature_eg1[]={0x04, 0xD9, 0x04, 0x6B, 0xC1, 0x9D, 0xAF, 0xA2, 
		0xEC, 0xF0, 0xA8, 0x14, 0x0B, 0x57, 0xAF, 0xDC, 
		0x90, 0xA5, 0x0B, 0xBB, 0x3B, 0x77, 0xC1, 0xDC, 
		0xC6, 0x44, 0xB2, 0x47, 0xAC, 0x93, 0xCE, 0xB6, 
		0x75, 0x34, 0x37, 0x0E, 0x27, 0x8A, 0xA0, 0xC0, 
		0x45, 0xE9, 0xEE, 0xB0, 0xED, 0xD7, 0x3C, 0x64, 
		0x5B, 0xEF, 0x57, 0x18, 0x95, 0x77, 0x2B, 0x55, 
		0x58, 0x71, 0x5E, 0xF9, 0x10, 0xBE, 0x5F, 0x3D };
	//sign_and_print(privatekey_example1, current_hash_test);
	signature_verify_by_pubkey_33(publickey_example1, current_hash_test, signature_eg1);


	uint8_t privatekey_eg2[] = { 0xf5,0x63,0xd4,0xb6,0xad,0x80,0x0e,0x85,
		0xec,0xd5,0xef,0x8d,0xe7,0x37,0xf4,0x87,
		0xe4,0xf4,0x2b,0x42,0x30,0x14,0xa1,0x39,
		0x15,0xe9,0x7f,0x97,0xe1,0xdf,0xe9,0xb3	};
	uint8_t publickey_eg2[ ]= { 0x03 , 0x03 , 0xEC , 0xBE , 0x5A , 0x0E , 0x9A , 0xF7 , // ECC_BYTES + 1
		0xAD , 0xDC , 0x15 , 0x34 , 0x9B , 0x96 , 0x3B , 0x29 , 
		0xC7 , 0x24 , 0x36 , 0x5E , 0x24 , 0xDE , 0x2E , 0xE9 , 
		0x92 , 0x7C , 0x11 , 0xE9 , 0x2D , 0xF5 , 0xA4 , 0xE1 , 0x80 };
	//getpublickey(publickey_eg2, privatekey_eg2);
	//sign_and_print(privatekey_eg2, current_hash_test);
	uint8_t signature_eg2[] = {0x57, 0x7E, 0x82, 0x87, 0x72, 0xB8, 0xC4, 0xD7, 0x70, 0xC9, 0xEA, 0xD2, 0x13, 0x66, 0x94, 0x95, 0x63, 0x22, 0xD2, 0x2A, 0x01, 0x59, 0x9C, 0x00, 0x4F, 0x7C, 0xAB, 0xBB, 0x68, 0xB7, 0x84, 0x59, 0x01, 0x76, 0x5F, 0x66, 0xFF, 0xA1, 0xF1, 0xEC, 0xFC, 0x35, 0x00, 0x18, 0x42, 0x9A, 0x46, 0xC9, 0x30, 0x7B, 0x31, 0x41, 0xAE, 0x9B, 0xFE, 0xC8, 0xC6, 0x9C, 0x20, 0x9F, 0x8F, 0x5A, 0x36, 0xDC };
	signature_verify_by_pubkey_33(publickey_eg2, current_hash_test, signature_eg2);

	uint8_t privatekey_eg3[] = { 0xc3,0xe0,0x3d,0x91,0xe8,0x12,0x7d,0xdd,
		0x93,0x86,0xd7,0x37,0xde,0xcc,0x18,0x24,
		0xb7,0xb1,0xe9,0x42,0x66,0x91,0xeb,0x9f,
		0x7d,0xb5,0x80,0x3c,0xf5,0x8f,0x09,0xc7 };
	uint8_t publickey_eg3[ ]= {0x03, 0x25, 0xA7, 0x91, 0xC4, 0x0B, 0x2B, 0xBB, 
		0x90, 0xC6, 0x9B, 0xA4, 0x09, 0x21, 0x44, 0x77, 
		0x4D, 0x54, 0x88, 0xB7, 0x01, 0x39, 0x19, 0x8D, 
		0x4F, 0x7A, 0x49, 0x6A, 0xDF, 0xFE, 0xD2, 0xF1, 0x13 }; //ECC_BYTES + 1
	//getpublickey(publickey_eg3, privatekey_eg3);
	//sign_and_print(privatekey_eg3, current_hash_test);
	uint8_t signature_eg3[] = {0x6E, 0xFD, 0x7A, 0x4D, 0x4C, 0x0F, 0x8D, 0x46, 0x6E, 0xB8, 0x37, 0x6D, 0x83, 0x84, 0xD3, 0xC9, 0x98, 0x4E, 0xF9, 0x0F, 0x20, 0x95, 0x60, 0xA9, 0x59, 0x58, 0xC8, 0xC0, 0x31, 0x14, 0x29, 0x3A, 0x0D, 0xB1, 0x82, 0x9F, 0xD8, 0xB8, 0x5B, 0xF7, 0xD6, 0xCA, 0x06, 0xFF, 0x73, 0xFB, 0x74, 0x4B, 0xC9, 0x24, 0xF8, 0x40, 0xA3, 0xA4, 0x91, 0x89, 0xD0, 0x8C, 0x55, 0x20, 0xE3, 0xD5, 0x08, 0x80 };
	signature_verify_by_pubkey_33(publickey_eg3, current_hash_test, signature_eg3);


	uint8_t privatekey_eg4[] = {0xcc,0x62,0x7f,0xd3,0x99,0xae,0xcc,0x8b,
		0x48,0x9d,0x29,0xf8,0x77,0xa4,0x05,0xea,
		0xd0,0xa7,0x8c,0x51,0xae,0x47,0xc6,0xb9,
		0x49,0xa6,0x8f,0xa7,0xa8,0xa2,0x27,0x11 };
	uint8_t publickey_eg4[ ]= { 0x03 , 0x75 , 0x60 , 0x99 , 0x3B , 0x5F , 0x74 , 0xCF , 
		0x10 , 0xD7 , 0x7F , 0x9F , 0x96 , 0x9E , 0x37 , 0x5E , 
		0x21 , 0x73 , 0x43 , 0x15 , 0xAA , 0x11 , 0xEE , 0x13 , 
		0x12 , 0x21 , 0x13 , 0x7B , 0x8C , 0x83 , 0x76 , 0xEA , 0x7F };// ECC_BYTES + 1
	//getpublickey(publickey_eg4, privatekey_eg4);
	//sign_and_print(privatekey_eg4, current_hash_test);
	uint8_t signature_eg4[]={0x20, 0xAE, 0x6F, 0x84, 0xDD, 0x85, 0xFF, 0x0A, 0x21, 0x1C, 0x25, 0x18, 0x71, 0x03, 0xF2, 0x97, 0xEE, 0x6B, 0xD1, 0x89, 0x0B, 0xB1, 0x71, 0x76, 0x1A, 0xBB, 0x43, 0x20, 0x96, 0x3B, 0xBE, 0x1A, 0xED, 0x6F, 0xEF, 0xF0, 0x60, 0x05, 0x67, 0xFF, 0xC0, 0xBD, 0xF6, 0x50, 0xDC, 0x1B, 0xFC, 0x22, 0xAD, 0x40, 0x95, 0xB8, 0x4B, 0x18, 0x9F, 0x34, 0xE8, 0xB7, 0x40, 0x86, 0x34, 0xCF, 0xC5, 0x34 };
	signature_verify_by_pubkey_33(publickey_eg4, current_hash_test, signature_eg4);
	
	
	return 0;
}
#endif/* Windows */


//{
//PrivKey: "MHcCAQEEICfrz3CsrsscS9h04p4Tt7JYuUmMvb0a/bLAE99lj8y5oAoGCCqGSM49AwEHoUQDQgAEaMDIHXKFZyLgNzintGwRYoXBo6hQ7vyEpudHeB8iHQr9n1fffwkJP3nIBm5TD9XEUjk72rAZEbylkSJOekTW0A==",
//PubKey : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaMDIHXKFZyLgNzintGwRYoXBo6hQ7vyEpudHeB8iHQr9n1fffwkJP3nIBm5TD9XEUjk72rAZEbylkSJOekTW0A==",
//},
//SEQUENCE
//INTEGER 01..(total 1bytes)..01
//OCTETSTRING 27ebcf70acaecb1c4bd874e29e13b7b258b9498cbdbd1afdb2c013df658fccb9..(total 32bytes)..27ebcf70acaecb1c4bd874e29e13b7b258b9498cbdbd1afdb2c013df658fccb9
//[0]
//ObjectIdentifier secp256r1(1 2 840 10045 3 1 7)
//[1]
//BITSTRING 000468c0c81d72856722e03738a7b46c116285c1a3a850eefc84a6e747781f221d0afd9f57df7f09093f79c8066e530fd5c452393bdab01911bca591224e7a44d6d0..(total 66bytes)..000468c0c81d72856722e03738a7b46c116285c1a3a850eefc84a6e747781f221d0afd9f57df7f09093f79c8066e530fd5c452393bdab01911bca591224e7a44d6d0


//	{
//		PrivKey: "MHcCAQEEIPVj1LatgA6F7NXvjec39Ifk9CtCMBShORXpf5fh3+mzoAoGCCqGSM49AwEHoUQDQgAEA+y+Wg6a963cFTSbljspxyQ2XiTeLumSfBHpLfWk4YB0OoQP/0e406cvXlvB0kHwejQrOQ4+cjAzpTwbZATbew==",
//		PubKey : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEA+y+Wg6a963cFTSbljspxyQ2XiTeLumSfBHpLfWk4YB0OoQP/0e406cvXlvB0kHwejQrOQ4+cjAzpTwbZATbew==",
//	},
//SEQUENCE
//INTEGER 01..(total 1bytes)..01
//OCTETSTRING f563d4b6ad800e85ecd5ef8de737f487e4f42b423014a13915e97f97e1dfe9b3..(total 32bytes)..f563d4b6ad800e85ecd5ef8de737f487e4f42b423014a13915e97f97e1dfe9b3
//[0]
//ObjectIdentifier secp256r1(1 2 840 10045 3 1 7)
//[1]
//BITSTRING 000403ecbe5a0e9af7addc15349b963b29c724365e24de2ee9927c11e92df5a4e180743a840fff47b8d3a72f5e5bc1d241f07a342b390e3e723033a53c1b6404db7b..(total 66bytes)..000403ecbe5a0e9af7addc15349b963b29c724365e24de2ee9927c11e92df5a4e180743a840fff47b8d3a72f5e5bc1d241f07a342b390e3e723033a53c1b6404db7b


//	{
//		PrivKey: "MHcCAQEEIMPgPZHoEn3dk4bXN97MGCS3selCZpHrn321gDz1jwnHoAoGCCqGSM49AwEHoUQDQgAEJaeRxAsru5DGm6QJIUR3TVSItwE5GY1Peklq3/7S8RO3JK7pCvbDfv4UpB/fjpN5g9Q5Xq4LreLf6RuGBxfxpw==",
//		PubKey : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJaeRxAsru5DGm6QJIUR3TVSItwE5GY1Peklq3/7S8RO3JK7pCvbDfv4UpB/fjpN5g9Q5Xq4LreLf6RuGBxfxpw==",
//	},
//SEQUENCE
//INTEGER 01..(total 1bytes)..01
//OCTETSTRING c3e03d91e8127ddd9386d737decc1824b7b1e9426691eb9f7db5803cf58f09c7..(total 32bytes)..c3e03d91e8127ddd9386d737decc1824b7b1e9426691eb9f7db5803cf58f09c7
//[0]
//ObjectIdentifier secp256r1(1 2 840 10045 3 1 7)
//[1]
//BITSTRING 000425a791c40b2bbb90c69ba4092144774d5488b70139198d4f7a496adffed2f113b724aee90af6c37efe14a41fdf8e937983d4395eae0bade2dfe91b860717f1a7..(total 66bytes)..000425a791c40b2bbb90c69ba4092144774d5488b70139198d4f7a496adffed2f113b724aee90af6c37efe14a41fdf8e937983d4395eae0bade2dfe91b860717f1a7


//	{
//		PrivKey: "MHcCAQEEIMxif9OZrsyLSJ0p+HekBerQp4xRrkfGuUmmj6eooicRoAoGCCqGSM49AwEHoUQDQgAEdWCZO190zxDXf5+WnjdeIXNDFaoR7hMSIRN7jIN26n94vtHj+czclJ4GX3qsq/9fKENl5zAMudrfwSOnjBiTtw==",
//		PubKey : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdWCZO190zxDXf5+WnjdeIXNDFaoR7hMSIRN7jIN26n94vtHj+czclJ4GX3qsq/9fKENl5zAMudrfwSOnjBiTtw==",
//	},
//SEQUENCE
//INTEGER 01..(total 1bytes)..01
//OCTETSTRING cc627fd399aecc8b489d29f877a405ead0a78c51ae47c6b949a68fa7a8a22711..(total 32bytes)..cc627fd399aecc8b489d29f877a405ead0a78c51ae47c6b949a68fa7a8a22711
//[0]
//ObjectIdentifier secp256r1(1 2 840 10045 3 1 7)
//[1]
//BITSTRING 00047560993b5f74cf10d77f9f969e375e21734315aa11ee131221137b8c8376ea7f78bed1e3f9ccdc949e065f7aacabff5f284365e7300cb9dadfc123a78c1893b7..(total 66bytes)..00047560993b5f74cf10d77f9f969e375e21734315aa11ee131221137b8c8376ea7f78bed1e3f9ccdc949e065f7aacabff5f284365e7300cb9dadfc123a78c1893b7

//https://gchq.github.io/CyberChef/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,33)&input=TUhjQ0FRRUVJQ2ZyejNDc3Jzc2NTOWgwNHA0VHQ3Sll1VW1NdmIwYS9iTEFFOTlsajh5NW9Bb0dDQ3FHU000OUF3RUhvVVFEUWdBRWFNRElIWEtGWnlMZ056aW50R3dSWW9YQm82aFE3dnlFcHVkSGVCOGlIUXI5bjFmZmZ3a0pQM25JQm01VEQ5WEVVams3MnJBWkVieWxrU0pPZWtUVzBBPT0

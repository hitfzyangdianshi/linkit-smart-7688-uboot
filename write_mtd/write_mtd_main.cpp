#include<iostream>
#include<cstdio>
#include<string>
#include "../ecdsa_lightweight/easy_ecc_main.c"
#include "../include/image.h"
using namespace std;
/*typedef struct fw_info {
	uint32_t	size_old;
	uint32_t	size_new;
	uint8_t		update;
	uint8_t		hash_old[32];
	uint8_t		hash_new[32];
} fw_info_t;*/    

//unsigned char current_hash_test[] = "e7eb4cd2a61df11fa56bdcb2e8744f668810311676d3d50b205f5ee78b1fdf6f";

/*openwrt-ramips-mt76x8-mediatek_linkit-smart-7688-squashfs-sysupgrade.bin
md5:		363d194515d5207f4dd08bcb44b820b9
SHA256:		18c625b863054a165773fe97fe11f7dbadf70122ce8b6cf4619bb1baffe24348			*/  

/*root@OpenWrt:/tmp# sha256sum /dev/mtd3
2f02bbf9b71e97dafe7b507567e582f736c4631a44e0e5343f4f0cb40237cebd /dev/mtd3			*/  

/*root@OpenWrt:/tmp# md5sum /dev/mtd3
8cf65650b4dd0dc0ed0cff4ef06e8bc2 /dev/mtd3			*/  



uint8_t privatekey_eg1[] = { 0x27,0xeb,0xcf,0x70,0xac,0xae,0xcb,0x1c,
								  0x4b,0xd8,0x74,0xe2,0x9e,0x13,0xb7,0xb2,
	0x58,0xb9,0x49,0x8c,0xbd,0xbd,0x1a,0xfd,
	0xb2,0xc0,0x13,0xdf,0x65,0x8f,0xcc,0xb9 };
uint8_t publickey_eg1[] = { 0x02, 0x68, 0xC0, 0xC8, 0x1D, 0x72, 0x85, 0x67,
	0x22, 0xE0, 0x37, 0x38, 0xA7, 0xB4, 0x6C, 0x11,
	0x62, 0x85, 0xC1, 0xA3, 0xA8, 0x50, 0xEE, 0xFC,
	0x84, 0xA6, 0xE7, 0x47, 0x78, 0x1F, 0x22, 0x1D,
	0x0A };
uint8_t signature_old_eg1[] = {0x68, 0xA9, 0xD2, 0x15, 0xD7, 0x79, 0x62, 0x52, 
0x3B, 0xC1, 0x8A, 0xB8, 0x6C, 0x0D, 0x8E, 0x4E, 
0xF5, 0xAB, 0x94, 0xC5, 0xD6, 0x3E, 0xBC, 0x44, 
0x94, 0xEA, 0x91, 0x81, 0xFB, 0x06, 0xAC, 0x8C, 
0x7E, 0x74, 0x7C, 0xFB, 0x75, 0xF1, 0x4C, 0xAE, 
0xB8, 0x47, 0xF5, 0xC5, 0x56, 0x11, 0xA6, 0x4E, 
0x48, 0xCD, 0xE5, 0xD3, 0xE1, 0xD3, 0xF5, 0xFF, 
0x49, 0xC9, 0xBA, 0x1B, 0xB6, 0xEC, 0x87, 0x5F };
uint8_t signature_new_eg1[] = { 0x68, 0xA9, 0xD2, 0x15, 0xD7, 0x79, 0x62, 0x52,
0x3B, 0xC1, 0x8A, 0xB8, 0x6C, 0x0D, 0x8E, 0x4E,
0xF5, 0xAB, 0x94, 0xC5, 0xD6, 0x3E, 0xBC, 0x44,
0x94, 0xEA, 0x91, 0x81, 0xFB, 0x06, 0xAC, 0x8C,
0x7E, 0x74, 0x7C, 0xFB, 0x75, 0xF1, 0x4C, 0xAE,
0xB8, 0x47, 0xF5, 0xC5, 0x56, 0x11, 0xA6, 0x4E,
0x48, 0xCD, 0xE5, 0xD3, 0xE1, 0xD3, 0xF5, 0xFF,
0x49, 0xC9, 0xBA, 0x1B, 0xB6, 0xEC, 0x87, 0x5F };
//sign_and_print(privatekey_example1, current_hash_test);
//signature_verify_by_pubkey_33(publickey_example1, current_hash_test, signature_eg1);

int copy_string_to_unsigned_char(string s, uint8_t ch[]) {
	int i;
	for (i = 0; i < s.length(); i++) {
		ch[i] = s.c_str()[i];
	}
	return 0;
}

int copy_char_to_unsigned_char(char s[], uint8_t ch[]) {
	int i;
	for (i = 0; i < strlen(s); i++) {
		ch[i] = s[i];
	}
	return 0;
}

int main(){
	//string hash_test = "8cf65650b4dd0dc0ed0cff4ef06e8bc2";//32
	char hash_old[]= "8cf65650b4dd0dc0ed0cff4ef06e8bc2";//32
	char hash_new[]= "8cf65650b4dd0dc0ed0cff4ef06e8bc2";
	fw_info_t fw_info_test = { 12345,54321,0x03 };
	/*copy_string_to_unsigned_char(hash_test, fw_info_test.hash_old);
	copy_string_to_unsigned_char(hash_test, fw_info_test.hash_new);*/	/*uint8_t signature_eg1[] = { 0x04, 0xD9, 0x04, 0x6B, 0xC1, 0x9D, 0xAF, 0xA2, 0xEC, 0xF0, 0xA8, 0x14, 0x0B, 0x57, 0xAF, 0xDC, 0x90, 0xA5, 0x0B, 0xBB, 0x3B, 0x77, 0xC1, 0xDC, 0xC6, 0x44, 0xB2, 0x47, 0xAC, 0x93, 0xCE, 0xB6, 0x75, 0x34, 0x37, 0x0E, 0x27, 0x8A, 0xA0, 0xC0, 0x45, 0xE9, 0xEE, 0xB0, 0xED, 0xD7, 0x3C, 0x64, 0x5B, 0xEF, 0x57, 0x18, 0x95, 0x77, 0x2B, 0x55, 0x58, 0x71, 0x5E, 0xF9, 0x10, 0xBE, 0x5F, 0x3D };*/
	copy_char_to_unsigned_char(hash_old, fw_info_test.hash_old);
	copy_char_to_unsigned_char(hash_new, fw_info_test.hash_new);

#ifdef GET_NEW_SIGNATURE
	sign_and_print(privatekey_eg1, fw_info_test.hash_new);
#endif // GET_NEW_SIGNATURE

	FILE* mtd8_pubsig = fopen("mtd8_pubsig.bin", "wb");
	int i;
	uint8_t* p = (uint8_t*)(&fw_info_test);
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		putc(p[i], mtd8_pubsig);
		printf("%02X ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\nsizeof(fw_info_t): %d\n", sizeof(fw_info_t));
	printf("there are three additional 00's here at the end of struct fw_info fw_info_t\n");

	for (i = 0; i < ECC_BYTES+1; i++) {
		fputc(publickey_eg1[i], mtd8_pubsig);
	}
	for(i=0;i< ECC_BYTES*2;i++) fputc(signature_old_eg1[i], mtd8_pubsig);
	for(i=0;i< ECC_BYTES*2;i++) fputc(signature_new_eg1[i], mtd8_pubsig);

	fclose(mtd8_pubsig);


	fw_info_t* fwi =(fw_info_t*) malloc(sizeof(fw_info_t));
	printf("fw-info size: %d\n", sizeof(fw_info_t));
	FILE* mtd8 = fopen("mtd8_pubsig.bin", "rb");
	printf("fw-info raw: \n");
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		*(p+i)=fgetc(mtd8);
	}
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		printf("%02X ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n\n");
	fwi = (fw_info_t*)p;

	uint8_t pubkey_get1[ECC_BYTES + 1];
	for (i = 0; i < ECC_BYTES + 1; i++) {
		pubkey_get1[i] = fgetc(mtd8);
	}

	uint8_t sig_old_get1[ECC_BYTES *2];
	for (i = 0; i < ECC_BYTES * 2; i++) {
		sig_old_get1[i] = fgetc(mtd8);
	}
	uint8_t sig_new_get1[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) {
		sig_new_get1[i] = fgetc(mtd8);
	}

	printf("fw-info data: ->update, ->size_old, ->size_new: %d %d %d\n", fwi->update, fwi->size_old, fwi->size_new);
	printf("sig_old:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_old, sig_old_get1);
	printf("sig_new:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_new, sig_new_get1);
	fclose(mtd8);

	return 0;
}
//mtd write mtd8_pubsig.bin fw-info
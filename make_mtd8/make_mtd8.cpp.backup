#include<iostream>
#include<cstdio>
#include<string>
#include "../ecdsa_lightweight/easy_ecc_main.c"
#include "../include/image.h"
/*#define USE_HOSTCC
#include "../include/u-boot/sha256.h"
#include "../lib_generic/sha256.c"*/
using namespace std;  
#define _CRT_SECURE_NO_WARNINGS

/*openwrt-ramips-mt76x8-mediatek_linkit-smart-7688-squashfs-sysupgrade.bin
md5:		363d194515d5207f4dd08bcb44b820b9
SHA256:		18c625b863054a165773fe97fe11f7dbadf70122ce8b6cf4619bb1baffe24348			  

root@OpenWrt:/tmp# sha256sum /dev/mtd3
2f02bbf9b71e97dafe7b507567e582f736c4631a44e0e5343f4f0cb40237cebd /dev/mtd3			  

root@OpenWrt:/tmp# md5sum /dev/mtd3
8cf65650b4dd0dc0ed0cff4ef06e8bc2 /dev/mtd3			*/  

/*openwrt-ramips-mt76x8-mediatek_linkit-smart-7688-squashfs-sysupgrade.bin
md5:		5ff30fb7cae8bd7a644a34f753ac4b87
SHA256:		0cf3de677a476dd0b3bff4a11ee80507f59655915f906122d02a076d9cf9abec 

root@OpenWrt:/tmp# sha256sum /dev/mtd3
383fa674ce40a1520f0a444da0a64c307ea21f2e1624a8ece3b5d6d34c6441b3  /dev/mtd3

root@OpenWrt:/tmp# md5sum /dev/mtd3
2909bd2c7cde11e45c6bdaa6e5ceece1  /dev/mtd3				*/

typedef		unsigned long		ulong;

uint8_t privatekey_eg1[] = { 0x27,0xeb,0xcf,0x70,0xac,0xae,0xcb,0x1c,
								  0x4b,0xd8,0x74,0xe2,0x9e,0x13,0xb7,0xb2,
	0x58,0xb9,0x49,0x8c,0xbd,0xbd,0x1a,0xfd,
	0xb2,0xc0,0x13,0xdf,0x65,0x8f,0xcc,0xb9 };
uint8_t publickey_eg1[] = { 0x02, 0x68, 0xC0, 0xC8, 0x1D, 0x72, 0x85, 0x67,
	0x22, 0xE0, 0x37, 0x38, 0xA7, 0xB4, 0x6C, 0x11,
	0x62, 0x85, 0xC1, 0xA3, 0xA8, 0x50, 0xEE, 0xFC,
	0x84, 0xA6, 0xE7, 0x47, 0x78, 0x1F, 0x22, 0x1D,
	0x0A };
uint8_t privatekey_eg2[] = { 0xf5,0x63,0xd4,0xb6,0xad,0x80,0x0e,0x85,
		0xec,0xd5,0xef,0x8d,0xe7,0x37,0xf4,0x87,
		0xe4,0xf4,0x2b,0x42,0x30,0x14,0xa1,0x39,
		0x15,0xe9,0x7f,0x97,0xe1,0xdf,0xe9,0xb3 };
uint8_t publickey_eg2[] = { 0x03 , 0x03 , 0xEC , 0xBE , 0x5A , 0x0E , 0x9A , 0xF7 , // ECC_BYTES + 1
	0xAD , 0xDC , 0x15 , 0x34 , 0x9B , 0x96 , 0x3B , 0x29 ,
	0xC7 , 0x24 , 0x36 , 0x5E , 0x24 , 0xDE , 0x2E , 0xE9 ,
	0x92 , 0x7C , 0x11 , 0xE9 , 0x2D , 0xF5 , 0xA4 , 0xE1 , 0x80 };

uint8_t privatekey_eg3[] = { 0xc3,0xe0,0x3d,0x91,0xe8,0x12,0x7d,0xdd,
	0x93,0x86,0xd7,0x37,0xde,0xcc,0x18,0x24,
	0xb7,0xb1,0xe9,0x42,0x66,0x91,0xeb,0x9f,
	0x7d,0xb5,0x80,0x3c,0xf5,0x8f,0x09,0xc7 };
uint8_t publickey_eg3[] = { 0x03, 0x25, 0xA7, 0x91, 0xC4, 0x0B, 0x2B, 0xBB,
	0x90, 0xC6, 0x9B, 0xA4, 0x09, 0x21, 0x44, 0x77,
	0x4D, 0x54, 0x88, 0xB7, 0x01, 0x39, 0x19, 0x8D,
	0x4F, 0x7A, 0x49, 0x6A, 0xDF, 0xFE, 0xD2, 0xF1, 0x13 }; //ECC_BYTES + 1
uint8_t privatekey_eg4[] = { 0xcc,0x62,0x7f,0xd3,0x99,0xae,0xcc,0x8b,
	0x48,0x9d,0x29,0xf8,0x77,0xa4,0x05,0xea,
	0xd0,0xa7,0x8c,0x51,0xae,0x47,0xc6,0xb9,
	0x49,0xa6,0x8f,0xa7,0xa8,0xa2,0x27,0x11 };
uint8_t publickey_eg4[] = { 0x03 , 0x75 , 0x60 , 0x99 , 0x3B , 0x5F , 0x74 , 0xCF ,
	0x10 , 0xD7 , 0x7F , 0x9F , 0x96 , 0x9E , 0x37 , 0x5E ,
	0x21 , 0x73 , 0x43 , 0x15 , 0xAA , 0x11 , 0xEE , 0x13 ,
	0x12 , 0x21 , 0x13 , 0x7B , 0x8C , 0x83 , 0x76 , 0xEA , 0x7F };// ECC_BYTES + 1


uint8_t signature_old_eg1[ECC_BYTES * 2];
uint8_t signature_new_eg1[ECC_BYTES * 2];
uint8_t signature_new_firstboot1[ECC_BYTES * 2];

uint8_t signature_old_eg2[ECC_BYTES * 2];
uint8_t signature_new_eg2[ECC_BYTES * 2];
uint8_t signature_new_firstboot2[ECC_BYTES * 2];

uint8_t signature_old_eg3[ECC_BYTES * 2];
uint8_t signature_new_eg3[ECC_BYTES * 2];
uint8_t signature_new_firstboot3[ECC_BYTES * 2];

uint8_t signature_old_eg4[ECC_BYTES * 2];
uint8_t signature_new_eg4[ECC_BYTES * 2];
uint8_t signature_new_firstboot4[ECC_BYTES * 2];
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
	for (i = 0; i < 32; i++) {
		ch[i] = s[i];
	}
	return 0;
}

int shastr64to0x32(const char singlechar[64], char hash[32]) {
	unsigned long i, j;
	int temp;

	i = 0;
	for (j = 0; j < 64; j++) {
		if (j % 2 == 0) {
			if (singlechar[j] == '0' || (singlechar[j] >= '1' && singlechar[j] <= '9'))
				temp = singlechar[j] - '1' + 1;
			else
				temp = singlechar[j] - 'a' + 0x0a;
		}
		else {
			if (singlechar[j] == '0' || (singlechar[j] >= '1' && singlechar[j] <= '9'))
				temp = temp * 0x10 + (singlechar[j] - '1' + 1);
			else
				temp = temp * 0x10 + (singlechar[j] - 'a' + 0x0a);
			hash[i] = temp;
			i++;
		}
	}
	return 0;
}



int main() {
	char hash_old[32] = { 0x31,0x38,0xee,0xd5,0x49,0xf0,0xfe,0x67,0xfa,0x1e,0x3c,0xe5,0xc6,0xd6,0x61,0x80,0x7d,0xb4,0x5f,0xc1,0xa8,0x4b,0xcc,0x36,0xf8,0xc0,0x63,0x9a,0x69,0x84,0xf1,0x97 };
	char hash_new[32] = { 0xa7,0x44,0x33,0x32,0x9a,0xba,0xca,0xce,0x7d,0xd3,0x46,0x23,0x38,0x3e,0xc3,0x18,0x96,0xba,0x0d,0x7f,0x01,0xd2,0x2d,0x13,0x32,0x81,0x61,0x97,0xe7,0xa0,0x8d,0x55 };
	char hash_new_firstboot[32] = { 0xa4,0x26,0xf2,0x58,0xcd,0xa1,0x65,0x8f,0x10,0xee,0x39,0x58,0x23,0x88,0x4b,0x7e,0xc4,0x07,0x47,0x89,0x32,0x02,0x6f,0xf2,0x88,0xb5,0xea,0xae,0x49,0x1a,0x37,0xd3 };
	fw_info_t fw_info_test ,*pst;
	pst = &fw_info_test;
	/*copy_string_to_unsigned_char(hash_test, fw_info_test.hash_old);
	copy_string_to_unsigned_char(hash_test, fw_info_test.hash_new);*/
	fw_info_test.size_old = 12583767;//12845911;//9700183;//15991639;
	fw_info_test.size_new = 9438039;//12583767;//9700183;//12845911;//9700183;//15991639
	fw_info_test.update = 0x00;
	fw_info_test.sig1_tag=1;
	fw_info_test.sig2_tag=1;
	fw_info_test.sig3_tag=1;
	fw_info_test.sig4_tag=1;
	shastr64to0x32("9a48d0581b744508cec1e2465e78d968703e8b21fe817428d67be467ac6930ca", hash_old);
	shastr64to0x32("a426f258cda1658f10ee395823884b7ec407478932026ff288b5eaae491a37d3", hash_new_firstboot);
	shastr64to0x32("a426f258cda1658f10ee395823884b7ec407478932026ff288b5eaae491a37d3", hash_new);
	copy_char_to_unsigned_char(hash_old, fw_info_test.hash_old);
	copy_char_to_unsigned_char(hash_new, fw_info_test.hash_new);
	fw_info_test.firstboot_tag = 0;
	copy_char_to_unsigned_char(hash_new_firstboot, fw_info_test.hash_new_firstboot);
	

#define GET_NEW_SIGNATURE
#ifdef GET_NEW_SIGNATURE
	/*sign_and_print(privatekey_eg1, fw_info_test.hash_old);
	sign_and_print(privatekey_eg1, fw_info_test.hash_new);
	sign_and_print(privatekey_eg1, fw_info_test.hash_new_firstboot);*/
	getsig_sign_and_print(privatekey_eg1, fw_info_test.hash_old, signature_old_eg1);
	getsig_sign_and_print(privatekey_eg1, fw_info_test.hash_new, signature_new_eg1);
	getsig_sign_and_print(privatekey_eg1, fw_info_test.hash_new_firstboot, signature_new_firstboot1);

	getsig_sign_and_print(privatekey_eg2, fw_info_test.hash_old, signature_old_eg2);
	getsig_sign_and_print(privatekey_eg2, fw_info_test.hash_new, signature_new_eg2);
	getsig_sign_and_print(privatekey_eg2, fw_info_test.hash_new_firstboot, signature_new_firstboot2);

	getsig_sign_and_print(privatekey_eg3, fw_info_test.hash_old, signature_old_eg3);
	getsig_sign_and_print(privatekey_eg3, fw_info_test.hash_new, signature_new_eg3);
	getsig_sign_and_print(privatekey_eg3, fw_info_test.hash_new_firstboot, signature_new_firstboot3);

	getsig_sign_and_print(privatekey_eg4, fw_info_test.hash_old, signature_old_eg4);
	getsig_sign_and_print(privatekey_eg4, fw_info_test.hash_new, signature_new_eg4);
	getsig_sign_and_print(privatekey_eg4, fw_info_test.hash_new_firstboot, signature_new_firstboot4);
#endif // GET_NEW_SIGNATURE

	FILE* mtd8_pubsig = fopen("mtd8_pubsig.bin", "wb");
	ulong i;
	uint8_t* p = (uint8_t*)(&fw_info_test);
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		putc(p[i], mtd8_pubsig);
		printf("%02x ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\nsizeof(fw_info_t): %d\n", sizeof(fw_info_t));

	for (i = 0; i < ECC_BYTES + 1; i++)	fputc(publickey_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_old_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_new_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_new_firstboot1[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++)	fputc(publickey_eg2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_old_eg2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_new_eg2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_new_firstboot2[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++)	fputc(publickey_eg3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_old_eg3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_new_eg3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_new_firstboot3[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++)	fputc(publickey_eg4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_old_eg4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_new_eg4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++)	fputc(signature_new_firstboot4[i], mtd8_pubsig);
	fclose(mtd8_pubsig);


	fw_info_t* fwi =(fw_info_t*) malloc(sizeof(fw_info_t));
	printf("fw-info size: %d\n", sizeof(fw_info_t));
	FILE* mtd8 = fopen("mtd8_pubsig.bin", "rb");
	printf("fw-info raw: \n");
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		*(p+i)=fgetc(mtd8);
	}
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		printf("%02x ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n\n");
	fwi = (fw_info_t*)p;

	uint8_t pubkey_get1[ECC_BYTES + 1];
	for (i = 0; i < ECC_BYTES + 1; i++) pubkey_get1[i] = fgetc(mtd8);
	uint8_t sig_old_get1[ECC_BYTES *2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_old_get1[i] = fgetc(mtd8);
	uint8_t sig_new_get1[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_new_get1[i] = fgetc(mtd8);
	uint8_t sig_new_firstboot_get1[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_new_firstboot_get1[i] = fgetc(mtd8);

	uint8_t pubkey_get2[ECC_BYTES + 1];
	for (i = 0; i < ECC_BYTES + 1; i++) pubkey_get2[i] = fgetc(mtd8);
	uint8_t sig_old_get2[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_old_get2[i] = fgetc(mtd8);
	uint8_t sig_new_get2[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_new_get2[i] = fgetc(mtd8);
	uint8_t sig_new_firstboot_get2[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_new_firstboot_get2[i] = fgetc(mtd8);

	uint8_t pubkey_get3[ECC_BYTES + 1];
	for (i = 0; i < ECC_BYTES + 1; i++) pubkey_get3[i] = fgetc(mtd8);
	uint8_t sig_old_get3[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_old_get3[i] = fgetc(mtd8);
	uint8_t sig_new_get3[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_new_get3[i] = fgetc(mtd8);
	uint8_t sig_new_firstboot_get3[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_new_firstboot_get3[i] = fgetc(mtd8);

	uint8_t pubkey_get4[ECC_BYTES + 1];
	for (i = 0; i < ECC_BYTES + 1; i++) pubkey_get4[i] = fgetc(mtd8);
	uint8_t sig_old_get4[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_old_get4[i] = fgetc(mtd8);
	uint8_t sig_new_get4[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_new_get4[i] = fgetc(mtd8);
	uint8_t sig_new_firstboot_get4[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) sig_new_firstboot_get4[i] = fgetc(mtd8);
	

	printf("fw-info data: ->update, ->size_old, ->size_new, fwi->firstboot_tag, sig_tag*4 : %d %d %d %d, %d %d %d %d\n", 
		fwi->update, fwi->size_old, fwi->size_new,fwi->firstboot_tag, fwi->sig1_tag, fwi->sig2_tag, fwi->sig3_tag, fwi->sig4_tag);
	printf("hash_3: ");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_old + i)); printf("\n");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_new + i)); printf("\n");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_new_firstboot + i)); printf("\n");

	/*//printf("pubkey: "); for (i = 0; i < ECC_BYTES + 1; i++)printf("%02x ", pubkey_get1[i]);
	printf("\nsig_old: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_old_get1[i]);
	printf("\nsig_new: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_new_get1[i]);
	//printf("\npubkey: "); for (i = 0; i < ECC_BYTES + 1; i++)printf("%02x ", pubkey_get1[i]);
	printf("\nsig_old: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_old_get1[i]);
	printf("\nsig_new: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_new_get1[i]);
	//printf("\npubkey: "); for (i = 0; i < ECC_BYTES + 1; i++)printf("%02x ", pubkey_get1[i]);
	printf("\nsig_old: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_old_get1[i]);
	printf("\nsig_new: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_new_get1[i]);
	//printf("\npubkey: "); for (i = 0; i < ECC_BYTES + 1; i++)printf("%02x ", pubkey_get1[i]);
	printf("\nsig_old: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_old_get1[i]);
	printf("\nsig_new: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_new_get1[i]);*/

	printf("\nsig_old1:"); signature_verify_by_pubkey_33(publickey_eg1, fwi->hash_old, sig_old_get1);
	printf("sig_new1:"); signature_verify_by_pubkey_33(publickey_eg1, fwi->hash_new, sig_new_get1);
	printf("sig_new_firstboot1:"); signature_verify_by_pubkey_33(publickey_eg1, fwi->hash_new_firstboot, sig_new_firstboot_get1);
	printf("sig_old2:"); signature_verify_by_pubkey_33(publickey_eg2, fwi->hash_old, sig_old_get2);
	printf("sig_new2:"); signature_verify_by_pubkey_33(publickey_eg2, fwi->hash_new, sig_new_get2);
	printf("sig_new_firstboot2:"); signature_verify_by_pubkey_33(publickey_eg2, fwi->hash_new_firstboot, sig_new_firstboot_get2);
	printf("sig_old3:"); signature_verify_by_pubkey_33(publickey_eg3, fwi->hash_old, sig_old_get3);
	printf("sig_new3:"); signature_verify_by_pubkey_33(publickey_eg3, fwi->hash_new, sig_new_get3);
	printf("sig_new_firstboot3:"); signature_verify_by_pubkey_33(publickey_eg3, fwi->hash_new_firstboot, sig_new_firstboot_get3);
	printf("sig_old4:"); signature_verify_by_pubkey_33(publickey_eg4, fwi->hash_old, sig_old_get4);
	printf("sig_new4:"); signature_verify_by_pubkey_33(publickey_eg4, fwi->hash_new, sig_new_get4);
	printf("sig_new_firstboot4:"); signature_verify_by_pubkey_33(publickey_eg4, fwi->hash_new_firstboot, sig_new_firstboot_get4);
	printf("\n");
	fclose(mtd8);


	/*int chunk = 4096;
	int empty = 0, j;
	ulong k;
	uint8_t sha256_sum[32];
	uint8_t test_sha256_string[] = { '1','2','3' };
	sha256_csum_wd(test_sha256_string, 3, sha256_sum, chunk);
	printf("testing sha256... ...  123:   \n");
	for (i = 0; i < 32; i++) {
		printf("%02lx", sha256_sum[i]);
	}
	printf("\n");
	for (i = 0; i < 32; i++) {
		printf("%c", sha256_sum[i]);
	}
	printf("\n");*/
	
/*#define mtd8_ADDR 0x1ff0000 //"fw-info"
#define mtd7_ADDR 0x1600000 //"fw-new"
#define mtd3_ADDR   0x50000 //"firmware"
#define mtd5_ADDR  0x1deeed //"rootfs"
#define mtd6_ADDR  0xf70000 //"rootfs_data" //mtd6_ADDR-mtd5_ADDR=14225683
	FILE *big6, *big5, *big5minus6;
	big5 = fopen("bin_files/mtd5_big", "rb");
	uint8_t sha256_sum[32];
	printf("Current Firmware /rom (/dev/root, mtd5-mtd6) sha256 ... \n");
	unsigned char temp[518028];
	for (i = 0; i < mtd6_ADDR - mtd5_ADDR;) {
		printf("%ld\r", i);
		*(temp +i)=fgetc(big5);
		if (*(temp + i) != 0xff)i++;
	}
	printf("\n");
	sha256_csum_wd(temp, i, sha256_sum, CHUNKSZ_SHA256);
	for (i = 0; i < 32; i++) {
		printf("%02lx", sha256_sum[i]);
	}
	printf("\n");

	fclose(big5);*/
	return 0;
}
//mtd write mtd8_pubsig.bin fw-info



/*
big2_init:9602ebcfffe429ca624fb2a2dd90719c7a1d099f57db7753417d4b60e33a0f9a					12,845,911
small2_init:8121e338a812d0aeda8c005337041a46062f8c41cdd7e636be2bbfaaebb9cce9				9,700,183 
big2_mtd3:4703b1391ffb313abc1624e77ef28adafff8686beb04e78d5072874209dc14d2
small2_mtd3:54df8e02ef0b899537d937a8df3b1125551af399fff928e561cd94e6ed6ca9c2

big3_init:9a48d0581b744508cec1e2465e78d968703e8b21fe817428d67be467ac6930ca					12,583,767
big3_mtd3:3138eed549f0fe67fa1e3ce5c6d661807db45fc1a84bcc36f8c0639a6984f197
small3_init:a426f258cda1658f10ee395823884b7ec407478932026ff288b5eaae491a37d3				9,438,039 
small3_mtd3:a74433329abacace7dd34623383ec31896ba0d7f01d22d1332816197e7a08d55
*/
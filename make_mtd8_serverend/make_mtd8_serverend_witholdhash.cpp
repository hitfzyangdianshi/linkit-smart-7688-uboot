#include <iostream>
#include <cstdio>
#include<cstring>
#include<cstdlib>
#include <ctime> 
#include <sys/stat.h>  
//#include <sys/statfs.h>
#include "../ecdsa_lightweight/easy_ecc_main.c"
#include "../include/image.h"
#define _CRT_SECURE_NO_WARNINGS
using namespace std;

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

typedef		unsigned long		ulong;

long file_size2(const char* filename)
{
	struct stat statbuf;
	stat(filename, &statbuf);
	long size = statbuf.st_size;
	return size;
}

int shastr64to0x32(char singlechar[64], char hash[32]) {
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

int copy_char_to_unsigned_char(char s[], uint8_t ch[]) {
	int i;
	for (i = 0; i < 32; i++) {
		ch[i] = s[i];
	}
	return 0;
}

int cut_fw_removemetadata(const char* old_filename, FILE* in, FILE* out, int offset = 0x357) {//offset = 0x357
	long initsize, outsize, i;
	initsize = file_size2(old_filename);
	outsize = initsize - offset, i;
	char c;
	printf("%s: initsize: %ld ,\toutsize: %ld\n", old_filename, initsize, outsize);
	for (i = 0; i < outsize; i++) {
		c = fgetc(in);
		fputc(c, out);
	}

	return 0;
}


#define GRNERATE_NOT_FIRSTBOOT



int main(int argc, char** argv)
{
	char  // * fwoldpath, 
		* fwnewpath, * outfilepath, c,
		hash_old[32], *hash_old_singlechar,
		hash_new[32], hash_new_singlechar[64];
	long i;

	if (argc != 4) {
		printf("argc!=4...  \nplease give parameters: old_fw_hashvalue    new_fw_path    output_fw_info\n");
		exit(1);
	}
	else {
		hash_old_singlechar = argv[1];
		fwnewpath = argv[2];
		outfilepath = argv[3];
	}

	FILE  // * oldfw, * oldfw_cut, 
		* newfw, * newfw_cut, * newfw_notfirstboot_cut;
	FILE //* sha2old, 
		* sha2new, * sha2new_notfirstboot;
	/*oldfw = fopen(fwoldpath, "rb");
	oldfw_cut = fopen("oldfw_cut.tmp", "wb");*/
	newfw = fopen(fwnewpath, "rb");
	newfw_cut = fopen("newfw_cut.tmp", "wb");
	newfw_notfirstboot_cut = fopen("newfw_notfirstboot_cut.tmp", "wb");

	//cut_fw_removemetadata(fwoldpath, oldfw, oldfw_cut);
	cut_fw_removemetadata(fwnewpath, newfw, newfw_cut, 0);
	fclose(newfw);
	newfw = fopen(fwnewpath, "rb");
	cut_fw_removemetadata(fwnewpath, newfw, newfw_notfirstboot_cut);


	fclose(newfw);
	fclose(newfw_cut);
	fclose(newfw_notfirstboot_cut);

	/*sha2old = popen("sha256sum oldfw_cut.tmp", "r");
	fgets(hash_old_singlechar, 65, sha2old);*/
	shastr64to0x32(hash_old_singlechar, hash_old);
	//pclose(sha2old);
	for (i = 0; i < 64; i++)printf("%c", hash_old_singlechar[i]);
	printf("\n");

	sha2new = popen("sha256sum newfw_cut.tmp", "r");
	fgets(hash_new_singlechar, 65, sha2new);
	shastr64to0x32(hash_new_singlechar, hash_new);
	pclose(sha2new);
	for (i = 0; i < 64; i++)printf("%c", hash_new_singlechar[i]);
	printf("\n");

	char hash_new_notfirstboot[32], hash_new_notfirstboot_singlechar[64];
#ifdef GRNERATE_NOT_FIRSTBOOT
	/*make_mtd3(fwnewpath, "newfw_mtd3_notfirstboot.tmp");
	//cut_fw_removemetadata("newfw_mtd3_notfirstboot.tmp",)
	sha2new_notfirstboot= popen("sha256sum newfw_mtd3_notfirstboot.tmp", "r");*/
	sha2new_notfirstboot = popen("sha256sum	newfw_notfirstboot_cut.tmp", "r");
	fgets(hash_new_notfirstboot_singlechar, 65, sha2new_notfirstboot);
	shastr64to0x32(hash_new_notfirstboot_singlechar, hash_new_notfirstboot);
	pclose(sha2new_notfirstboot);
	for (i = 0; i < 64; i++)printf("%c", hash_new_notfirstboot_singlechar[i]);
	printf("\n");
#endif // GRNERATE_NOT_FIRSTBOOT



	fw_info_t fw_info_test, * pst;
	pst = &fw_info_test;

	fw_info_test.update = 0x01;
	copy_char_to_unsigned_char(hash_old, fw_info_test.hash_old);
	copy_char_to_unsigned_char(hash_new_notfirstboot, fw_info_test.hash_new);
	fw_info_test.firstboot_tag = 1;
	copy_char_to_unsigned_char(hash_new, fw_info_test.hash_new_firstboot);

	fw_info_test.size_old = file_size2("oldfw_cut.tmp");//(fwoldpath);
	fw_info_test.size_new = file_size2(fwnewpath);

	fw_info_test.sig1_tag = 1;
	fw_info_test.sig2_tag = 1;
	fw_info_test.sig3_tag = 1;
	fw_info_test.sig4_tag = 1;
	srand((unsigned)time(NULL));
	int randomnumber = rand() % 6;
	if (randomnumber == 1) {
		fw_info_test.sig1_tag = 0;
		fw_info_test.sig2_tag = 0;
	}
	else if (randomnumber == 2) {
		fw_info_test.sig1_tag = 0;
		fw_info_test.sig3_tag = 0;
	}
	else if (randomnumber == 3) {
		fw_info_test.sig1_tag = 0;
		fw_info_test.sig4_tag = 0;
	}
	else if (randomnumber == 4) {
		fw_info_test.sig2_tag = 0;
		fw_info_test.sig3_tag = 0;
	}
	else if (randomnumber == 4) {
		fw_info_test.sig2_tag = 0;
		fw_info_test.sig4_tag = 0;
	}
	else {
		fw_info_test.sig3_tag = 0;
		fw_info_test.sig4_tag = 0;
	}

	getsig_sign_no_print(privatekey_eg1, fw_info_test.hash_old, signature_old_eg1);
	getsig_sign_no_print(privatekey_eg1, fw_info_test.hash_new, signature_new_eg1);
	if (fw_info_test.sig1_tag == 1) getsig_sign_and_print(privatekey_eg1, fw_info_test.hash_new_firstboot, signature_new_firstboot1);
	else  getsig_sign_no_print(privatekey_eg1, fw_info_test.hash_new_firstboot, signature_new_firstboot1);

	getsig_sign_no_print(privatekey_eg2, fw_info_test.hash_old, signature_old_eg2);
	getsig_sign_no_print(privatekey_eg2, fw_info_test.hash_new, signature_new_eg2);
	if (fw_info_test.sig2_tag == 1) getsig_sign_and_print(privatekey_eg2, fw_info_test.hash_new_firstboot, signature_new_firstboot2);
	else getsig_sign_no_print(privatekey_eg2, fw_info_test.hash_new_firstboot, signature_new_firstboot2);

	getsig_sign_no_print(privatekey_eg3, fw_info_test.hash_old, signature_old_eg3);
	getsig_sign_no_print(privatekey_eg3, fw_info_test.hash_new, signature_new_eg3);
	if (fw_info_test.sig3_tag == 1) getsig_sign_and_print(privatekey_eg3, fw_info_test.hash_new_firstboot, signature_new_firstboot3);
	else getsig_sign_no_print(privatekey_eg3, fw_info_test.hash_new_firstboot, signature_new_firstboot3);

	getsig_sign_no_print(privatekey_eg4, fw_info_test.hash_old, signature_old_eg4);
	getsig_sign_no_print(privatekey_eg4, fw_info_test.hash_new, signature_new_eg4);
	if (fw_info_test.sig4_tag == 1)getsig_sign_and_print(privatekey_eg4, fw_info_test.hash_new_firstboot, signature_new_firstboot4);
	getsig_sign_no_print(privatekey_eg4, fw_info_test.hash_new_firstboot, signature_new_firstboot4);




	FILE* mtd8_pubsig = fopen(outfilepath, "wb");
	uint8_t* p = (uint8_t*)(&fw_info_test);
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		putc(p[i], mtd8_pubsig);
		/*printf("%02x ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}*/
	}
	//printf("\nsizeof(fw_info_t): %d\n", sizeof(fw_info_t));

	for (i = 0; i < ECC_BYTES + 1; i++) fputc(publickey_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_old_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_firstboot1[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++) fputc(publickey_eg2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_old_eg2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_eg2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_firstboot2[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++) fputc(publickey_eg3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_old_eg3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_eg3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_firstboot3[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++) fputc(publickey_eg4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_old_eg4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_eg4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_firstboot4[i], mtd8_pubsig);

	fclose(mtd8_pubsig);






	return 0;
}

/*
hash_old: sizeold (init-0x357)
hash_new_firstboot:sizenew
hash_new(not firstboot): sizenew -0x357
*/
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <time.h> 
#include <sys/stat.h>  
//#include <sys/statfs.h>
#include "../ecdsa_lightweight/easy_ecc_main.c"
#include "../include/image.h"
#define _CRT_SECURE_NO_WARNINGS

typedef		unsigned long		ulong;

int copy_unsigned_char_to_unsigned_char(uint8_t in[], uint8_t out[], int length) {
	int i;
	for (i = 0; i < length; i++) {
		out[i] = in[i];
	}
	return 0;
}

int main() {
	int i;
	membership_info_t membership_new, *membership_old=(membership_info_t*)malloc(sizeof(membership_info_t));
	uint8_t* p = (uint8_t*)membership_old;
	FILE* versionfile, * keysn, *membership_old_mtd10;
	versionfile = fopen("/tmp/membership_version_number.txt", "r");
	keysn = fopen("/tmp/membership_keys_howmany.txt", "r");

	membership_old_mtd10 = fopen("/tmp/mtd10", "rb");
	for (i = 0; i < sizeof(membership_info_t); i++) {
		p[i] = fgetc(membership_old_mtd10);
	}

	fscanf(versionfile, "%d", &membership_new.version);
	if (membership_old->version >= membership_new.version) {
		printf("the version of old membership is bigger or equal (>=) to the version of new membership...\nexit\n");
		exit(-1);
	}

	int keysN;
	fscanf(keysn, "%d", &keysN);
	
	for (i = 0; i < keysN; i++) {
		FILE* keys;
		char number_s[5];
		char keysfilename[50];
		itoa(i, number_s, 10);
		strcat(keysfilename, "/tmp/k");
		strcat(keysfilename, number_s);
		uint8_t keyi[ECC_BYTES +1];
		keys = fopen(keysfilename, "rb");
		fread(keyi, 1, ECC_BYTES +1, keys);
		copy_unsigned_char_to_unsigned_char(keyi, membership_new.pubkeys[i], ECC_BYTES + 1);
		fclose(keys);
	}
	fclose(versionfile);
	fclose(keysn);

	FILE* mtd9_meminfo = fopen("/tmp/mtd9_.bin", "wb");
	uint8_t* q = (uint8_t*)(&membership_new);
	for (i = 0; i < (sizeof(membership_info_t)); i++) {
		putc(q[i], mtd9_meminfo);
	}
	fclose(mtd9_meminfo);

	system("mtd write /tmp/mtd9_.bin u-info_i");

	return 0;
}


//  /home/qwer/openwrt19/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-8.3.0_musl/bin/mipsel-openwrt-linux-gcc update_membership.cpp -o update_membership.out
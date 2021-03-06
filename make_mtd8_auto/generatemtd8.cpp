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
/*
uint8_t publickey_eg1[] = { 0x02, 0x68, 0xC0, 0xC8, 0x1D, 0x72, 0x85, 0x67,
	0x22, 0xE0, 0x37, 0x38, 0xA7, 0xB4, 0x6C, 0x11,
	0x62, 0x85, 0xC1, 0xA3, 0xA8, 0x50, 0xEE, 0xFC,
	0x84, 0xA6, 0xE7, 0x47, 0x78, 0x1F, 0x22, 0x1D,
	0x0A };

uint8_t publickey_eg2[] = { 0x03 , 0x03 , 0xEC , 0xBE , 0x5A , 0x0E , 0x9A , 0xF7 , // ECC_BYTES + 1
	0xAD , 0xDC , 0x15 , 0x34 , 0x9B , 0x96 , 0x3B , 0x29 ,
	0xC7 , 0x24 , 0x36 , 0x5E , 0x24 , 0xDE , 0x2E , 0xE9 ,
	0x92 , 0x7C , 0x11 , 0xE9 , 0x2D , 0xF5 , 0xA4 , 0xE1 , 0x80 };

uint8_t publickey_eg3[] = { 0x03, 0x25, 0xA7, 0x91, 0xC4, 0x0B, 0x2B, 0xBB,
	0x90, 0xC6, 0x9B, 0xA4, 0x09, 0x21, 0x44, 0x77,
	0x4D, 0x54, 0x88, 0xB7, 0x01, 0x39, 0x19, 0x8D,
	0x4F, 0x7A, 0x49, 0x6A, 0xDF, 0xFE, 0xD2, 0xF1, 0x13 }; //ECC_BYTES + 1

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
*/
/*int copy_string_to_unsigned_char(string s, uint8_t ch[]) {
	int i;
	for (i = 0; i < s.length(); i++) {
		ch[i] = s.c_str()[i];
	}
	return 0;
}*/

int copy_char_to_unsigned_char(char s[], uint8_t ch[],int length) {
	int i;
	for (i = 0; i < length; i++) {
		ch[i] = s[i];
	}
	return 0;
}

int copy_unsigned_char_to_unsigned_char(uint8_t in[], uint8_t out[],int length) {
	int i;
	for (i = 0; i < length; i++) {
		out[i] = in[i];
	}
	return 0;
}

long file_size2(const char* filename)
{
	struct stat statbuf;
	stat(filename, &statbuf);
	long size = statbuf.st_size;
	return size;
}

/*long getFsSize(const char* path) {

	struct statfs myStatfs;
	long totalSize;
	if (statfs(path, &myStatfs) == -1) {
		return -1;
	}

	//ע��long long�������������
	//*freeSize = ((unsigned long)myStatfs.f_bsize * (unsigned long)myStatfs.f_bfree) ;
	totalSize = ((  long)myStatfs.f_bsize * (  long)myStatfs.f_blocks) ;
	printf("fssize:%ld\n", totalSize);
	return totalSize;
}*/



#define FW_TAIL_OFFSET 0x30e

int main(int argc, char** argv)
{

	//FILE* current_fw, * current_fw_cut, * new_fw, * new_fw_cut, * fpsha256old, * fpsha256new, * fpsha256newfirstboot;
	fw_info_t fwinfo ;

	unsigned long i, j;
	char c;
	/*//current_fw = fopen("/tmp/current_fw.bin", "rb");
	//current_fw_cut = fopen("/tmp/current_fw_cut.bin", "wb");

	//fw_info_test.size_old = file_size2("/tmp/current_fw.bin") - file_size2("/tmp/mtd6");
	//remove("/tmp/mtd6");
	//remove("/tmp/current_fw.bin");*/

	fwinfo.size_new = file_size2("/tmp/download_fw.bin") - 0;

	fwinfo.update = 0x01;
	
//	fwinfo.firstboot_tag = 1;
	fwinfo.membership_update = 0; 

	for (i = 0; i < 10; i++) fwinfo.sigs_tag[i] = 0;

	FILE* sighowmany = fopen("/tmp/sighowmany.txt", "r");
	int sighowmany_n;
	fscanf(sighowmany, "%d", &sighowmany_n);
	fclose(sighowmany);

	for (i = 0; i < sighowmany_n; i++) {
		uint8_t sigi[ECC_BYTES * 2];
		char number_s[5];
		char sigsfilename[50];
		itoa(i, number_s, 10);
		strcat(sigsfilename, "/tmp/sig");
		strcat(sigsfilename, number_s);
		FILE *sigs;
		sigs = fopen(sigsfilename, "rb");
		fread(sigi, 1, ECC_BYTES * 2, sigs);
		copy_unsigned_char_to_unsigned_char(sigi, fwinfo.sigs[i], ECC_BYTES *2);
		fclose(sigs);
	}


	FILE *keyindex;
	keyindex = fopen("/tmp/index.txt", "r");
	int index_temp;
	for (i = 0; i < sighowmany_n; i++) {
		fscanf(keyindex, "%d", &index_temp);
		fwinfo.sigs_tag[index_temp] = 1;
	}
	fclose(keyindex);

	



	FILE* mtd8_pubsig = fopen("/tmp/mtd8_.bin", "wb");
	uint8_t* p = (uint8_t*)(&fwinfo);
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		putc(p[i], mtd8_pubsig);

	}




	fclose(mtd8_pubsig);


	return 0;
}
//  /home/qwer/openwrt19/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-8.3.0_musl/bin/mipsel-openwrt-linux-gcc generatemtd8.cpp -o generatemtd8.out
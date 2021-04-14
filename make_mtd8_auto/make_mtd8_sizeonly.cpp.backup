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



long file_size2(const char* filename)
{
	struct stat statbuf;
	stat(filename, &statbuf);
	long size = statbuf.st_size;
	return size;
}





int main(int argc, char** argv)
{
	FILE* mtd3, * mtd6, * newfw;
	

	unsigned long i, j;
	char c;
	/*current_fw = fopen("/tmp/current_fw.bin", "rb");
	current_fw_cut = fopen("/tmp/current_fw_cut.bin", "wb");*/
	mtd3 = fopen("/tmp/current_fw.bin", "rb");
	mtd6 = fopen("/tmp/mtd6", "rb");
	newfw = fopen("/tmp/download_fw.bin", "rb");


	int size_old = file_size2("/tmp/current_fw.bin") - file_size2("/tmp/mtd6");
	int size_new= file_size2("/tmp/download_fw.bin");
	printf("%d\t%d\n", size_old, size_new);

	fw_info_t* fwi = (fw_info_t*)malloc(sizeof(fw_info_t));
	//int p[1020];
	uint8_t* p = (uint8_t*)(fwi);
	FILE* mtd8 = fopen("/tmp/mtd8_pubsig.bin", "rb");
	//printf("fw-info raw: \n");
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		*(p + i) = fgetc(mtd8);
	}
	fwi = (fw_info_t*)p;

	printf("%d\t%d\n", fwi->size_old, fwi->size_new);

	uint8_t pubkey_get1[ECC_BYTES + 1];
	for (i = 0; i < ECC_BYTES + 1; i++) pubkey_get1[i] = fgetc(mtd8);
	uint8_t sig_old_get1[ECC_BYTES * 2];
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


	/*printf("fw-info data: ->update, ->size_old, ->size_new, fwi->firstboot_tag: %d %d %d %d\n", fwi->update, fwi->size_old, fwi->size_new, fwi->firstboot_tag);
	printf("hash_3: ");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_old + i)); printf("\n");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_new + i)); printf("\n");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_new_firstboot + i)); printf("\n");

	printf("pubkey: "); for (i = 0; i < ECC_BYTES + 1; i++)printf("%02x ", pubkey_get1[i]);
	printf("\nsig_old: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_old_get1[i]);
	printf("\nsig_new: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_new_get1[i]);

	printf("\nsig_old:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_old, sig_old_get1);
	printf("sig_new:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_new, sig_new_get1);
	printf("sig_new_firstboot:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_new_firstboot, sig_new_firstboot_get);
	printf("\n");*/
	fclose(mtd8);



	fwi->size_old = size_old;
	fwi->size_new = size_new- 0x357;


	printf("%d\t%d\n", fwi->size_old, fwi->size_new);


	FILE* mtd8_pubsig = fopen("/tmp/mtd8_1_big2small.bin", "wb");
	uint8_t* p1 = (uint8_t*)(fwi);
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		putc(p1[i], mtd8_pubsig);
		/*printf("%02x ", p1[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}*/
	}
	//printf("\nsizeof(fw_info_t): %d\n", sizeof(fw_info_t));

	for (i = 0; i < ECC_BYTES + 1; i++) fputc(pubkey_get1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_old_get1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_new_get1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_new_firstboot_get1[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++) fputc(pubkey_get2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_old_get2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_new_get2[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_new_firstboot_get2[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++) fputc(pubkey_get3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_old_get3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_new_get3[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_new_firstboot_get3[i], mtd8_pubsig);

	for (i = 0; i < ECC_BYTES + 1; i++) fputc(pubkey_get4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_old_get4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_new_get4[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(sig_new_firstboot_get4[i], mtd8_pubsig);

	fclose(mtd8_pubsig);




	return 0;
}
//  /home/qwer/openwrt19/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-8.4.0_musl/bin/mipsel-openwrt-linux-gcc make_mtd8_sizeonly.cpp -o generatemtd8.out
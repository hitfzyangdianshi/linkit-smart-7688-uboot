#include<iostream>
#include<cstdio>
#include<string>
#include "../ecdsa_lightweight/easy_ecc_main.c"
#include "../include/image.h"
#define USE_HOSTCC
#include "../include/u-boot/sha256.h"
#include "../lib_generic/sha256.c"
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
uint8_t signature_old_eg1[] = { 0x86 , 0x69 , 0xA4 , 0x53 , 0xD9 , 0x1F , 0x89 , 0xA7 , 0xAA , 0x0E , 0x79 , 0xD9 , 0xE1 , 0x3C , 0x4D , 0x84 , 0x34 , 0xE7 , 0x83 , 0x65 , 0xF5 , 0xCD , 0xCB , 0xC8 , 0x37 , 0xFB , 0x2C , 0x44 , 0xE5 , 0x3C , 0xF8 , 0x69 , 0x67 , 0xE5 , 0xEA , 0x9F , 0x88 , 0xAA , 0xED , 0x9A , 0x21 , 0xE0 , 0x12 , 0x16 , 0xCC , 0x0F , 0x1E , 0x7E , 0xF1 , 0xEB , 0xDD , 0x10 , 0x2F , 0x48 , 0x33 , 0x8E , 0xB8 , 0x08 , 0xD7 , 0x5E , 0xA2 , 0x8D , 0x10 , 0xFB };
uint8_t signature_new_eg1[] = { 0x1A , 0xCB , 0xD8 , 0xA0 , 0x63 , 0xAF , 0x00 , 0x44 , 0xBE , 0x31 , 0xB2 , 0xAC , 0xDC , 0xC1 , 0x70 , 0x35 , 0x14 , 0x05 , 0x22 , 0x08 , 0x64 , 0x76 , 0xA6 , 0x5A , 0x85 , 0x72 , 0xA9 , 0x68 , 0x28 , 0x92 , 0x97 , 0xCD , 0xD6 , 0x2A , 0xA9 , 0x0A , 0x99 , 0xDA , 0x8F , 0x7B , 0xBB , 0xFB , 0xFE , 0x0A , 0x85 , 0x0F , 0x1C , 0xEA , 0xE7 , 0xC8 , 0x91 , 0x3A , 0x3F , 0x4B , 0xAD , 0xC0 , 0xAF , 0x00 , 0xDB , 0x14 , 0x0B , 0x4E , 0xCE , 0x4D };
uint8_t signature_new_firstboot[]= { 0x17 , 0xDE , 0xC8 , 0x1E , 0xEF , 0x70 , 0x72 , 0x14 , 0x56 , 0x74 , 0x08 , 0x6D , 0x06 , 0x71 , 0xA9 , 0x1E , 0xBC , 0xF0 , 0xF1 , 0x8E , 0x0A , 0xC6 , 0x10 , 0x42 , 0x18 , 0xB8 , 0x1B , 0x48 , 0xA5 , 0xA1 , 0xDE , 0x45 , 0x5D , 0x4A , 0xDA , 0xE6 , 0x20 , 0xC8 , 0x8E , 0xEC , 0xDD , 0x0D , 0x7E , 0x9B , 0x1F , 0x6C , 0x1A , 0xAE , 0x1F , 0x08 , 0xD0 , 0x9E , 0x4C , 0xF7 , 0x4D , 0x2B , 0x50 , 0xD9 , 0x99 , 0xF4 , 0x20 , 0x6E , 0xAC , 0x44 };
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
	char hash_old[] = { 0x26,0xf1,0x47,0x3d,0x6e,0xdd,0x3f,0x91,0xb0,0x71,0x12,0x87,0x77,0xdd,0x04,0x08,0x40,0x3a,0x3e,0xd0,0xc2,0x0e,0xf0,0x58,0xa7,0x13,0x2e,0xf7,0xf2,0x60,0x20,0xad };//32
	//26f1473d6edd3f91b071128777dd0408403a3ed0c20ef058a7132ef7f26020ad
	char hash_new[]= { 0x63,0xdf,0xbf,0xeb,0x16,0x73,0xf2,0x0d,0xa7,0x1b,0x43,0xfd,0x5f,0x04,0x8d,0x22,0x05,0x2d,0xe9,0xb4,0xa0,0xa6,0x85,0x50,0x20,0xf1,0x95,0xac,0x5c,0xb0,0x23,0xfa }; 
	char hash_new_firstboot[32] = { 0x26,0xf1,0x47,0x3d,0x6e,0xdd,0x3f,0x91,0xb0,0x71,0x12,0x87,0x77,0xdd,0x04,0x08,0x40,0x3a,0x3e,0xd0,0xc2,0x0e,0xf0,0x58,0xa7,0x13,0x2e,0xf7,0xf2,0x60,0x20,0xad };
	fw_info_t fw_info_test ,*pst;
	pst = &fw_info_test;
	/*copy_string_to_unsigned_char(hash_test, fw_info_test.hash_old);
	copy_string_to_unsigned_char(hash_test, fw_info_test.hash_new);*/	/*uint8_t signature_eg1[] = { 0x04, 0xD9, 0x04, 0x6B, 0xC1, 0x9D, 0xAF, 0xA2, 0xEC, 0xF0, 0xA8, 0x14, 0x0B, 0x57, 0xAF, 0xDC, 0x90, 0xA5, 0x0B, 0xBB, 0x3B, 0x77, 0xC1, 0xDC, 0xC6, 0x44, 0xB2, 0x47, 0xAC, 0x93, 0xCE, 0xB6, 0x75, 0x34, 0x37, 0x0E, 0x27, 0x8A, 0xA0, 0xC0, 0x45, 0xE9, 0xEE, 0xB0, 0xED, 0xD7, 0x3C, 0x64, 0x5B, 0xEF, 0x57, 0x18, 0x95, 0x77, 0x2B, 0x55, 0x58, 0x71, 0x5E, 0xF9, 0x10, 0xBE, 0x5F, 0x3D };*/
	fw_info_test.size_old = 15991639;
	fw_info_test.size_new = 15991639;
	fw_info_test.update = 0x00;
	copy_char_to_unsigned_char(hash_old, fw_info_test.hash_old);
	copy_char_to_unsigned_char(hash_new, fw_info_test.hash_new);
	fw_info_test.firstboot_tag = 1;
	copy_char_to_unsigned_char(hash_new_firstboot, fw_info_test.hash_new_firstboot);

//#define GET_NEW_SIGNATURE
#ifdef GET_NEW_SIGNATURE
	sign_and_print(privatekey_eg1, fw_info_test.hash_old);
	sign_and_print(privatekey_eg1, fw_info_test.hash_new);
	sign_and_print(privatekey_eg1, fw_info_test.hash_new_firstboot);
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
	printf("there are three additional 00's here at the end of struct fw_info fw_info_t\n");

	for (i = 0; i < ECC_BYTES+1; i++) {
		fputc(publickey_eg1[i], mtd8_pubsig);
	}
	for(i=0;i< ECC_BYTES*2;i++) fputc(signature_old_eg1[i], mtd8_pubsig);
	for(i=0;i< ECC_BYTES*2;i++) fputc(signature_new_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_firstboot[i], mtd8_pubsig);
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
	uint8_t sig_new_firstboot_get[ECC_BYTES * 2];
	for (i = 0; i < ECC_BYTES * 2; i++) {
		sig_new_firstboot_get[i] = fgetc(mtd8);
	}

	printf("fw-info data: ->update, ->size_old, ->size_new, fwi->firstboot_tag: %d %d %d %d\n", fwi->update, fwi->size_old, fwi->size_new,fwi->firstboot_tag);
	printf("hash_3: ");
	for (i = 0; i < 32; i++)printf("%c", *(fwi->hash_old + i)); printf("\n");
	for (i = 0; i < 32; i++)printf("%c", *(fwi->hash_new + i)); printf("\n");
	for (i = 0; i < 32; i++)printf("%c", *(fwi->hash_new_firstboot + i)); printf("\n");

	printf("pubkey: "); for (i = 0; i < ECC_BYTES + 1; i++)printf("%02x ", pubkey_get1[i]);
	printf("\nsig_old: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_old_get1[i]);
	printf("\nsig_new: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_new_get1[i]);

	printf("\nsig_old:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_old, sig_old_get1);
	printf("sig_new:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_new, sig_new_get1);
	printf("sig_new_firstboot:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_new_firstboot, sig_new_firstboot_get);
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
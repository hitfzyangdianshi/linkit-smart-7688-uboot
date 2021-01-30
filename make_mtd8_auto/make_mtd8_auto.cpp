#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <sys/stat.h>  
#include <sys/statfs.h>
#include "../ecdsa_lightweight/easy_ecc_main.c"
#include "../include/image.h"


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
uint8_t signature_old_eg1[ECC_BYTES * 2];
uint8_t signature_new_eg1[ECC_BYTES * 2];
uint8_t signature_new_firstboot[ECC_BYTES * 2];

/*int copy_string_to_unsigned_char(string s, uint8_t ch[]) {
	int i;
	for (i = 0; i < s.length(); i++) {
		ch[i] = s.c_str()[i];
	}
	return 0;
}*/

int copy_char_to_unsigned_char(char s[], uint8_t ch[]) {
	int i;
	for (i = 0; i < 32; i++) {
		ch[i] = s[i];
	}
	return 0;
}

bool compare_char(uint8_t* a, uint8_t* b, int length) {
	int i;
	for (i = 0; i < length; i++) {
		if (a[i] != b[i])  return false;
	}
	return true;
}

long file_size2(const char* filename)
{
	struct stat statbuf;
	stat(filename, &statbuf);
	long size = statbuf.st_size;
	return size;
}

long getFsSize(const char* path) {

	struct statfs myStatfs;
	long totalSize;
	if (statfs(path, &myStatfs) == -1) {
		return -1;
	}

	//注明long long，避免数据溢出
	//*freeSize = ((unsigned long)myStatfs.f_bsize * (unsigned long)myStatfs.f_bfree) ;
	totalSize = ((  long)myStatfs.f_bsize * (  long)myStatfs.f_blocks) ;
	printf("fssize:%ld\n", totalSize);
	return totalSize;
}

int shastr64to0x32(char singlechar[64], char hash[32]) {
	unsigned long i, j;
	int temp;
	
	i = 0;
	for (j = 0; j < 64; j++) {
		if (j % 2 == 0) {
			if(singlechar[j]=='0' || (singlechar[j]>='1' && singlechar[j]<='9'))
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

uint8_t deadc0deffffffff[] = { 0xDE, 0xAD, 0xC0, 0xDE, 0xFF, 0xFF, 0xFF, 0xFF,     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
uint8_t ffffffffffffffff[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
uint8_t deadc0de00000000[] = { 0xDE, 0xAD ,0xC0, 0xDE, 0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00, 0x7B, 0x20, 0x20, 0x22 };
uint8_t _851903200C000000[] ={ 0x85, 0x19 ,0x03, 0x20 ,0x0C ,0x00 ,0x00 ,0x00     ,0xB1 ,0xB0 ,0x1E, 0xE4, 0xFF, 0xFF, 0xFF, 0xFF };
int make_mtd3() {
	char init_filename[] = "/tmp/download_fw.bin";   //"../write_mtd/bin_files/big_init.bin";
    long init_file_length = file_size2(init_filename),i;
    FILE* init_file = fopen(init_filename, "rb");
    FILE* output_file = fopen("/tmp/output_file.binmtd3", "wb");
    uint8_t b[16];
    int j;
    bool putFF = false;
    for (i = 0; i < init_file_length; i++) {
        if (putFF == true)     fputc(0xff, output_file);
        else {
            if (i % 0x10000 == 0) {
                for (j = 0; j < 16; j++) {
                    b[j] = fgetc(init_file);
                }
                if (compare_char(b, deadc0deffffffff, 16) == true || compare_char(b, ffffffffffffffff, 16) == true)
                {
                    for (j = 0; j < 16; j++) {
                        fputc(_851903200C000000[j], output_file);
                    }
                }
                else if (compare_char(b, deadc0de00000000, 16) == true) {
                    for (j = 0; j < 16; j++) {
                        fputc(_851903200C000000[j], output_file);
                    }
                    putFF = true;
                }
                else {
                    for (j = 0; j < 16; j++) {
                        fputc(b[j], output_file);
                    }
                }
                i = i + 15;
            }
            else 
                fputc(fgetc(init_file), output_file);
        }
      //  printf("%ld\r", i);
    }

    fclose(init_file);
    fclose(output_file);
    //printf("\nDone!\n");
    return 0;
}



#define CHECK_FWUPDATE_ONLY

int main( )
{
    /*if (argc != 3) {
        printf("two arguments are needed here. please confirm the current firmware path and the new firmware path. \n");
        return -1;
    }*/

	FILE *current_fw, * current_fw_cut,*new_fw,*fpsha256old,*fpsha256new,*fpsha256newfirstboot;
	fw_info_t fw_info_test, * pst;
	pst = &fw_info_test;
	/*current_fw = fopen(argv[1], "rb");
	new_fw = fopen(argv[2], "rb");*/
	unsigned long i,j;
	char c;
	current_fw = fopen("/tmp/current_fw.bin", "rb");
	current_fw_cut = fopen("/tmp/current_fw_cut.bin", "wb");
	char hash_old[32],hash_old_singlechar[64];

	system("dd if=/dev/mtd8 of=/tmp/mtd8");//system("dd if=/dev/mtd6 of=/tmp/mtd6");

	fw_info_t* fwiold = (fw_info_t*)malloc(sizeof(fw_info_t));
	FILE* mtd8 = fopen("/tmp/mtd8", "rb");
	uint8_t* p1 = (uint8_t*)(&fwiold);
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		*(p1 + i) = fgetc(mtd8);
	}
	fwiold = (fw_info_t*)p1;
	fw_info_test.size_old = fwiold->size_new;// file_size2("/tmp/current_fw.bin") - file_size2("/tmp/mtd6") - 12582912 + 12583767;					//12583767;//12845911;//9700183;//15991639;
	fclose(mtd8);
	//remove("/tmp/mtd6");

#ifndef CHECK_FWUPDATE_ONLY
	for (i = 0; i < fw_info_test.size_old; i++) {
		c = fgetc(current_fw);
		fputc(c, current_fw_cut);
}
	fclose(current_fw_cut);
	fclose(current_fw);
	fpsha256old = popen("sha256sum /tmp/current_fw_cut.bin", "r");
	fgets(hash_old_singlechar, 65, fpsha256old);
	shastr64to0x32(hash_old_singlechar, hash_old);
	pclose(fpsha256old);
	for (i = 0; i < 64; i++)printf("%c", hash_old_singlechar[i]);
	printf("\n");
	/*for (i = 0; i < 32; i++)printf("%02x", hash_old[i]);
	printf("\n");*/
	//remove("/tmp/current_fw.bin");
#endif // !CHECK_FWUPDATE_ONLY

	

	char hash_new[32], hash_new_singlechar[64];
	fw_info_test.size_new = file_size2("/tmp/download_fw.bin");			//9438039;//12583767;//9700183;//12845911;//9700183;//15991639

#ifndef CHECK_FWUPDATE_ONLY
	make_mtd3();
	fpsha256new = popen("sha256sum /tmp/output_file.binmtd3", "r");
	fgets(hash_new_singlechar, 65, fpsha256new);
	shastr64to0x32(hash_new_singlechar, hash_new);
	pclose(fpsha256new);
	for (i = 0; i < 64; i++)printf("%c", hash_new_singlechar[i]);
	printf("\n");
	/*for (i = 0; i < 32; i++)printf("%02x", hash_new[i]);
	printf("\n");*/
	remove("/tmp/output_file.binmtd3");

#endif // !CHECK_FWUPDATE_ONLY



	char hash_new_firstboot[32], hash_new_firstboot_singlechar[64];
	fpsha256newfirstboot = popen("sha256sum /tmp/download_fw.bin", "r");
	fgets(hash_new_firstboot_singlechar, 65, fpsha256newfirstboot);
	shastr64to0x32(hash_new_firstboot_singlechar, hash_new_firstboot);
	pclose(fpsha256newfirstboot);
	for (i = 0; i < 64; i++)printf("%c", hash_new_firstboot_singlechar[i]);
	printf("\n");
	for (i = 0; i < 32; i++)printf("%02x", hash_new_firstboot[i]);
	printf("\n");
#ifdef CHECK_FWUPDATE_ONLY
	for (i = 0; i < 32; i++)hash_new[i] = hash_new_firstboot[i];
#endif // CHECK_FWUPDATE_ONLY



	
	fw_info_test.update = 0x01;
	fw_info_test.firstboot_tag = 1;

	copy_char_to_unsigned_char(hash_old, fw_info_test.hash_old);
	copy_char_to_unsigned_char(hash_new, fw_info_test.hash_new);
#ifndef CHECK_FWUPDATE_ONLY
	getsig_sign_and_print(privatekey_eg1, fw_info_test.hash_old, signature_old_eg1);
	getsig_sign_and_print(privatekey_eg1, fw_info_test.hash_new, signature_new_eg1);
#else // !CHECK_FWUPDATE_ONLY
	getsig_sign_no_print(privatekey_eg1, fw_info_test.hash_old, signature_old_eg1);
	getsig_sign_no_print(privatekey_eg1, fw_info_test.hash_new, signature_new_eg1);
#endif // !CHECK_FWUPDATE_ONLY
	copy_char_to_unsigned_char(hash_new_firstboot, fw_info_test.hash_new_firstboot);


	getsig_sign_and_print(privatekey_eg1, fw_info_test.hash_new_firstboot, signature_new_firstboot);




	FILE* mtd8_pubsig = fopen("/tmp/mtd8_1_big2small.bin", "wb");
	uint8_t*p = (uint8_t*)(&fw_info_test);
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		putc(p[i], mtd8_pubsig);
		/*printf("%02x ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}*/
	}
	//printf("\nsizeof(fw_info_t): %d\n", sizeof(fw_info_t));						//printf("there are three additional 00's here at the end of struct fw_info fw_info_t\n");

	for (i = 0; i < ECC_BYTES + 1; i++) {
		fputc(publickey_eg1[i], mtd8_pubsig);
	}
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_old_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_eg1[i], mtd8_pubsig);
	for (i = 0; i < ECC_BYTES * 2; i++) fputc(signature_new_firstboot[i], mtd8_pubsig);
	fclose(mtd8_pubsig);








#ifdef PRE_VERIFY_fwi
	fw_info_t* fwi = (fw_info_t*)malloc(sizeof(fw_info_t));
	printf("fw-info size: %d\n", sizeof(fw_info_t));
	FILE* mtd8 = fopen("mtd8_pubsig.bin", "rb");
	printf("fw-info raw: \n");
	for (i = 0; i < (sizeof(fw_info_t)); i++) {
		*(p + i) = fgetc(mtd8);
	}
	/*for (i = 0; i < (sizeof(fw_info_t)); i++) {
		printf("%02x ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}*/
	printf("\n\n");
	fwi = (fw_info_t*)p;

	uint8_t pubkey_get1[ECC_BYTES + 1];
	for (i = 0; i < ECC_BYTES + 1; i++) {
		pubkey_get1[i] = fgetc(mtd8);
	}

	uint8_t sig_old_get1[ECC_BYTES * 2];
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

	printf("fw-info data: ->update, ->size_old, ->size_new, fwi->firstboot_tag: %d %d %d %d\n", fwi->update, fwi->size_old, fwi->size_new, fwi->firstboot_tag);
	printf("hash_3: ");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_old + i)); printf("\n");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_new + i)); printf("\n");
	for (i = 0; i < 32; i++)printf("%02x ", *(fwi->hash_new_firstboot + i)); printf("\n");

	/*printf("pubkey: "); for (i = 0; i < ECC_BYTES + 1; i++)printf("%02x ", pubkey_get1[i]);
	printf("\nsig_old: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_old_get1[i]);
	printf("\nsig_new: "); for (i = 0; i < ECC_BYTES * 2; i++)printf("%02x ", sig_new_get1[i]);*/

	printf("\nsig_old:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_old, sig_old_get1);
	printf("sig_new:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_new, sig_new_get1);
	printf("sig_new_firstboot:"); signature_verify_by_pubkey_33(pubkey_get1, fwi->hash_new_firstboot, sig_new_firstboot_get);
	printf("\n");
	fclose(mtd8);


#endif // PRE_VERIFY_fwi


	printf("\tmake mtd8 Done.");
    return 0;
}


//  /home/qwer/openwrt19/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-8.4.0_musl/bin/mipsel-openwrt-linux-gcc make_mtd8_auto.cpp -o generatemtd8.out

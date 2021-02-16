/*
/home/qwer/openwrt19/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-8.4.0_musl/bin/mipsel-openwrt-linux-g++ make_kernel_dev_root.cpp -o make_kernel_dev_root.out
*/

#include <iostream>
#include<cstdlib>
#include<cstdio>
#include<cstring>
#include <sys/stat.h>  
#include <sys/statfs.h>
#define _CRT_SECURE_NO_WARNINGS

using namespace std;

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



int main()
{
	FILE* current_fw, * current_fw_cut, * fpsha256mtd3minusmtd6;
    system("dd if=/dev/mtd3 of=/tmp/mtd3");
    system("dd if=/dev/mtd6 of=/tmp/mtd6");
	current_fw = fopen("/tmp/mtd3", "rb");
	current_fw_cut = fopen("/tmp/mtd3_minus_mtd6.bin", "wb");
	int cutsize=file_size2("/tmp/mtd3") - file_size2("/tmp/mtd6");
	printf("cutsize: %d -%d = %d\n", file_size2("/tmp/mtd3"), file_size2("/tmp/mtd6"),cutsize);
	int i;
	char c, hash_old[32], hash_old_singlechar[64];
	for (i = 0; i < cutsize; i++) {
		c = fgetc(current_fw);
		fputc(c, current_fw_cut);
	}
	fclose(current_fw_cut);
	fclose(current_fw);
	fpsha256mtd3minusmtd6 = popen("sha256sum /tmp/mtd3_minus_mtd6.bin", "r");
	fgets(hash_old_singlechar, 65, fpsha256mtd3minusmtd6);
	shastr64to0x32(hash_old_singlechar, hash_old);
	pclose(fpsha256mtd3minusmtd6);
	for (i = 0; i < 64; i++)printf("%c", hash_old_singlechar[i]);
	printf("\n");
	/*for (i = 0; i < 32; i++)printf("%x", hash_old[i]);
	printf("\n");*/


    return 0;
}


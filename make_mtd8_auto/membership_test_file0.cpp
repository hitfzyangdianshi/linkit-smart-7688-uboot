#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <time.h> 
#include <sys/stat.h>  
//#include <sys/statfs.h>
#include "../ecdsa_lightweight/easy_ecc_main.c"
#include "../include/image.h"
#define _CRT_SECURE_NO_WARNINGS

#include "sha256.h"


int copy_unsigned_char_to_unsigned_char(uint8_t in[], uint8_t out[], int length) {
	int i;
	for (i = 0; i < length; i++) {
		out[i] = in[i];
	}
	return 0;
}

uint8_t p_privateKey0[10][ECC_BYTES];
uint8_t p_privateKey1[10][ECC_BYTES];
uint8_t p_privateKey2[10][ECC_BYTES];
uint8_t p_privateKey3[10][ECC_BYTES];

int main()
{
	printf("generate membership info init0...\n");
	int i;

	FILE* fwi;
	fwi = fopen("fwi.bin", "wb");
	fw_info_t fwinfoformem;
	fwinfoformem.membership_update = 1;
	fwinfoformem.update = 0;
	uint8_t* pfwi = (uint8_t*)(&fwinfoformem);
	for (i = 0; i < sizeof(fw_info_t); i++) {
		fputc(pfwi[i], fwi);
	}
	fclose(fwi);




	FILE* f0;
	f0 = fopen("f0.bin", "wb");

	membership_info_t meminit;
	memset((void*)&meminit, 0, sizeof(membership_info_t));
	meminit.version = 0;
	meminit.including_next =0;


	for(i=0;i<10;i++)
		ecc_make_key(meminit.pubkeys[i], p_privateKey0[i]);

	uint8_t* p = (uint8_t*)(&meminit);
	for (i = 0; i < sizeof(membership_info_t); i++)
		fputc(p[i], f0);
	

	fclose(f0);


	
	
	printf("generate membership info 1 ... ...\n");

	FILE* fi;
	fi = fopen("fi.bin", "wb");

	
	membership_info_t m1;
	m1.version = 1;
	m1.including_next =1;


	uint8_t sha256hash[32];
	uint8_t* q = (uint8_t*)&m1;

	for (i = 0; i < 10; i++) {
		ecc_make_key(m1.pubkeys[i], p_privateKey1[i]);
	}

	sha256_csum_wd(q, sizeof(uint32_t) + 10 * 33 * sizeof(uint8_t), sha256hash, CHUNKSZ_SHA256);
	for (i = 0; i < 32; i++)printf("%02x", sha256hash[i]);
	printf("\n");

	for (i = 0; i < 10; i++) {
		m1.sigs_tag[i] = 1;
		ecdsa_sign(p_privateKey0[i], sha256hash, m1.sigs[i]);
		signature_verify_by_pubkey_33(meminit.pubkeys[i], sha256hash, m1.sigs[i]);
	}

	

	for (i = 0; i < sizeof(membership_info_t); i++)
		fputc(q[i], fi);





	/*************************************************************************/
	membership_info_t m2;
	m2.version = 2;
	m2.including_next = 1;

	q = (uint8_t*)&m2;

	for (i = 0; i < 10; i++) {
		ecc_make_key(m2.pubkeys[i], p_privateKey2[i]);
	}

	sha256_csum_wd(q, sizeof(uint32_t) + 10 * 33 * sizeof(uint8_t), sha256hash, CHUNKSZ_SHA256);
	for (i = 0; i < 32; i++)printf("%02x", sha256hash[i]);
	printf("\n");

	for (i = 0; i < 10; i++) {
		m2.sigs_tag[i] = 1;
		ecdsa_sign(p_privateKey1[i], sha256hash, m2.sigs[i]);
		signature_verify_by_pubkey_33(m1.pubkeys[i], sha256hash, m2.sigs[i]);
	}


	for (i = 0; i < sizeof(membership_info_t); i++)
		fputc(q[i], fi);



	/*************************************************************************/
	membership_info_t m3;
	m3.version = 3;
	m3.including_next = 0;

	q = (uint8_t*)&m3;

	for (i = 0; i < 10; i++) {
		ecc_make_key(m3.pubkeys[i], p_privateKey3[i]);
	}

	sha256_csum_wd(q, sizeof(uint32_t) + 10 * 33 * sizeof(uint8_t), sha256hash, CHUNKSZ_SHA256);
	for (i = 0; i < 32; i++)printf("%02x", sha256hash[i]);
	printf("\n");

	for (i = 0; i < 10; i++) {
		m3.sigs_tag[i] = 1;
		ecdsa_sign(p_privateKey2[i], sha256hash, m3.sigs[i]);
		signature_verify_by_pubkey_33(m2.pubkeys[i], sha256hash, m3.sigs[i]);
	}


	for (i = 0; i < sizeof(membership_info_t); i++)
		fputc(q[i], fi);









	fclose(fi);



/*	printf("test\n");

	membership_info_t* meminfo_current = (membership_info_t*)malloc(sizeof(membership_info_t));
	uint8_t* r0 = (uint8_t*)meminfo_current;
	FILE* t0 = fopen("f0.bin", "rb");
	for (i = 0; i < sizeof(membership_info_t); i++) {
		*(r0 + i) = fgetc(t0);
	}
	uint32_t current_version = meminfo_current->version;
	uint8_t (*current_pubkeys)[33]  = meminfo_current->pubkeys;


	membership_info_t* meminfo_new =(membership_info_t*) malloc(sizeof(membership_info_t));
	uint8_t* r1 = (uint8_t*)meminfo_new;
	FILE* t1 = fopen("fi.bin", "rb");
	for (i = 0; i < sizeof(membership_info_t); i++) {
		*(r1 + i) = fgetc(t1);
	}
	uint32_t new_version = meminfo_new->version;
	uint8_t (* new_pubkeys)[33] = meminfo_new->pubkeys;
	uint8_t (* new_sig )[64]= meminfo_new->sigs;
	uint32_t	  including_next = meminfo_new->including_next;
	uint8_t* new_sigs_tag = meminfo_new->sigs_tag;



	uint32_t version0 = current_version, version1 = new_version;
	uint8_t (* keys0 )[33]= meminfo_current->pubkeys;
	uint8_t(* keys1)[33] = meminfo_new->pubkeys;
	uint8_t (* sig0)[64];
	uint8_t (* sig1)[64] = meminfo_new->sigs;

	sha256_csum_wd(r1, sizeof(uint32_t) + 10 * 33 * sizeof(uint8_t), sha256hash, CHUNKSZ_SHA256);

	for (i = 0; i < 32; i++)	printf("%02x", sha256hash[i]);

	signature_verify_by_pubkey_33(keys0[0], sha256hash, sig1[0]);


	
	current_version = meminfo_current->version;
	current_pubkeys = meminfo_current->pubkeys;

	new_version = meminfo_new->version;
	new_pubkeys = meminfo_new->pubkeys;
	new_sig = meminfo_new->sigs;
	including_next = meminfo_new->including_next;
	new_sigs_tag = meminfo_new->sigs_tag;


	version0 = current_version; 	version1 = new_version;
	keys0 = current_pubkeys; 		keys1 = new_pubkeys;
	sig1 = new_sig;

	signature_verify_by_pubkey_33(keys0[0], sha256hash, sig1[0]);*/

	












	return 0;
}
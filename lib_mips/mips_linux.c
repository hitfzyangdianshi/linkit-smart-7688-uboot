/*
 * (C) Copyright 2003
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <common.h>
#include <command.h>
#include <image.h>
#include <zlib.h>
#include <asm/byteorder.h>
#include <asm/addrspace.h>

#define	LINUX_MAX_ENVS		256
#define	LINUX_MAX_ARGS		256

#ifdef CONFIG_SHOW_BOOT_PROGRESS
# include <status_led.h>
# define SHOW_BOOT_PROGRESS(arg)	show_boot_progress(arg)
#else
# define SHOW_BOOT_PROGRESS(arg)
#endif

extern image_header_t header;           /* from cmd_bootm.c */

extern int do_reset (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[]);

static int	linux_argc;
static char **	linux_argv;

static char **	linux_env;
static char *	linux_env_p;
static int	linux_env_idx;

static void linux_params_init (ulong start, char * commandline);
static void linux_env_set (char * env_name, char * env_val);


void do_bootm_linux (cmd_tbl_t * cmdtp, int flag, int argc, char *argv[],
		     ulong addr, ulong * len_ptr, int verify)
{
	DECLARE_GLOBAL_DATA_PTR;

	ulong len = 0, checksum;
	ulong initrd_start, initrd_end;
	ulong data;
	void (*theKernel) (int, char **, char **, int *);
	image_header_t *hdr = &header;
	char *commandline = getenv ("bootargs");
	char env_buf[12];
	int i;

	theKernel =
		(void (*)(int, char **, char **, int *)) ntohl (hdr->ih_ep);

	/*
	 * Check if there is an initrd image
	 */
	if (argc >= 3) {
		SHOW_BOOT_PROGRESS (9);

		addr = simple_strtoul (argv[2], NULL, 16);

		printf ("## Loading Ramdisk Image at %08lx ...\n", addr);

		/* Copy header so we can blank CRC field for re-calculation */
		memcpy (&header, (char *) addr, sizeof (image_header_t));

		if (ntohl (hdr->ih_magic) != IH_MAGIC) {
			printf ("Bad Magic Number\n");
			SHOW_BOOT_PROGRESS (-10);
			do_reset (cmdtp, flag, argc, argv);
		}

		data = (ulong) & header;
		len = sizeof (image_header_t);

		checksum = ntohl (hdr->ih_hcrc);
		hdr->ih_hcrc = 0;

		if (crc32 (0, (char *) data, len) != checksum) {
			printf ("Bad Header Checksum\n");
			SHOW_BOOT_PROGRESS (-11);
			do_reset (cmdtp, flag, argc, argv);
		}

		SHOW_BOOT_PROGRESS (10);

		print_image_hdr (hdr);

		data = addr + sizeof (image_header_t);
		len = ntohl (hdr->ih_size);

		if (verify) {
			ulong csum = 0;

			printf ("   Verifying Checksum ... ");
			csum = crc32 (0, (char *) data, len);
			if (csum != ntohl (hdr->ih_dcrc)) {
				printf ("Bad Data CRC\n");
				SHOW_BOOT_PROGRESS (-12);
				do_reset (cmdtp, flag, argc, argv);
			}
			printf ("OK\n");
		}

		SHOW_BOOT_PROGRESS (11);

		if ((hdr->ih_os != IH_OS_LINUX) ||
		    (hdr->ih_arch != IH_CPU_MIPS) ||
		    (hdr->ih_type != IH_TYPE_RAMDISK)) {
			printf ("No Linux MIPS Ramdisk Image\n");
			SHOW_BOOT_PROGRESS (-13);
			do_reset (cmdtp, flag, argc, argv);
		}

		/*
		 * Now check if we have a multifile image
		 */
	} else if ((hdr->ih_type == IH_TYPE_MULTI) && (len_ptr[1])) {
		ulong tail = ntohl (len_ptr[0]) % 4;
		int i;

		SHOW_BOOT_PROGRESS (13);

		/* skip kernel length and terminator */
		data = (ulong) (&len_ptr[2]);
		/* skip any additional image length fields */
		for (i = 1; len_ptr[i]; ++i)
			data += 4;
		/* add kernel length, and align */
		data += ntohl (len_ptr[0]);
		if (tail) {
			data += 4 - tail;
		}

		len = ntohl (len_ptr[1]);

	} else {
		/*
		 * no initrd image
		 */
		SHOW_BOOT_PROGRESS (14);

		data = 0;
	}

#ifdef	DEBUG
	if (!data) {
		printf ("No initrd\n");
	}
#endif

	if (data) {
		initrd_start = data;
		initrd_end = initrd_start + len;
	} else {
		initrd_start = 0;
		initrd_end = 0;
	}

	SHOW_BOOT_PROGRESS (15);

#ifdef DEBUG
	printf ("## Transferring control to Linux (at address %08lx) ...\n",
		(ulong) theKernel);
#endif

	linux_params_init (UNCACHED_SDRAM (gd->bd->bi_boot_params), commandline);

#ifdef CONFIG_MEMSIZE_IN_BYTES
	sprintf (env_buf, "%lu", gd->ram_size);
#ifdef DEBUG
	printf ("## Giving linux memsize in bytes, %lu\n", gd->ram_size);
#endif
#else
	sprintf (env_buf, "%lu", gd->ram_size >> 20);
#ifdef DEBUG
	printf ("## Giving linux memsize in MB, %lu\n", gd->ram_size >> 20);
#endif
#endif /* CONFIG_MEMSIZE_IN_BYTES */

	linux_env_set ("memsize", env_buf);

	sprintf (env_buf, "0x%08X", (uint) UNCACHED_SDRAM (initrd_start));
	linux_env_set ("initrd_start", env_buf);

	sprintf (env_buf, "0x%X", (uint) (initrd_end - initrd_start));
	linux_env_set ("initrd_size", env_buf);

	sprintf (env_buf, "0x%08X", (uint) (gd->bd->bi_flashstart));
	linux_env_set ("flash_start", env_buf);

	sprintf (env_buf, "0x%X", (uint) (gd->bd->bi_flashsize));
	linux_env_set ("flash_size", env_buf);

	for (i = 1; i < linux_argc; i++)
		linux_argv[i] = KSEG0ADDR(linux_argv[i]);
	linux_argv = KSEG0ADDR(linux_argv);
	for (i = 0; i < linux_env_idx; i++)
		linux_env[i] = KSEG0ADDR(linux_env[i]);
	linux_env = KSEG0ADDR(linux_env);

	/* we assume that the kernel is in place */
	printf ("\nStarting kernel ...\n\n");
	printf("checkpoint /lib_mips/mips_linux.c, do_bootm_linux(), line223\n\n");

//#define TEST_DCDSA_OPENSSL_01
#ifdef TEST_DCDSA_OPENSSL_01
#include "../ecdsa/ecdsa_f.c"
	char digest[] = "11111111111111111111111111111111";
	char* privatekey = "\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIIKLAYVVQVLBq6ZXeJuzblt7a1caKaiibD3q8X3NNLH1oAoGCCqGSM49\n\
AwEHoUQDQgAEk3tdHSfsp+js0THokxaDtSye9AXavB+0KVuXCuzRKqMgc7EfOkLn\n\
m2CqbE4xKDAqlybrUDyYh4ocfbQEkt2r1A==\n\
-----END EC PRIVATE KEY-----";
	char* publickey = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3tdHSfsp+js0THokxaDtSye9AXa\n\
vB+0KVuXCuzRKqMgc7EfOkLnm2CqbE4xKDAqlybrUDyYh4ocfbQEkt2r1A==\n\
-----END PUBLIC KEY-----";
	char signature_test0[71] = {
0x30 , 0x45 , 0x02 , 0x20 , 0x5B , 0xDA , 0x92 , 0x9D ,
0xFA , 0x81 , 0x26 , 0xB2 , 0x49 , 0x24 , 0x96 , 0xB4 ,
0x63 , 0x49 , 0xD1 , 0x6D , 0x09 , 0x61 , 0xBA , 0x50 ,
0x84 , 0x8F , 0xED , 0x77 , 0x49 , 0xE6 , 0x8E , 0x6B ,
0x82 , 0xE9 , 0x04 , 0x73 , 0x02 , 0x21 , 0x00 , 0xE7 ,
0x7B , 0x68 , 0xCF , 0x24 , 0xBC , 0xD4 , 0xF0 , 0x1B ,
0x85 , 0x13 , 0xD0 , 0xA1 , 0x64 , 0x34 , 0xB2 , 0x3B ,
0x38 , 0x18 , 0x0A , 0x95 , 0x7F , 0xF7 , 0x31 , 0x73 ,
0x82 , 0x15 , 0xE1 , 0x63 , 0x6A , 0xCB , 0x20 };

	printf("\n\ntest ecdsa_verify_signature: \n");
	ecdsa_verify_signature(publickey, signature_test0, sizeof(signature_test0), digest);
#endif // TEST_DCDSA_OPENSSL_01

#define TEST_EASY_ECC_01
#ifdef TEST_EASY_ECC_01
#include "../ecdsa_lightweight/easy_ecc_main.c"
	//unsigned char  digest[] = "11111111111111111111111111111111";
	unsigned char current_hash_test[] = "e7eb4cd2a61df11fa56bdcb2e8744f668810311676d3d50b205f5ee78b1fdf6f";

	int re;
	

	/*uint8_t privatekey_example1[] = { 0x27,0xeb,0xcf,0x70,0xac,0xae,0xcb,0x1c,
									  0x4b,0xd8,0x74,0xe2,0x9e,0x13,0xb7,0xb2,
		0x58,0xb9,0x49,0x8c,0xbd,0xbd,0x1a,0xfd,
		0xb2,0xc0,0x13,0xdf,0x65,0x8f,0xcc,0xb9 };*/

	uint8_t publickey_example1[] = { 0x02, 0x68, 0xC0, 0xC8, 0x1D, 0x72, 0x85, 0x67,
		0x22, 0xE0, 0x37, 0x38, 0xA7, 0xB4, 0x6C, 0x11,
		0x62, 0x85, 0xC1, 0xA3, 0xA8, 0x50, 0xEE, 0xFC,
		0x84, 0xA6, 0xE7, 0x47, 0x78, 0x1F, 0x22, 0x1D,
		0x0A };
	uint8_t signature_eg1[] = { 0x04, 0xD9, 0x04, 0x6B, 0xC1, 0x9D, 0xAF, 0xA2, 0xEC, 0xF0, 0xA8, 0x14, 0x0B, 0x57, 0xAF, 0xDC, 0x90, 0xA5, 0x0B, 0xBB, 0x3B, 0x77, 0xC1, 0xDC, 0xC6, 0x44, 0xB2, 0x47, 0xAC, 0x93, 0xCE, 0xB6, 0x75, 0x34, 0x37, 0x0E, 0x27, 0x8A, 0xA0, 0xC0, 0x45, 0xE9, 0xEE, 0xB0, 0xED, 0xD7, 0x3C, 0x64, 0x5B, 0xEF, 0x57, 0x18, 0x95, 0x77, 0x2B, 0x55, 0x58, 0x71, 0x5E, 0xF9, 0x10, 0xBE, 0x5F, 0x3D };
	//sign_and_print(privatekey_example1, current_hash_test);
	signature_verify_by_pubkey_33(publickey_example1, current_hash_test, signature_eg1);


	/*uint8_t privatekey_eg2[] = { 0xf5,0x63,0xd4,0xb6,0xad,0x80,0x0e,0x85,
		0xec,0xd5,0xef,0x8d,0xe7,0x37,0xf4,0x87,
		0xe4,0xf4,0x2b,0x42,0x30,0x14,0xa1,0x39,
		0x15,0xe9,0x7f,0x97,0xe1,0xdf,0xe9,0xb3 };*/
	uint8_t publickey_eg2[] = { 0x03 , 0x03 , 0xEC , 0xBE , 0x5A , 0x0E , 0x9A , 0xF7 , // ECC_BYTES + 1
		0xAD , 0xDC , 0x15 , 0x34 , 0x9B , 0x96 , 0x3B , 0x29 ,
		0xC7 , 0x24 , 0x36 , 0x5E , 0x24 , 0xDE , 0x2E , 0xE9 ,
		0x92 , 0x7C , 0x11 , 0xE9 , 0x2D , 0xF5 , 0xA4 , 0xE1 , 0x80 };
	//getpublickey(publickey_eg2, privatekey_eg2);
	//sign_and_print(privatekey_eg2, current_hash_test);
	uint8_t signature_eg2[] = { 0x57, 0x7E, 0x82, 0x87, 0x72, 0xB8, 0xC4, 0xD7, 0x70, 0xC9, 0xEA, 0xD2, 0x13, 0x66, 0x94, 0x95, 0x63, 0x22, 0xD2, 0x2A, 0x01, 0x59, 0x9C, 0x00, 0x4F, 0x7C, 0xAB, 0xBB, 0x68, 0xB7, 0x84, 0x59, 0x01, 0x76, 0x5F, 0x66, 0xFF, 0xA1, 0xF1, 0xEC, 0xFC, 0x35, 0x00, 0x18, 0x42, 0x9A, 0x46, 0xC9, 0x30, 0x7B, 0x31, 0x41, 0xAE, 0x9B, 0xFE, 0xC8, 0xC6, 0x9C, 0x20, 0x9F, 0x8F, 0x5A, 0x36, 0xDC };
	signature_verify_by_pubkey_33(publickey_eg2, current_hash_test, signature_eg2);

	/*uint8_t privatekey_eg3[] = { 0xc3,0xe0,0x3d,0x91,0xe8,0x12,0x7d,0xdd,
		0x93,0x86,0xd7,0x37,0xde,0xcc,0x18,0x24,
		0xb7,0xb1,0xe9,0x42,0x66,0x91,0xeb,0x9f,
		0x7d,0xb5,0x80,0x3c,0xf5,0x8f,0x09,0xc7 };*/
	uint8_t publickey_eg3[] = { 0x03, 0x25, 0xA7, 0x91, 0xC4, 0x0B, 0x2B, 0xBB,
		0x90, 0xC6, 0x9B, 0xA4, 0x09, 0x21, 0x44, 0x77,
		0x4D, 0x54, 0x88, 0xB7, 0x01, 0x39, 0x19, 0x8D,
		0x4F, 0x7A, 0x49, 0x6A, 0xDF, 0xFE, 0xD2, 0xF1, 0x13 }; //ECC_BYTES + 1
	//getpublickey(publickey_eg3, privatekey_eg3);
	//sign_and_print(privatekey_eg3, current_hash_test);
	uint8_t signature_eg3[] = { 0x6E, 0xFD, 0x7A, 0x4D, 0x4C, 0x0F, 0x8D, 0x46, 0x6E, 0xB8, 0x37, 0x6D, 0x83, 0x84, 0xD3, 0xC9, 0x98, 0x4E, 0xF9, 0x0F, 0x20, 0x95, 0x60, 0xA9, 0x59, 0x58, 0xC8, 0xC0, 0x31, 0x14, 0x29, 0x3A, 0x0D, 0xB1, 0x82, 0x9F, 0xD8, 0xB8, 0x5B, 0xF7, 0xD6, 0xCA, 0x06, 0xFF, 0x73, 0xFB, 0x74, 0x4B, 0xC9, 0x24, 0xF8, 0x40, 0xA3, 0xA4, 0x91, 0x89, 0xD0, 0x8C, 0x55, 0x20, 0xE3, 0xD5, 0x08, 0x80 };
	signature_verify_by_pubkey_33(publickey_eg3, current_hash_test, signature_eg3);


	/*uint8_t privatekey_eg4[] = { 0xcc,0x62,0x7f,0xd3,0x99,0xae,0xcc,0x8b,
		0x48,0x9d,0x29,0xf8,0x77,0xa4,0x05,0xea,
		0xd0,0xa7,0x8c,0x51,0xae,0x47,0xc6,0xb9,
		0x49,0xa6,0x8f,0xa7,0xa8,0xa2,0x27,0x11 };*/
	uint8_t publickey_eg4[] = { 0x03 , 0x75 , 0x60 , 0x99 , 0x3B , 0x5F , 0x74 , 0xCF ,
		0x10 , 0xD7 , 0x7F , 0x9F , 0x96 , 0x9E , 0x37 , 0x5E ,
		0x21 , 0x73 , 0x43 , 0x15 , 0xAA , 0x11 , 0xEE , 0x13 ,
		0x12 , 0x21 , 0x13 , 0x7B , 0x8C , 0x83 , 0x76 , 0xEA , 0x7F };// ECC_BYTES + 1
	//getpublickey(publickey_eg4, privatekey_eg4);
	//sign_and_print(privatekey_eg4, current_hash_test);
	uint8_t signature_eg4[] = { 0x20, 0xAE, 0x6F, 0x84, 0xDD, 0x85, 0xFF, 0x0A, 0x21, 0x1C, 0x25, 0x18, 0x71, 0x03, 0xF2, 0x97, 0xEE, 0x6B, 0xD1, 0x89, 0x0B, 0xB1, 0x71, 0x76, 0x1A, 0xBB, 0x43, 0x20, 0x96, 0x3B, 0xBE, 0x1A, 0xED, 0x6F, 0xEF, 0xF0, 0x60, 0x05, 0x67, 0xFF, 0xC0, 0xBD, 0xF6, 0x50, 0xDC, 0x1B, 0xFC, 0x22, 0xAD, 0x40, 0x95, 0xB8, 0x4B, 0x18, 0x9F, 0x34, 0xE8, 0xB7, 0x40, 0x86, 0x34, 0xCF, 0xC5, 0x34 };
	signature_verify_by_pubkey_33(publickey_eg4, current_hash_test, signature_eg4);


//{
//PrivKey: "MHcCAQEEICfrz3CsrsscS9h04p4Tt7JYuUmMvb0a/bLAE99lj8y5oAoGCCqGSM49AwEHoUQDQgAEaMDIHXKFZyLgNzintGwRYoXBo6hQ7vyEpudHeB8iHQr9n1fffwkJP3nIBm5TD9XEUjk72rAZEbylkSJOekTW0A==",
//PubKey : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaMDIHXKFZyLgNzintGwRYoXBo6hQ7vyEpudHeB8iHQr9n1fffwkJP3nIBm5TD9XEUjk72rAZEbylkSJOekTW0A==",
//},
//SEQUENCE
//INTEGER 01..(total 1bytes)..01
//OCTETSTRING 27ebcf70acaecb1c4bd874e29e13b7b258b9498cbdbd1afdb2c013df658fccb9..(total 32bytes)..27ebcf70acaecb1c4bd874e29e13b7b258b9498cbdbd1afdb2c013df658fccb9
//[0]
//ObjectIdentifier secp256r1(1 2 840 10045 3 1 7)
//[1]
//BITSTRING 000468c0c81d72856722e03738a7b46c116285c1a3a850eefc84a6e747781f221d0afd9f57df7f09093f79c8066e530fd5c452393bdab01911bca591224e7a44d6d0..(total 66bytes)..000468c0c81d72856722e03738a7b46c116285c1a3a850eefc84a6e747781f221d0afd9f57df7f09093f79c8066e530fd5c452393bdab01911bca591224e7a44d6d0


//	{
//		PrivKey: "MHcCAQEEIPVj1LatgA6F7NXvjec39Ifk9CtCMBShORXpf5fh3+mzoAoGCCqGSM49AwEHoUQDQgAEA+y+Wg6a963cFTSbljspxyQ2XiTeLumSfBHpLfWk4YB0OoQP/0e406cvXlvB0kHwejQrOQ4+cjAzpTwbZATbew==",
//		PubKey : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEA+y+Wg6a963cFTSbljspxyQ2XiTeLumSfBHpLfWk4YB0OoQP/0e406cvXlvB0kHwejQrOQ4+cjAzpTwbZATbew==",
//	},
//SEQUENCE
//INTEGER 01..(total 1bytes)..01
//OCTETSTRING f563d4b6ad800e85ecd5ef8de737f487e4f42b423014a13915e97f97e1dfe9b3..(total 32bytes)..f563d4b6ad800e85ecd5ef8de737f487e4f42b423014a13915e97f97e1dfe9b3
//[0]
//ObjectIdentifier secp256r1(1 2 840 10045 3 1 7)
//[1]
//BITSTRING 000403ecbe5a0e9af7addc15349b963b29c724365e24de2ee9927c11e92df5a4e180743a840fff47b8d3a72f5e5bc1d241f07a342b390e3e723033a53c1b6404db7b..(total 66bytes)..000403ecbe5a0e9af7addc15349b963b29c724365e24de2ee9927c11e92df5a4e180743a840fff47b8d3a72f5e5bc1d241f07a342b390e3e723033a53c1b6404db7b


//	{
//		PrivKey: "MHcCAQEEIMPgPZHoEn3dk4bXN97MGCS3selCZpHrn321gDz1jwnHoAoGCCqGSM49AwEHoUQDQgAEJaeRxAsru5DGm6QJIUR3TVSItwE5GY1Peklq3/7S8RO3JK7pCvbDfv4UpB/fjpN5g9Q5Xq4LreLf6RuGBxfxpw==",
//		PubKey : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJaeRxAsru5DGm6QJIUR3TVSItwE5GY1Peklq3/7S8RO3JK7pCvbDfv4UpB/fjpN5g9Q5Xq4LreLf6RuGBxfxpw==",
//	},
//SEQUENCE
//INTEGER 01..(total 1bytes)..01
//OCTETSTRING c3e03d91e8127ddd9386d737decc1824b7b1e9426691eb9f7db5803cf58f09c7..(total 32bytes)..c3e03d91e8127ddd9386d737decc1824b7b1e9426691eb9f7db5803cf58f09c7
//[0]
//ObjectIdentifier secp256r1(1 2 840 10045 3 1 7)
//[1]
//BITSTRING 000425a791c40b2bbb90c69ba4092144774d5488b70139198d4f7a496adffed2f113b724aee90af6c37efe14a41fdf8e937983d4395eae0bade2dfe91b860717f1a7..(total 66bytes)..000425a791c40b2bbb90c69ba4092144774d5488b70139198d4f7a496adffed2f113b724aee90af6c37efe14a41fdf8e937983d4395eae0bade2dfe91b860717f1a7


//	{
//		PrivKey: "MHcCAQEEIMxif9OZrsyLSJ0p+HekBerQp4xRrkfGuUmmj6eooicRoAoGCCqGSM49AwEHoUQDQgAEdWCZO190zxDXf5+WnjdeIXNDFaoR7hMSIRN7jIN26n94vtHj+czclJ4GX3qsq/9fKENl5zAMudrfwSOnjBiTtw==",
//		PubKey : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdWCZO190zxDXf5+WnjdeIXNDFaoR7hMSIRN7jIN26n94vtHj+czclJ4GX3qsq/9fKENl5zAMudrfwSOnjBiTtw==",
//	},
//SEQUENCE
//INTEGER 01..(total 1bytes)..01
//OCTETSTRING cc627fd399aecc8b489d29f877a405ead0a78c51ae47c6b949a68fa7a8a22711..(total 32bytes)..cc627fd399aecc8b489d29f877a405ead0a78c51ae47c6b949a68fa7a8a22711
//[0]
//ObjectIdentifier secp256r1(1 2 840 10045 3 1 7)
//[1]
//BITSTRING 00047560993b5f74cf10d77f9f969e375e21734315aa11ee131221137b8c8376ea7f78bed1e3f9ccdc949e065f7aacabff5f284365e7300cb9dadfc123a78c1893b7..(total 66bytes)..00047560993b5f74cf10d77f9f969e375e21734315aa11ee131221137b8c8376ea7f78bed1e3f9ccdc949e065f7aacabff5f284365e7300cb9dadfc123a78c1893b7

//https://gchq.github.io/CyberChef/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,33)&input=TUhjQ0FRRUVJQ2ZyejNDc3Jzc2NTOWgwNHA0VHQ3Sll1VW1NdmIwYS9iTEFFOTlsajh5NW9Bb0dDQ3FHU000OUF3RUhvVVFEUWdBRWFNRElIWEtGWnlMZ056aW50R3dSWW9YQm82aFE3dnlFcHVkSGVCOGlIUXI5bjFmZmZ3a0pQM25JQm01VEQ5WEVVams3MnJBWkVieWxrU0pPZWtUVzBBPT0


#endif //TEST_EASY_ECC_01


#define TEST_READ_USB_FILE
#ifdef TEST_READ_USB_FILE
	//refer to board.c line2401

#if defined (RALINK_USB ) || defined (MTK_USB)
	extern int usb_stor_curr_dev;
#endif
	char addr_str[11];

	argc = 2;
	argv[1] = "start";
	do_usb(cmdtp, flag, argc, argv);
	if (usb_stor_curr_dev < 0) {
		printf("No USB Storage found.Reading key/sig file failed.\n");
	}

	argc = 5;
	argv[1] = "usb";
	argv[2] = "0";
	sprintf(addr_str, "0x%X", CFG_LOAD_ADDR);
	argv[3] = &addr_str[0];
	argv[4] = "publickey1.file";
	
	if (do_fat_fsload(cmdtp, 0, argc, argv)) {
		printf("Could not find publickey1.file\n");
	}
	else {
		printf("Find publickey1.file\n");
	}

	argc = 2;
	argv[1] = "stop";
	do_usb(cmdtp, flag, argc, argv);



#endif // TEST_READ_USB_FILE


	theKernel (linux_argc, linux_argv, linux_env, 0);
}

static void linux_params_init (ulong start, char *line)
{
	char *next, *quote, *argp;

	linux_argc = 1;
	linux_argv = (char **) start;
	linux_argv[0] = 0;
	argp = (char *) (linux_argv + LINUX_MAX_ARGS);

	next = line;

	while (line && *line && linux_argc < LINUX_MAX_ARGS) {
		quote = strchr (line, '"');
		next = strchr (line, ' ');

		while (next != NULL && quote != NULL && quote < next) {
			/* we found a left quote before the next blank
			 * now we have to find the matching right quote
			 */
			next = strchr (quote + 1, '"');
			if (next != NULL) {
				quote = strchr (next + 1, '"');
				next = strchr (next + 1, ' ');
			}
		}

		if (next == NULL) {
			next = line + strlen (line);
		}

		linux_argv[linux_argc] = argp;
		memcpy (argp, line, next - line);
		argp[next - line] = 0;

		argp += next - line + 1;
		linux_argc++;

		if (*next)
			next++;

		line = next;
	}

	linux_env = (char **) (((ulong) argp + 15) & ~15);
	linux_env[0] = 0;
	linux_env_p = (char *) (linux_env + LINUX_MAX_ENVS);
	linux_env_idx = 0;
}

static void linux_env_set (char *env_name, char *env_val)
{
	if (linux_env_idx < LINUX_MAX_ENVS - 1) {
		linux_env[linux_env_idx] = linux_env_p;

		strcpy (linux_env_p, env_name);
		linux_env_p += strlen (env_name);

		strcpy (linux_env_p, "=");
		linux_env_p += 1;

		strcpy (linux_env_p, env_val);
		linux_env_p += strlen (env_val);

		linux_env_p++;
		linux_env[++linux_env_idx] = 0;
	}
}

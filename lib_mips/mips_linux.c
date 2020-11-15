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

//#define TEST_DCDSA_01
#ifdef TEST_DCDSA_01
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
#endif // TEST_DCDSA_01

#define TEST_EASY_ECC
#ifdef TEST_EASY_ECC
#include "../ecdsa_lightweight/ecc.c"
	unsigned char  digest[] = "11111111111111111111111111111111";
	int re;
	uint8_t publickey_example1[] = { 0x03 , 0x37 , 0xFE , 0x9A , 0xE4 , 0x85 , 0xEE , 0x20 ,
		0xFE , 0xF2 , 0x1D , 0xD4 , 0x5A , 0x6F , 0x6B , 0x0C ,
		0xB7 , 0xF0 , 0x7E , 0x50 , 0x97 , 0xE2 , 0xF4 , 0xA5 ,
		0x13 , 0x9E , 0x9B , 0x45 , 0xFE , 0x9A , 0x28 , 0xF6 ,
		0x51 };
	uint8_t privatekey_example1[] = { 0xF1, 0x2B, 0x87, 0x38, 0x9F, 0x88, 0xB4, 0xF7,
		0xF2, 0x11, 0xDB, 0xE9, 0xFA, 0x77, 0x8C, 0xD8,
		0xC2, 0x92, 0x46, 0xAC, 0x63, 0x42, 0x10, 0x82,
		0x5A, 0x74, 0x97, 0x69, 0xA2, 0x3C, 0xD1, 0xC0 };
	uint8_t signature_example[] = { 0x81 , 0xB3 , 0xE0 , 0x20 , 0x5B , 0xD5 , 0x3A , 0xCA ,
		0x38 , 0x3C , 0xB3 , 0x08 , 0x49 , 0xDF , 0x7B , 0xE4 ,
		0xA9 , 0xF1 , 0xD9 , 0xE4 , 0xF5 , 0x4E , 0xE6 , 0x3F ,
		0x22 , 0x55 , 0x7C , 0x8D , 0x8D , 0x31 , 0x84 , 0xBC ,
		0x50 , 0xF7 , 0x0A , 0xE7 , 0x84 , 0x96 , 0x9A , 0xCE ,
		0x6F , 0x93 , 0x2C , 0x58 , 0xFF , 0xE6 , 0xCA , 0x9F ,
		0xC3 , 0x99 , 0x34 , 0xAA , 0x90 , 0x9E , 0x03 , 0xEF ,
		0x6A , 0x1A , 0xA8 , 0x9F , 0xEB , 0x35 , 0x3C , 0x50 };
	re = ecdsa_verify(publickey_example1, digest, signature_example);
	if (re == 1)printf("eg1 valid\n");
	else printf("eg1 INvalid\n");

#endif //TEST_EASY_ECC


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

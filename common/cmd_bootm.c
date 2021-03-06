/*
 * (C) Copyright 2000-2002
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

/*
 * Boot support
 */
#include <common.h>
#include <watchdog.h>
#include <command.h>
#include <image.h>
#include <malloc.h>
#include <rt_mmap.h>

#include <environment.h>
#include <asm/byteorder.h>

#ifdef CONFIG_GZIP
#include <zlib.h>
#endif /* CONFIG_GZIP */

#ifdef CONFIG_BZIP2
#include <bzlib.h>
#endif

#ifdef CONFIG_LZMA
#include <LzmaDecode.h>
#endif /* CONFIG_LZMA */

#ifdef CONFIG_XZ
#include <unxz.h>
#endif /* CONFIG_XZ */

 /*cmd_boot.c*/
 extern int do_reset (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[]);

#if (CONFIG_COMMANDS & CFG_CMD_DATE) || defined(CONFIG_TIMESTAMP)
#include <rtc.h>
#endif

#ifdef CFG_HUSH_PARSER
#include <hush.h>
#endif

#ifdef CONFIG_SHOW_BOOT_PROGRESS
# include <status_led.h>
# define SHOW_BOOT_PROGRESS(arg)	show_boot_progress(arg)
#else
# define SHOW_BOOT_PROGRESS(arg)
#endif

#ifdef CFG_INIT_RAM_LOCK
#include <asm/cache.h>
#endif

#ifdef CONFIG_LOGBUFFER
#include <logbuff.h>
#endif

#ifdef CONFIG_HAS_DATAFLASH
#include <dataflash.h>
#endif

/*
 * Some systems (for example LWMON) have very short watchdog periods;
 * we must make sure to split long operations like memmove() or
 * crc32() into reasonable chunks.
 */
#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
# define CHUNKSZ (64 * 1024)
#endif


#if (CONFIG_COMMANDS & CFG_CMD_IMI)
#ifdef RT2880_U_BOOT_CMD_OPEN
static int image_info (unsigned long addr);
#endif
#endif

#if (CONFIG_COMMANDS & CFG_CMD_IMLS)
#include <flash.h>
extern flash_info_t flash_info[CFG_MAX_FLASH_BANKS]; /* info for FLASH chips */
static int do_imls (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[]);
#endif

static void print_type (image_header_t *hdr);

#ifdef __I386__
image_header_t *fake_header(image_header_t *hdr, void *ptr, int size);
#endif

#define IH_TYPE_STANDALONE_SUPPORT
#define CONFIG_NONE

/*
 *  Continue booting an OS image; caller already has:
 *  - copied image header to global variable `header'
 *  - checked header magic number, checksums (both header & image),
 *  - verified image architecture (PPC) and type (KERNEL or MULTI),
 *  - loaded (first part of) image to header load address,
 *  - disabled interrupts.
 */
typedef void boot_os_Fcn (cmd_tbl_t *cmdtp, int flag,
			  int	argc, char *argv[],
			  ulong	addr,		/* of image to boot */
			  ulong	*len_ptr,	/* multi-file image length table */
			  int	verify);	/* getenv("verify")[0] != 'n' */

#ifdef	DEBUG
extern int do_bdinfo ( cmd_tbl_t *cmdtp, int flag, int argc, char *argv[]);
#endif

#ifdef CONFIG_PPC
static boot_os_Fcn do_bootm_linux;
#else
extern boot_os_Fcn do_bootm_linux;
#endif
#ifdef CONFIG_SILENT_CONSOLE
static void fixup_silent_linux (void);
#endif
#ifdef CONFIG_NETBSD
static boot_os_Fcn do_bootm_netbsd;
#endif
#ifdef CONFIG_RTEMS
static boot_os_Fcn do_bootm_rtems;
#endif
#if (CONFIG_COMMANDS & CFG_CMD_ELF)
static boot_os_Fcn do_bootm_vxworks;
static boot_os_Fcn do_bootm_qnxelf;
int do_bootvx ( cmd_tbl_t *cmdtp, int flag, int argc, char *argv[] );
int do_bootelf (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[] );
#endif /* CFG_CMD_ELF */
#if defined(CONFIG_ARTOS) && defined(CONFIG_PPC)
static boot_os_Fcn do_bootm_artos;
#endif
#ifdef CONFIG_LYNXKDI
static boot_os_Fcn do_bootm_lynxkdi;
extern void lynxkdi_boot( image_header_t * );
#endif

image_header_t header;
ulong load_addr =  CFG_LOAD_ADDR;		/* Default Load Address */  //0x80100000

static inline void mips_cache_set(u32 v)
{
	asm volatile ("mtc0 %0, $16" : : "r" (v));
}

extern unsigned long mips_cpu_feq;


int check_array_empty0(uint8_t *a,int length)
{
	int i;
	for(i=0;i<length;i++){
		if(a[i]!=0) return 0;
	}
	return 1;
}

int check_duplicate_sigs(uint8_t sigs[10][64], uint8_t sigs_tag[10])
{
	int i,j,t;
	for(i=0;i<10;i++){
		for(j=i+1;j<10;j++){
			if(sigs[i][0]==sigs[j][0] && sigs[i][1]==sigs[j][1] && sigs[i][2]==sigs[j][2] && sigs[i][3]==sigs[j][3] && 
				sigs_tag[i]==1 && sigs_tag[j]==1 )
			{
				printf("contains duplicate signatures\n");
				return -1;	
			}
		}
	}
	return 1;

}

int do_bootm (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	ulong	addr;
	ulong	data, len, checksum;
	ulong  *len_ptr;
	uint	unc_len = 0x800000;
	int	i, verify;
	char	*name, *s;
	int	(*appl)(int, char *[]);
	image_header_t *hdr = &header;

	//mips_cache_set(3);

	s = getenv ("verify");
	verify = (s && (*s == 'n')) ? 0 : 1;
    
	if (argc < 2) {
		addr = load_addr;
	} else {
		addr = simple_strtoul(argv[1], NULL, 16);
	}




//#define USE_GET_TIMER


#define mtd8_ADDR 0x1ff0000 //"fw-info"
#define mtd7_ADDR 0x1360000 //"fw-new"
#define mtd3_ADDR   0x50000 //"firmware"
//#define mtd5_ADDR  0x1df91c+0x50000 //"rootfs"
//#define mtd6_ADDR  0xf20000+0x50000 //"rootfs_data"
#define mtd7_SIZE	(mtd8_ADDR-mtd7_ADDR)

#define mtd9_ADDR 0x1ff8000 //"u-info_i"
#define mtd10_ADDR 0x1ffc000 //"u-info" read_only

#define FW_TAIL_OFFSET 0x30e

#include<u-boot/sha256.h>
#include "../ecdsa_lightweight/easy_ecc_main.c"

	fw_info_t* fwi = malloc(sizeof(fw_info_t));
	raspi_read(fwi, mtd8_ADDR, sizeof(fw_info_t));
	uint8_t* p = (uint8_t*)fwi;
	// check while first boot only
/*	if (fwi->firstboot_tag != 1) {
		printf("\nnot first boot. skip fw verify.\n\n");
		goto boot_start_point;
	}*/
	if (fwi->update != 1 && fwi->membership_update!=1) {
		printf("\n - -\n\n");
		goto boot_start_point;
	}
	else if (fwi->membership_update != 1 &&fwi->update == 1) {
		membership_info_t* meminfo = malloc(sizeof(membership_info_t));
		raspi_read(meminfo, mtd10_ADDR, sizeof(membership_info_t));
		uint8_t* q = (uint8_t*)meminfo;


		printf("fw-info data: ->update,  ->size_new : %d %d \n", fwi->update, fwi->size_new);
		//uint32_t fwi_size_old = fwi->size_old;
		uint32_t fwi_size_new = fwi->size_new;
		uint32_t fwi_update = fwi->update;
		//uint32_t fwi_firstboot_tag = fwi->firstboot_tag;

		uint8_t* fwi_sigs_tag = fwi->sigs_tag;
		uint8_t (*fwi_sigs)[ECC_BYTES*2] = fwi->sigs;

		uint8_t		meminfo_version = meminfo->version;
		uint8_t   (*meminfo_pubkeys)[ECC_BYTES+1] = meminfo->pubkeys;



		if (fwi->size_new <= 0 || fwi->size_new > 32 * 1024 * 1024) {
			fwi_size_new = 1;
			printf("fwi->size_new size out of range\n");
		}

		uint8_t  sha256_sum_mtd7[32];				//void sha256_csum_wd(const unsigned char* input, unsigned int ilen,	unsigned char* output, unsigned int chunk_sz)

		printf("sha256...    ");
		raspi_read(load_addr, mtd7_ADDR, fwi_size_new);
		printf("new firmware mtd7 sha256 ... \n");
		sha256_csum_wd((char*)load_addr, fwi_size_new, sha256_sum_mtd7, CHUNKSZ_SHA256);
		/*WITHOUT 0x(FW_TAIL_OFFSET) metadata!!!!*/
		for (i = 0; i < 32; i++)		printf("%02x", sha256_sum_mtd7[i]);
		printf("\n");




		/*uint8_t privatekey_eg1[] = { 0x27,0xeb,0xcf,0x70,0xac,0xae,0xcb,0x1c,
										  0x4b,0xd8,0x74,0xe2,0x9e,0x13,0xb7,0xb2,
			0x58,0xb9,0x49,0x8c,0xbd,0xbd,0x1a,0xfd,
			0xb2,0xc0,0x13,0xdf,0x65,0x8f,0xcc,0xb9 };

		uint8_t publickey_eg1[] = { 0x02, 0x68, 0xC0, 0xC8, 0x1D, 0x72, 0x85, 0x67,
			0x22, 0xE0, 0x37, 0x38, 0xA7, 0xB4, 0x6C, 0x11,
			0x62, 0x85, 0xC1, 0xA3, 0xA8, 0x50, 0xEE, 0xFC,
			0x84, 0xA6, 0xE7, 0x47, 0x78, 0x1F, 0x22, 0x1D,
			0x0A };

		/*uint8_t privatekey_eg2[] = { 0xf5,0x63,0xd4,0xb6,0xad,0x80,0x0e,0x85,
			0xec,0xd5,0xef,0x8d,0xe7,0x37,0xf4,0x87,
			0xe4,0xf4,0x2b,0x42,0x30,0x14,0xa1,0x39,
			0x15,0xe9,0x7f,0x97,0xe1,0xdf,0xe9,0xb3 };
		uint8_t publickey_eg2[] = { 0x03 , 0x03 , 0xEC , 0xBE , 0x5A , 0x0E , 0x9A , 0xF7 , // ECC_BYTES + 1
			0xAD , 0xDC , 0x15 , 0x34 , 0x9B , 0x96 , 0x3B , 0x29 ,
			0xC7 , 0x24 , 0x36 , 0x5E , 0x24 , 0xDE , 0x2E , 0xE9 ,
			0x92 , 0x7C , 0x11 , 0xE9 , 0x2D , 0xF5 , 0xA4 , 0xE1 , 0x80 };

		/*uint8_t privatekey_eg3[] = { 0xc3,0xe0,0x3d,0x91,0xe8,0x12,0x7d,0xdd,
			0x93,0x86,0xd7,0x37,0xde,0xcc,0x18,0x24,
			0xb7,0xb1,0xe9,0x42,0x66,0x91,0xeb,0x9f,
			0x7d,0xb5,0x80,0x3c,0xf5,0x8f,0x09,0xc7 };
		uint8_t publickey_eg3[] = { 0x03, 0x25, 0xA7, 0x91, 0xC4, 0x0B, 0x2B, 0xBB,
			0x90, 0xC6, 0x9B, 0xA4, 0x09, 0x21, 0x44, 0x77,
			0x4D, 0x54, 0x88, 0xB7, 0x01, 0x39, 0x19, 0x8D,
			0x4F, 0x7A, 0x49, 0x6A, 0xDF, 0xFE, 0xD2, 0xF1, 0x13 }; //ECC_BYTES + 1
		/*uint8_t privatekey_eg4[] = { 0xcc,0x62,0x7f,0xd3,0x99,0xae,0xcc,0x8b,
			0x48,0x9d,0x29,0xf8,0x77,0xa4,0x05,0xea,
			0xd0,0xa7,0x8c,0x51,0xae,0x47,0xc6,0xb9,
			0x49,0xa6,0x8f,0xa7,0xa8,0xa2,0x27,0x11 };
		uint8_t publickey_eg4[] = { 0x03 , 0x75 , 0x60 , 0x99 , 0x3B , 0x5F , 0x74 , 0xCF ,
			0x10 , 0xD7 , 0x7F , 0x9F , 0x96 , 0x9E , 0x37 , 0x5E ,
			0x21 , 0x73 , 0x43 , 0x15 , 0xAA , 0x11 , 0xEE , 0x13 ,
			0x12 , 0x21 , 0x13 , 0x7B , 0x8C , 0x83 , 0x76 , 0xEA , 0x7F };// ECC_BYTES + 1
		*/

	//	if (fwi_sig1_tag + fwi_sig2_tag + fwi_sig3_tag + fwi_sig4_tag < 1 || fwi_sig1_tag + fwi_sig2_tag + fwi_sig3_tag + fwi_sig4_tag >4)	printf("fwi_sig_tag error... ... %d %d %d %d \n", fwi_sig1_tag, fwi_sig2_tag, fwi_sig3_tag, fwi_sig4_tag);

		int sum_sig_index = 0;
		for (i = 0; i < 10; i++)sum_sig_index = sum_sig_index + fwi_sigs_tag[i];
		if (sum_sig_index < 1 || sum_sig_index >10) {
			printf("fwi_sig_tag error... ...");
			for (i = 0; i < 10; i++) printf("%d ", fwi_sigs_tag[i]);
			printf("\n");
		}


		int sig_verified = 0;

		printf(" verify signature(s):\n");			//sig_varify_newfirmware_mtd7_result = signature_verify_by_pubkey_33(publickey_eg1, sha256_sum_mtd7, signature_new_firstboot);
		for (i = 0; i < 10; i++) {
			if (fwi_sigs_tag[i] == 1) {
				printf("sig%d: ", i);
				if (signature_verify_by_pubkey_33(meminfo_pubkeys[i], sha256_sum_mtd7, fwi_sigs[i]) == 1 && sig_verified >= 0) sig_verified = 1;
				else sig_verified = -1;
			}
		}


		if (sig_verified == 1) {

			printf(" sig verified..... flash mtd7 as the new firmware to mtd3 now.....\n");

			int raspi_erase_write_result = 1;
			//raspi_read(load_addr, mtd7_ADDR, fwi_size_new );
			printf("reading.# ");
			raspi_read(load_addr, mtd7_ADDR, mtd7_SIZE);

			printf("    writing.# ");
			raspi_erase_write_result = raspi_erase_write((char*)load_addr, mtd3_ADDR, fwi_size_new + 0 * FW_TAIL_OFFSET);//raspi_erase_write_result=raspi_erase_write((char*)load_addr, mtd3_ADDR, mtd7_SIZE);

			if (raspi_erase_write_result == 0)
			{
				if (fwi->update != 0) {
					printf("change fwi->update to 0 .... .... ");
					fwi->update = 0;
					raspi_erase_write(fwi, mtd8_ADDR, sizeof(fw_info_t));
				}
				printf("upgrade process finishes ....  reboot now ...\n");
				do_reset(cmdtp, 0, argc, argv);
			}
			else printf("it seems that raspi_erase_write() is not successful because the return value is not 0.. .... \n");
		}
		else {
			printf("ecdsa_verify error, firmware sig not verified.....    %d\n", sig_verified);
		}


	}

	else if (fwi->membership_update == 1) {

		membership_info_t* meminfo_current = malloc(sizeof(membership_info_t));
		raspi_read(meminfo_current, mtd10_ADDR, sizeof(membership_info_t));
		uint8_t* q0 = (uint8_t*)meminfo_current;
		uint32_t current_version=meminfo_current->version;
		uint8_t (*current_pubkeys)[ECC_BYTES+1] = meminfo_current->pubkeys;


		membership_info_t* meminfo_new = malloc(sizeof(membership_info_t));
		raspi_read(meminfo_new, mtd7_ADDR  , sizeof(membership_info_t));
		uint8_t* q = (uint8_t*)meminfo_new;
		uint32_t new_version=meminfo_new->version;
		uint8_t (*new_pubkeys)[ECC_BYTES+1] = meminfo_new->pubkeys;
		uint8_t (*new_sig)[ECC_BYTES*2] = meminfo_new->sigs;
		uint32_t	  including_next=meminfo_new->including_next;
		uint8_t* new_sigs_tag=meminfo_new->sigs_tag;



		uint32_t version0=current_version, version1=new_version;
		uint8_t (*keys0)[ECC_BYTES+1] = meminfo_current->pubkeys;
		uint8_t (*keys1)[ECC_BYTES+1] = meminfo_new->pubkeys;
		uint8_t  (*sig0)[ECC_BYTES*2];
		uint8_t  (*sig1)[ECC_BYTES*2] = meminfo_new->sigs;

		int verify_membershipinfo_new = -1;
		uint8_t sha2_mem_new[32];
		int sig_count=0;
		int j;

		printf("\ncurrent version: %d\n", version0);

		for(i=0;i<32767;i++)
		{
			if(version0+1!=version1){
				printf("invlaid membership version, v0=%d ,v1=%d ,i=%d \n",version0,version1,i);
				break;
			}

			check_duplicate_sigs(sig1, new_sigs_tag);

	


			/*for (j = 0; j < sizeof(membership_info_t); j++) {
				printf("%02x ", q0[j]);
			}
			printf("\n");*/
	

			printf("verify membership info [version %d] with sig:  \n",version1);
			//sha256_csum_wd(q, sizeof(membership_info_t) , sha2_mem_new, CHUNKSZ_SHA256);

			/*for (j = 0; j < sizeof(membership_info_t); j++) {
				printf("%02x ", q[j]);
			}
			printf("\n");*/
			
			sha256_csum_wd(q, sizeof(uint32_t)+10*(ECC_BYTES+1)*sizeof(uint8_t) , sha2_mem_new, CHUNKSZ_SHA256);

			for (j = 0; j < 32; j++)	printf("%02x", sha2_mem_new[j]);
			printf("\n");

			sig_count=0;

			for(j=0;j<10;j++)
			{
							
				if(new_sigs_tag[j]==1)
				{
					sig_count++;
					verify_membershipinfo_new= signature_verify_by_pubkey_33(keys0[j], sha2_mem_new, sig1[j]);
					if (verify_membershipinfo_new == 1) {
						printf("    version %d verified by sig%d\n",version1,j);
					}
					else {
						printf("...version %d is not verified by sig%d\n",version1,j);
						break;
					}
				}
				else{
					if(check_array_empty0(sig1[j],64)!=1){
						printf("contains non member signatures at %d\n",j);
					}
				}
			}
			if (verify_membershipinfo_new != 1) break;
			/*if(sig_count<???){
				printf("not enough signatures, sig_count= %d\n",sig_count);
			}*/
		

			if(including_next==0){
					printf("\n\nflashing new membership [version %d]... ...", version1);
					raspi_erase_write(meminfo_new, mtd10_ADDR, sizeof(membership_info_t));
					break;
			}
			else if(including_next==1){
					raspi_read(meminfo_current, mtd7_ADDR+( i*sizeof(membership_info_t) ), sizeof(membership_info_t));
					q0 = (uint8_t*)meminfo_current;
					current_version=meminfo_current->version;
					current_pubkeys = meminfo_current->pubkeys;

					
					raspi_read(meminfo_new, mtd7_ADDR+( (i+1)*sizeof(membership_info_t)), sizeof(membership_info_t));
					q = (uint8_t*)meminfo_new;
					new_version=meminfo_new->version;
					new_pubkeys = meminfo_new->pubkeys;
					new_sig = meminfo_new->sigs;
					including_next=meminfo_new->including_next;
					new_sigs_tag=meminfo_new->sigs_tag;


					version0=current_version; 	version1=new_version;
					keys0=current_pubkeys; 		keys1=new_pubkeys;
					sig1=new_sig;	


					verify_membershipinfo_new = -1;
			}
			else {
				printf("including_next is not 1 or 0. error value: %d\n", including_next);
			}


	
			/*else {
				printf("...version %d is not verified\n",version1);
				break;
			}*/


		} //for


	} //else if (fwi->membership_update == 1)


	if (fwi->membership_update == 0&& fwi->update != 0) {
		printf("change fwi->update to 0 .... ....\n");
		fwi->update = 0;
		raspi_erase_write(fwi, mtd8_ADDR, sizeof(fw_info_t));//int raspi_erase_write(char *buf, unsigned int offs, int count)
	}
	if (fwi->membership_update != 0) {
		printf("change fwi->membership_update to 0 .... ....\n");
		fwi->membership_update = 0;
		raspi_erase_write(fwi, mtd8_ADDR, sizeof(fw_info_t));
	}
	printf("\n");



	

boot_start_point:
	SHOW_BOOT_PROGRESS (1);
	printf ("## Booting image at %08lx ...\n", addr);

#ifdef DUAL_IMAGE_SUPPORT
	if (strcmp(getenv("Image1Stable"), "1") != 0) {
		s = getenv("Image1Try");
		if (s == NULL)
			setenv("Image1Try", "1");
		else {
			char buf[32];
	
			i = (int)simple_strtoul(s, NULL, 10);
			sprintf(buf, "%d", ++i);
			setenv("Image1Try", buf);
		}
		saveenv();
	}
#endif

   /* YJ, 5/16/2006 */
   if (addr == 0x8A200000)
	   ((void(*) (void)) (0x8A200000U))();	
   else if(addr == 0x80200000)
	   ((void(*) (void)) (0x80200000U))();	
   else if(addr == 0x8A300000)
	   ((void(*) (void)) (0x8A300000U))();	
   else if(addr == 0x88001000)
	   ((void(*) (void)) (0x88001000U))();	
   else if(addr == 0x8B800000)
	   ((void(*) (void)) (0x8B800000U))();	

	/* Copy header so we can blank CRC field for re-calculation */
#ifdef CONFIG_HAS_DATAFLASH
	if (addr_dataflash(addr)){
		read_dataflash(addr, sizeof(image_header_t), (char *)&header);
	}
#endif

	do {	
#if defined (CFG_ENV_IS_IN_NAND)
	if (addr >= CFG_FLASH_BASE)
		ranand_read(&header, (char *)(addr - CFG_FLASH_BASE), sizeof(image_header_t));
	else
		memmove (&header, (char *)addr, sizeof(image_header_t));
#elif defined (CFG_ENV_IS_IN_SPI)
	if (addr >= CFG_FLASH_BASE)
		raspi_read(&header, (char *)(addr - CFG_FLASH_BASE), sizeof(image_header_t));
	else
		memmove (&header, (char *)addr, sizeof(image_header_t));
#else //CFG_ENV_IS_IN_FLASH
	memmove (&header, (char *)addr, sizeof(image_header_t));
#endif //CFG_ENV_IS_IN_FLASH

	if (ntohl(hdr->ih_magic) != IH_MAGIC) {
#ifdef __I386__	/* correct image format not implemented yet - fake it */
		if (fake_header(hdr, (void*)addr, -1) != NULL) {
			/* to compensate for the addition below */
			addr -= sizeof(image_header_t);
			/* turnof verify,
			 * fake_header() does not fake the data crc
			 */
			verify = 0;
		} else
#endif	/* __I386__ */
	    {
		printf ("Bad Magic Number,%08X \n",ntohl(hdr->ih_magic));
#if defined (CFG_ENV_IS_IN_NAND)
			addr += CFG_BLOCKSIZE;
			if ((addr-CFG_FLASH_BASE) < 0x2000000) /* Suppose minimum NAND flash size 32MB */
			{	
				printf("Search header in next block address %x\n",addr-CFG_FLASH_BASE); 
				continue;
			}
			else
#endif				
			{	
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	    }
	}
	}
	break;
	}while (1);
	SHOW_BOOT_PROGRESS (2);

	data = (ulong)&header;
	len  = sizeof(image_header_t);

	checksum = ntohl(hdr->ih_hcrc);
	hdr->ih_hcrc = 0;

	if (crc32 (0, (char *)data, len) != checksum) {
		puts ("Bad Header Checksum\n");
		SHOW_BOOT_PROGRESS (-2);
		return 1;
	}
	SHOW_BOOT_PROGRESS (3);

	/* for multi-file images we need the data part, too */
	print_image_hdr ((image_header_t *)hdr);

	data = addr + sizeof(image_header_t);
	len  = ntohl(hdr->ih_size);

#ifdef CONFIG_HAS_DATAFLASH
	if (addr_dataflash(addr)){
		read_dataflash(data, len, (char *)CFG_LOAD_ADDR);
		data = CFG_LOAD_ADDR;
	}
#endif

#if defined (CFG_ENV_IS_IN_NAND)
	if (addr >= CFG_FLASH_BASE) {
		ulong load_addr = CFG_SPINAND_LOAD_ADDR;
		ranand_read(load_addr, data - CFG_FLASH_BASE, len);
		data = load_addr;
	}
#elif defined (CFG_ENV_IS_IN_SPI)
	if (addr >= CFG_FLASH_BASE) {
		ulong load_addr = CFG_SPINAND_LOAD_ADDR;
		raspi_read(load_addr, data - CFG_FLASH_BASE, len);
		data = load_addr;
	}
#else //CFG_ENV_IS_IN_FLASH
#endif

	if (verify) {
		puts ("   Verifying Checksum ... ");
		if (crc32 (0, (char *)data, len) != ntohl(hdr->ih_dcrc)) {
			printf ("Bad Data CRC\n");
			SHOW_BOOT_PROGRESS (-3);
			return 1;
		}
		puts ("OK\n");
	}
	SHOW_BOOT_PROGRESS (4);

	len_ptr = (ulong *)data;

#if defined(__PPC__)
	if (hdr->ih_arch != IH_CPU_PPC)
#elif defined(__ARM__)
	if (hdr->ih_arch != IH_CPU_ARM)
#elif defined(__I386__)
	if (hdr->ih_arch != IH_CPU_I386)
#elif defined(__mips__)
	if (hdr->ih_arch != IH_CPU_MIPS)
#elif defined(__nios__)
	if (hdr->ih_arch != IH_CPU_NIOS)
#elif defined(__M68K__)
	if (hdr->ih_arch != IH_CPU_M68K)
#elif defined(__microblaze__)
	if (hdr->ih_arch != IH_CPU_MICROBLAZE)
#elif defined(__nios2__)
	if (hdr->ih_arch != IH_CPU_NIOS2)
#else
# error Unknown CPU type
#endif
	{
		printf ("Unsupported Architecture 0x%x\n", hdr->ih_arch);
		SHOW_BOOT_PROGRESS (-4);
		return 1;
	}
	SHOW_BOOT_PROGRESS (5);

	switch (hdr->ih_type) {
#ifdef IH_TYPE_STANDALONE_SUPPORT
	case IH_TYPE_STANDALONE:
		name = "Standalone Application";
		/* A second argument overwrites the load address */
		if (argc > 2) {
			hdr->ih_load = simple_strtoul(argv[2], NULL, 16);
		}
		break;
#endif
	case IH_TYPE_KERNEL:
		name = "Kernel Image";
		break;
#ifdef IH_TYPE_MULTI_SUPPORT
	case IH_TYPE_MULTI:
		name = "Multi-File Image";
		len  = ntohl(len_ptr[0]);
		/* OS kernel is always the first image */
		data += 8; /* kernel_len + terminator */
		for (i=1; len_ptr[i]; ++i)
			data += 4;
		break;
#endif // IH_TYPE_MULTI_SUPPORT //
	default: printf ("Wrong Image Type for %s command\n", cmdtp->name);
		SHOW_BOOT_PROGRESS (-5);
		return 1;
	}
	SHOW_BOOT_PROGRESS (6);

	/*
	 * We have reached the point of no return: we are going to
	 * overwrite all exception vector code, so we cannot easily
	 * recover from any failures any more...
	 */

	//iflag = disable_interrupts();

#ifdef CONFIG_AMIGAONEG3SE
	/*
	 * We've possible left the caches enabled during
	 * bios emulation, so turn them off again
	 */
	icache_disable();
	invalidate_l1_instruction_cache();
	flush_data_cache();
	dcache_disable();
#endif

	switch (hdr->ih_comp) {
#ifdef CONFIG_NONE
	case IH_COMP_NONE:
		if(ntohl(hdr->ih_load) == addr) {
			printf ("   XIP %s ... ", name);
		} else {
#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
			size_t l = len;
			void *to = (void *)ntohl(hdr->ih_load);
			void *from = (void *)data;

			printf ("   Loading %s ... ", name);

			while (l > 0) {
				size_t tail = (l > CHUNKSZ) ? CHUNKSZ : l;
				WATCHDOG_RESET();
				memmove (to, from, tail);
				to += tail;
				from += tail;
				l -= tail;
			}
#else	/* !(CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG) */
			memmove ((void *) ntohl(hdr->ih_load), (uchar *)data, len);
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */
		}
		break;
#endif
#ifdef CONFIG_GZIP
	case IH_COMP_GZIP:
		printf ("   Uncompressing %s ... ", name);
		if (gunzip ((void *)ntohl(hdr->ih_load), unc_len,
			    (uchar *)data, &len) != 0) {
			puts ("GUNZIP ERROR - must RESET board to recover\n");
			SHOW_BOOT_PROGRESS (-6);
			do_reset (cmdtp, flag, argc, argv);
		}
		break;
#endif
#ifdef CONFIG_BZIP2
	case IH_COMP_BZIP2:
		printf ("   Uncompressing %s ... ", name);
		/*
		 * If we've got less than 4 MB of malloc() space,
		 * use slower decompression algorithm which requires
		 * at most 2300 KB of memory.
		 */
		i = BZ2_bzBuffToBuffDecompress ((char*)ntohl(hdr->ih_load),
						&unc_len, (char *)data, len,
						CFG_MALLOC_LEN < (4096 * 1024), 0);
		if (i != BZ_OK) {
			printf ("BUNZIP2 ERROR %d - must RESET board to recover\n", i);
			SHOW_BOOT_PROGRESS (-6);
			udelay(100000);
			do_reset (cmdtp, flag, argc, argv);
		}
		break;
#endif /* CONFIG_BZIP2 */
#ifdef CONFIG_LZMA
        case IH_COMP_LZMA:
                printf ("   Uncompressing %s ... ", name);

#ifdef CONFIG_UNCOMPRESS_TIME
                tBUncompress = get_ticks();
#endif
		unsigned int destLen = 0;
                i = lzmaBuffToBuffDecompress ((char*)ntohl(hdr->ih_load),
                                &destLen, (char *)data, len);
                if (i != LZMA_RESULT_OK) {
                        printf ("LZMA ERROR %d - must RESET board to recover\n", i);
                        SHOW_BOOT_PROGRESS (-6);
                        udelay(100000);
                        do_reset (cmdtp, flag, argc, argv);
                }
#ifdef CONFIG_UNCOMPRESS_TIME
                tAUncompress = get_ticks();
                tAUncompress = (tAUncompress - tBUncompress) >> 10;
                printf("Uncompression time : %lu/%lu\n",tAUncompress,get_tbclk());
                printf("Uncompression length is %d\n",destLen);
#endif
                break;
#endif /* CONFIG_LZMA */
#ifdef CONFIG_XZ
	case IH_COMP_XZ:
		printf ("   Uncompressing %s ... ", name);
		i = unxz((unsigned char *)data, len,
			(unsigned char *)ntohl(hdr->ih_load), &unc_len);

		if (i != 0) {
			printf ("XZ: uncompress or overwrite error %d "
				"- must RESET board to recover\n", i);
			SHOW_BOOT_PROGRESS (-6);
                        udelay(100000);
                        do_reset (cmdtp, flag, argc, argv);
		}
		break;
#endif /* CONFIG_XZ */
	default:
		/*
		if (iflag)
			enable_interrupts();
			*/
		printf ("Unimplemented compression type %d\n", hdr->ih_comp);
		SHOW_BOOT_PROGRESS (-7);
		return 1;
	}
	puts ("OK\n");
	SHOW_BOOT_PROGRESS (7);

	switch (hdr->ih_type) {
#ifdef IH_TYPE_STANDALONE_SUPPORT
	case IH_TYPE_STANDALONE:
		/*
		if (iflag)
			enable_interrupts();
			*/

		/* load (and uncompress), but don't start if "autostart"
		 * is set to "no"
		 */
#if 0
		if (((s = getenv("autostart")) != NULL) && (strcmp(s,"no") == 0)) {
			char buf[32];
			sprintf(buf, "%lX", len);
			setenv("filesize", buf);
			return 0;
		}
#endif
		appl = (int (*)(int, char *[]))ntohl(hdr->ih_ep);
		(*appl)(argc-1, &argv[1]);
		return 0;
#endif
	case IH_TYPE_KERNEL:
		break;
#ifdef IH_TYPE_MULTI_SUPPORT
	case IH_TYPE_MULTI:
		break;
#endif // IH_TYPE_MULTI_SUPPORT //
	default:
		/*
		if (iflag)
			enable_interrupts();
			*/
		printf ("Can't boot image type %d\n", hdr->ih_type);
		SHOW_BOOT_PROGRESS (-8);
		return 1;
	}
	SHOW_BOOT_PROGRESS (8);

	switch (hdr->ih_os) {
	default:			/* handled by (original) Linux case */
	case IH_OS_LINUX:
#ifdef CONFIG_SILENT_CONSOLE
	    fixup_silent_linux();
#endif
	    do_bootm_linux  (cmdtp, flag, argc, argv,
			     addr, len_ptr, verify);
	    break;

#ifdef CONFIG_NETBSD
	case IH_OS_NETBSD:
	    do_bootm_netbsd (cmdtp, flag, argc, argv,
			     addr, len_ptr, verify);
	    break;
#endif

#ifdef CONFIG_LYNXKDI
	case IH_OS_LYNXOS:
	    do_bootm_lynxkdi (cmdtp, flag, argc, argv,
			     addr, len_ptr, verify);
	    break;
#endif

#ifdef CONFIG_RTEMS
	case IH_OS_RTEMS:
	    do_bootm_rtems (cmdtp, flag, argc, argv,
			     addr, len_ptr, verify);
	    break;
#endif

#if (CONFIG_COMMANDS & CFG_CMD_ELF)
	case IH_OS_VXWORKS:
	    do_bootm_vxworks (cmdtp, flag, argc, argv,
			      addr, len_ptr, verify);
	    break;
	case IH_OS_QNX:
	    do_bootm_qnxelf (cmdtp, flag, argc, argv,
			      addr, len_ptr, verify);
	    break;
#endif /* CFG_CMD_ELF */
#ifdef CONFIG_ARTOS
	case IH_OS_ARTOS:
	    do_bootm_artos  (cmdtp, flag, argc, argv,
			     addr, len_ptr, verify);
	    break;
#endif
	}

	SHOW_BOOT_PROGRESS (-9);
#ifdef DEBUG
	puts ("\n## Control returned to monitor - resetting...\n");
	do_reset (cmdtp, flag, argc, argv);
#endif
	return 1;
}

#ifdef RALINK_CMDLINE
U_BOOT_CMD(
 	bootm,	CFG_MAXARGS,	1,	do_bootm,
 	"bootm   - boot application image from memory\n",
 	"[addr [arg ...]]\n    - boot application image stored in memory\n"
 	"\tpassing arguments 'arg ...'; when booting a Linux kernel,\n"
 	"\t'arg' can be the address of an initrd image\n"
);
#endif

#ifdef CONFIG_SILENT_CONSOLE
static void
fixup_silent_linux ()
{
	DECLARE_GLOBAL_DATA_PTR;
	char buf[256], *start, *end;
	char *cmdline = getenv ("bootargs");

	/* Only fix cmdline when requested */
	if (!(gd->flags & GD_FLG_SILENT))
		return;

	debug ("before silent fix-up: %s\n", cmdline);
	if (cmdline) {
		if ((start = strstr (cmdline, "console=")) != NULL) {
			end = strchr (start, ' ');
			strncpy (buf, cmdline, (start - cmdline + 8));
			if (end)
				strcpy (buf + (start - cmdline + 8), end);
			else
				buf[start - cmdline + 8] = '\0';
		} else {
			strcpy (buf, cmdline);
			strcat (buf, " console=");
		}
	} else {
		strcpy (buf, "console=");
	}

	setenv ("bootargs", buf);
	debug ("after silent fix-up: %s\n", buf);
}
#endif /* CONFIG_SILENT_CONSOLE */

#ifdef CONFIG_PPC
static void
do_bootm_linux (cmd_tbl_t *cmdtp, int flag,
		int	argc, char *argv[],
		ulong	addr,
		ulong	*len_ptr,
		int	verify)
{
	DECLARE_GLOBAL_DATA_PTR;

	ulong	sp;
	ulong	len, checksum;
	ulong	initrd_start, initrd_end;
	ulong	cmd_start, cmd_end;
	ulong	initrd_high;
	ulong	data;
	int	initrd_copy_to_ram = 1;
	char    *cmdline;
	char	*s;
	bd_t	*kbd;
	void	(*kernel)(bd_t *, ulong, ulong, ulong, ulong);
	image_header_t *hdr = &header;

	if ((s = getenv ("initrd_high")) != NULL) {
		/* a value of "no" or a similar string will act like 0,
		 * turning the "load high" feature off. This is intentional.
		 */
		initrd_high = simple_strtoul(s, NULL, 16);
		if (initrd_high == ~0)
			initrd_copy_to_ram = 0;
	} else {	/* not set, no restrictions to load high */
		initrd_high = ~0;
	}

#ifdef CONFIG_LOGBUFFER
	kbd=gd->bd;
	/* Prevent initrd from overwriting logbuffer */
	if (initrd_high < (kbd->bi_memsize-LOGBUFF_LEN-LOGBUFF_OVERHEAD))
		initrd_high = kbd->bi_memsize-LOGBUFF_LEN-LOGBUFF_OVERHEAD;
	debug ("## Logbuffer at 0x%08lX ", kbd->bi_memsize-LOGBUFF_LEN);
#endif

	/*
	 * Booting a (Linux) kernel image
	 *
	 * Allocate space for command line and board info - the
	 * address should be as high as possible within the reach of
	 * the kernel (see CFG_BOOTMAPSZ settings), but in unused
	 * memory, which means far enough below the current stack
	 * pointer.
	 */

	asm( "mr %0,1": "=r"(sp) : );

	debug ("## Current stack ends at 0x%08lX ", sp);

	sp -= 2048;		/* just to be sure */
	if (sp > CFG_BOOTMAPSZ)
		sp = CFG_BOOTMAPSZ;
	sp &= ~0xF;

	debug ("=> set upper limit to 0x%08lX\n", sp);

	cmdline = (char *)((sp - CFG_BARGSIZE) & ~0xF);
	kbd = (bd_t *)(((ulong)cmdline - sizeof(bd_t)) & ~0xF);

	if ((s = getenv("bootargs")) == NULL)
		s = "";

	strcpy (cmdline, s);

	cmd_start    = (ulong)&cmdline[0];
	cmd_end      = cmd_start + strlen(cmdline);

	*kbd = *(gd->bd);

#ifdef	DEBUG
	printf ("## cmdline at 0x%08lX ... 0x%08lX\n", cmd_start, cmd_end);

	do_bdinfo (NULL, 0, 0, NULL);
#endif

	if ((s = getenv ("clocks_in_mhz")) != NULL) {
		/* convert all clock information to MHz */
		kbd->bi_intfreq /= 1000000L;
		kbd->bi_busfreq /= 1000000L;
#if defined(CONFIG_MPC8220)
	kbd->bi_inpfreq /= 1000000L;
	kbd->bi_pcifreq /= 1000000L;
	kbd->bi_pevfreq /= 1000000L;
	kbd->bi_flbfreq /= 1000000L;
	kbd->bi_vcofreq /= 1000000L;
#endif
#if defined(CONFIG_8260) || defined(CONFIG_MPC8560)
		kbd->bi_cpmfreq /= 1000000L;
		kbd->bi_brgfreq /= 1000000L;
		kbd->bi_sccfreq /= 1000000L;
		kbd->bi_vco     /= 1000000L;
#endif /* CONFIG_8260 */
#if defined(CONFIG_MPC5xxx)
		kbd->bi_ipbfreq /= 1000000L;
		kbd->bi_pcifreq /= 1000000L;
#endif /* CONFIG_MPC5xxx */
	}

	kernel = (void (*)(bd_t *, ulong, ulong, ulong, ulong))hdr->ih_ep;

	/*
	 * Check if there is an initrd image
	 */
	if (argc >= 3) {
		SHOW_BOOT_PROGRESS (9);

		addr = simple_strtoul(argv[2], NULL, 16);

		printf ("## Loading RAMDisk Image at %08lx ...\n", addr);

		/* Copy header so we can blank CRC field for re-calculation */
		memmove (&header, (char *)addr, sizeof(image_header_t));

		if (hdr->ih_magic  != IH_MAGIC) {
			puts ("Bad Magic Number\n");
			SHOW_BOOT_PROGRESS (-10);
			do_reset (cmdtp, flag, argc, argv);
		}

		data = (ulong)&header;
		len  = sizeof(image_header_t);

		checksum = hdr->ih_hcrc;
		hdr->ih_hcrc = 0;

		if (crc32 (0, (char *)data, len) != checksum) {
			puts ("Bad Header Checksum\n");
			SHOW_BOOT_PROGRESS (-11);
			do_reset (cmdtp, flag, argc, argv);
		}

		SHOW_BOOT_PROGRESS (10);

		print_image_hdr (hdr);

		data = addr + sizeof(image_header_t);
		len  = hdr->ih_size;

		if (verify) {
			ulong csum = 0;
#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
			ulong cdata = data, edata = cdata + len;
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */

			puts ("   Verifying Checksum ... ");

#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)

			while (cdata < edata) {
				ulong chunk = edata - cdata;

				if (chunk > CHUNKSZ)
					chunk = CHUNKSZ;
				csum = crc32 (csum, (char *)cdata, chunk);
				cdata += chunk;

				WATCHDOG_RESET();
			}
#else	/* !(CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG) */
			csum = crc32 (0, (char *)data, len);
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */

			if (csum != hdr->ih_dcrc) {
				puts ("Bad Data CRC\n");
				SHOW_BOOT_PROGRESS (-12);
				do_reset (cmdtp, flag, argc, argv);
			}
			puts ("OK\n");
		}

		SHOW_BOOT_PROGRESS (11);

		if ((hdr->ih_os   != IH_OS_LINUX)	||
		    (hdr->ih_arch != IH_CPU_PPC)	||
		    (hdr->ih_type != IH_TYPE_RAMDISK)	) {
			puts ("No Linux PPC Ramdisk Image\n");
			SHOW_BOOT_PROGRESS (-13);
			do_reset (cmdtp, flag, argc, argv);
		}

		/*
		 * Now check if we have a multifile image
		 */
#ifdef IH_TYPE_MULTI_SUPPORT
	} else if ((hdr->ih_type==IH_TYPE_MULTI) && (len_ptr[1])) {
		u_long tail    = ntohl(len_ptr[0]) % 4;
		int i;

		SHOW_BOOT_PROGRESS (13);

		/* skip kernel length and terminator */
		data = (ulong)(&len_ptr[2]);
		/* skip any additional image length fields */
		for (i=1; len_ptr[i]; ++i)
			data += 4;
		/* add kernel length, and align */
		data += ntohl(len_ptr[0]);
		if (tail) {
			data += 4 - tail;
		}

		len   = ntohl(len_ptr[1]);
#endif // IH_TYPE_MULTI_SUPPORT //
	} else {
		/*
		 * no initrd image
		 */
		SHOW_BOOT_PROGRESS (14);

		len = data = 0;
	}

	if (!data) {
		debug ("No initrd\n");
	}

	if (data) {
	    if (!initrd_copy_to_ram) {	/* zero-copy ramdisk support */
		initrd_start = data;
		initrd_end = initrd_start + len;
	    } else {
		initrd_start  = (ulong)kbd - len;
		initrd_start &= ~(4096 - 1);	/* align on page */

		if (initrd_high) {
			ulong nsp;

			/*
			 * the inital ramdisk does not need to be within
			 * CFG_BOOTMAPSZ as it is not accessed until after
			 * the mm system is initialised.
			 *
			 * do the stack bottom calculation again and see if
			 * the initrd will fit just below the monitor stack
			 * bottom without overwriting the area allocated
			 * above for command line args and board info.
			 */
			asm( "mr %0,1": "=r"(nsp) : );
			nsp -= 2048;		/* just to be sure */
			nsp &= ~0xF;
			if (nsp > initrd_high)	/* limit as specified */
				nsp = initrd_high;
			nsp -= len;
			nsp &= ~(4096 - 1);	/* align on page */
			if (nsp >= sp)
				initrd_start = nsp;
		}

		SHOW_BOOT_PROGRESS (12);

		debug ("## initrd at 0x%08lX ... 0x%08lX (len=%ld=0x%lX)\n",
			data, data + len - 1, len, len);

		initrd_end    = initrd_start + len;
		printf ("   Loading Ramdisk to %08lx, end %08lx ... ",
			initrd_start, initrd_end);
#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
		{
			size_t l = len;
			void *to = (void *)initrd_start;
			void *from = (void *)data;

			while (l > 0) {
				size_t tail = (l > CHUNKSZ) ? CHUNKSZ : l;
				WATCHDOG_RESET();
				memmove (to, from, tail);
				to += tail;
				from += tail;
				l -= tail;
			}
		}
#else	/* !(CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG) */
		memmove ((void *)initrd_start, (void *)data, len);
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */
		puts ("OK\n");
	    }
	} else {
		initrd_start = 0;
		initrd_end = 0;
	}


	debug ("## Transferring control to Linux (at address %08lx) ...\n",
		(ulong)kernel);

	SHOW_BOOT_PROGRESS (15);

#if defined(CFG_INIT_RAM_LOCK) && !defined(CONFIG_E500)
	unlock_ram_in_cache();
#endif
	/*
	 * Linux Kernel Parameters:
	 *   r3: ptr to board info data
	 *   r4: initrd_start or 0 if no initrd
	 *   r5: initrd_end - unused if r4 is 0
	 *   r6: Start of command line string
	 *   r7: End   of command line string
	 */
	(*kernel) (kbd, initrd_start, initrd_end, cmd_start, cmd_end);
}
#endif /* CONFIG_PPC */

#ifdef CONFIG_NETBSD
static void
do_bootm_netbsd (cmd_tbl_t *cmdtp, int flag,
		int	argc, char *argv[],
		ulong	addr,
		ulong	*len_ptr,
		int	verify)
{
	DECLARE_GLOBAL_DATA_PTR;

	image_header_t *hdr = &header;

	void	(*loader)(bd_t *, image_header_t *, char *, char *);
	image_header_t *img_addr;
	char     *consdev;
	char     *cmdline;


	/*
	 * Booting a (NetBSD) kernel image
	 *
	 * This process is pretty similar to a standalone application:
	 * The (first part of an multi-) image must be a stage-2 loader,
	 * which in turn is responsible for loading & invoking the actual
	 * kernel.  The only differences are the parameters being passed:
	 * besides the board info strucure, the loader expects a command
	 * line, the name of the console device, and (optionally) the
	 * address of the original image header.
	 */

	img_addr = 0;
#ifdef IH_TYPE_MULTI_SUPPORT
	if ((hdr->ih_type==IH_TYPE_MULTI) && (len_ptr[1]))
		img_addr = (image_header_t *) addr;
#endif // IH_TYPE_MULTI_SUPPORT //

	consdev = "";
#if   defined (CONFIG_8xx_CONS_SMC1)
	consdev = "smc1";
#elif defined (CONFIG_8xx_CONS_SMC2)
	consdev = "smc2";
#elif defined (CONFIG_8xx_CONS_SCC2)
	consdev = "scc2";
#elif defined (CONFIG_8xx_CONS_SCC3)
	consdev = "scc3";
#endif

	if (argc > 2) {
		ulong len;
		int   i;

		for (i=2, len=0 ; i<argc ; i+=1)
			len += strlen (argv[i]) + 1;
		cmdline = malloc (len);

		for (i=2, len=0 ; i<argc ; i+=1) {
			if (i > 2)
				cmdline[len++] = ' ';
			sprintf(&cmdline[len], argv[i]);
			len += strlen (argv[i]);
		}
	} else if ((cmdline = getenv("bootargs")) == NULL) {
		cmdline = "";
	}

	loader = (void (*)(bd_t *, image_header_t *, char *, char *)) hdr->ih_ep;

	printf ("## Transferring control to NetBSD stage-2 loader (at address %08lx) ...\n",
		(ulong)loader);

	SHOW_BOOT_PROGRESS (15);

	/*
	 * NetBSD Stage-2 Loader Parameters:
	 *   r3: ptr to board info data
	 *   r4: image address
	 *   r5: console device
	 *   r6: boot args string
	 */
	(*loader) (gd->bd, img_addr, consdev, cmdline);
}
#endif

#if defined(CONFIG_ARTOS) && defined(CONFIG_PPC)

/* Function that returns a character from the environment */
extern uchar (*env_get_char)(int);

static void
do_bootm_artos (cmd_tbl_t *cmdtp, int flag,
		int	argc, char *argv[],
		ulong	addr,
		ulong	*len_ptr,
		int	verify)
{
	DECLARE_GLOBAL_DATA_PTR;
	ulong top;
	char *s, *cmdline;
	char **fwenv, **ss;
	int i, j, nxt, len, envno, envsz;
	bd_t *kbd;
	void (*entry)(bd_t *bd, char *cmdline, char **fwenv, ulong top);
	image_header_t *hdr = &header;

	/*
	 * Booting an ARTOS kernel image + application
	 */

	/* this used to be the top of memory, but was wrong... */
#ifdef CONFIG_PPC
	/* get stack pointer */
	asm volatile ("mr %0,1" : "=r"(top) );
#endif
	debug ("## Current stack ends at 0x%08lX ", top);

	top -= 2048;		/* just to be sure */
	if (top > CFG_BOOTMAPSZ)
		top = CFG_BOOTMAPSZ;
	top &= ~0xF;

	debug ("=> set upper limit to 0x%08lX\n", top);

	/* first check the artos specific boot args, then the linux args*/
	if ((s = getenv("abootargs")) == NULL && (s = getenv("bootargs")) == NULL)
		s = "";

	/* get length of cmdline, and place it */
	len = strlen(s);
	top = (top - (len + 1)) & ~0xF;
	cmdline = (char *)top;
	debug ("## cmdline at 0x%08lX ", top);
	strcpy(cmdline, s);

	/* copy bdinfo */
	top = (top - sizeof(bd_t)) & ~0xF;
	debug ("## bd at 0x%08lX ", top);
	kbd = (bd_t *)top;
	memcpy(kbd, gd->bd, sizeof(bd_t));

	/* first find number of env entries, and their size */
	envno = 0;
	envsz = 0;
	for (i = 0; env_get_char(i) != '\0'; i = nxt + 1) {
		for (nxt = i; env_get_char(nxt) != '\0'; ++nxt)
			;
		envno++;
		envsz += (nxt - i) + 1;	/* plus trailing zero */
	}
	envno++;	/* plus the terminating zero */
	debug ("## %u envvars total size %u ", envno, envsz);

	top = (top - sizeof(char **)*envno) & ~0xF;
	fwenv = (char **)top;
	debug ("## fwenv at 0x%08lX ", top);

	top = (top - envsz) & ~0xF;
	s = (char *)top;
	ss = fwenv;

	/* now copy them */
	for (i = 0; env_get_char(i) != '\0'; i = nxt + 1) {
		for (nxt = i; env_get_char(nxt) != '\0'; ++nxt)
			;
		*ss++ = s;
		for (j = i; j < nxt; ++j)
			*s++ = env_get_char(j);
		*s++ = '\0';
	}
	*ss++ = NULL;	/* terminate */

	entry = (void (*)(bd_t *, char *, char **, ulong))ntohl(hdr->ih_ep);
	(*entry)(kbd, cmdline, fwenv, top);
}
#endif


#if (CONFIG_COMMANDS & CFG_CMD_BOOTD)
int do_bootd (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	int rcode = 0;
#ifndef CFG_HUSH_PARSER
	if (run_command (getenv ("bootcmd"), flag) < 0) rcode = 1;
#else
	if (parse_string_outer(getenv("bootcmd"),
		FLAG_PARSE_SEMICOLON | FLAG_EXIT_FROM_LOOP) != 0 ) rcode = 1;
#endif
	return rcode;
}

U_BOOT_CMD(
 	boot,	1,	1,	do_bootd,
 	"boot    - boot default, i.e., run 'bootcmd'\n",
	NULL
);

/* keep old command name "bootd" for backward compatibility */
U_BOOT_CMD(
 	bootd, 1,	1,	do_bootd,
 	"bootd   - boot default, i.e., run 'bootcmd'\n",
	NULL
);

#endif

#if (CONFIG_COMMANDS & CFG_CMD_IMI)
#ifdef RT2880_U_BOOT_CMD_OPEN
int do_iminfo ( cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	int	arg;
	ulong	addr;
	int     rcode=0;

	if (argc < 2) {
		return image_info (load_addr);
	}

	for (arg=1; arg <argc; ++arg) {
		addr = simple_strtoul(argv[arg], NULL, 16);
		if (image_info (addr) != 0) rcode = 1;
	}

	return rcode;
}

static int image_info (ulong addr)
{

	ulong	data, len, checksum;
	image_header_t *hdr = &header;

	printf ("\n## Checking Image at %08lx ...\n", addr);

	/* Copy header so we can blank CRC field for re-calculation */
	memmove (&header, (char *)addr, sizeof(image_header_t));

	if (ntohl(hdr->ih_magic) != IH_MAGIC) {
		puts ("   Bad Magic Number\n");
		return 1;
	}

	data = (ulong)&header;
	len  = sizeof(image_header_t);

	checksum = ntohl(hdr->ih_hcrc);
	hdr->ih_hcrc = 0;

	if (crc32 (0, (char *)data, len) != checksum) {
		puts ("   Bad Header Checksum\n");
		return 1;
	}

	/* for multi-file images we need the data part, too */
	print_image_hdr ((image_header_t *)addr);

	data = addr + sizeof(image_header_t);
	len  = ntohl(hdr->ih_size);

	puts ("   Verifying Checksum ... ");
	if (crc32 (0, (char *)data, len) != ntohl(hdr->ih_dcrc)) {
		puts ("   Bad Data CRC\n");
		return 1;
	}
	puts ("OK\n");
	
	return 0;
}
#endif

#ifdef RT2880_U_BOOT_CMD_OPEN
U_BOOT_CMD(
	iminfo,	CFG_MAXARGS,	1,	do_iminfo,
	"iminfo  - print header information for application image\n",
	"addr [addr ...]\n"
	"    - print header information for application image starting at\n"
	"      address 'addr' in memory; this includes verification of the\n"
	"      image contents (magic number, header and payload checksums)\n"
);
#endif
#endif	/* CFG_CMD_IMI */

#if (CONFIG_COMMANDS & CFG_CMD_IMLS)
/*-----------------------------------------------------------------------
 * List all images found in flash.
 */
#ifdef RT2880_U_BOOT_CMD_OPEN
 
int do_imls (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{


	flash_info_t *info;
	int i, j;
	image_header_t *hdr;
	ulong data, len, checksum;

	for (i=0, info=&flash_info[0]; i<CFG_MAX_FLASH_BANKS; ++i, ++info) {
		if (info->flash_id == FLASH_UNKNOWN)
			goto next_bank;
		for (j=0; j<CFG_MAX_FLASH_SECT; ++j) {

			if (!(hdr=(image_header_t *)info->start[j]) ||
			    (ntohl(hdr->ih_magic) != IH_MAGIC))
				goto next_sector;

			/* Copy header so we can blank CRC field for re-calculation */
			memmove (&header, (char *)hdr, sizeof(image_header_t));

			checksum = ntohl(header.ih_hcrc);
			header.ih_hcrc = 0;

			if (crc32 (0, (char *)&header, sizeof(image_header_t))
			    != checksum)
				goto next_sector;

			printf ("Image at %08lX:\n", (ulong)hdr);
			print_image_hdr( hdr );

			data = (ulong)hdr + sizeof(image_header_t);
			len  = ntohl(hdr->ih_size);

			puts ("   Verifying Checksum ... ");
			if (crc32 (0, (char *)data, len) != ntohl(hdr->ih_dcrc)) {
				puts ("   Bad Data CRC\n");
			}
			puts ("OK\n");
next_sector:		;
		}
next_bank:	;
	}

	return (0);
}

U_BOOT_CMD(
	imls,	1,		1,	do_imls,
	"imls    - list all images found in flash\n",
	"\n"
	"    - Prints information about all images found at sector\n"
	"      boundaries in flash.\n"
);
#endif

#endif	/* CFG_CMD_IMLS */

void
print_image_hdr (image_header_t *hdr)
{
#if (CONFIG_COMMANDS & CFG_CMD_DATE) || defined(CONFIG_TIMESTAMP)
	time_t timestamp = (time_t)ntohl(hdr->ih_time);
	struct rtc_time tm;
#endif

	printf ("   Image Name:   %.*s\n", IH_NMLEN, hdr->ih_name);
#if (CONFIG_COMMANDS & CFG_CMD_DATE) || defined(CONFIG_TIMESTAMP)
	to_tm (timestamp, &tm);
	printf ("   Created:      %4d-%02d-%02d  %2d:%02d:%02d UTC\n",
		tm.tm_year, tm.tm_mon, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
#endif	/* CFG_CMD_DATE, CONFIG_TIMESTAMP */

	puts ("   Image Type:   "); print_type(hdr);
	printf ("\n   Data Size:    %d Bytes = ", ntohl(hdr->ih_size));
	print_size (ntohl(hdr->ih_size), "\n");
	printf ("   Load Address: %08x\n"
		"   Entry Point:  %08x\n",
		 ntohl(hdr->ih_load), ntohl(hdr->ih_ep));

#ifdef IH_TYPE_MULTI_SUPPORT
	if (hdr->ih_type == IH_TYPE_MULTI) {
		int i;
		ulong len;
		ulong *len_ptr = (ulong *)((ulong)hdr + sizeof(image_header_t));

		puts ("   Contents:\n");
		for (i=0; (len = ntohl(*len_ptr)); ++i, ++len_ptr) {
			printf ("   Image %d: %8ld Bytes = ", i, len);
			print_size (len, "\n");
		}
	}
#endif // IH_TYPE_MULTI_SUPPORT //
}


static void
print_type (image_header_t *hdr)
{
	char *os, *arch, *type, *comp;

	switch (hdr->ih_os) {
	case IH_OS_INVALID:	os = "Invalid OS";		break;
	case IH_OS_NETBSD:	os = "NetBSD";			break;
	case IH_OS_LINUX:	os = "Linux";			break;
	case IH_OS_VXWORKS:	os = "VxWorks";			break;
	case IH_OS_QNX:		os = "QNX";			break;
	case IH_OS_U_BOOT:	os = "U-Boot";			break;
	case IH_OS_RTEMS:	os = "RTEMS";			break;
#ifdef CONFIG_ARTOS
	case IH_OS_ARTOS:	os = "ARTOS";			break;
#endif
#ifdef CONFIG_LYNXKDI
	case IH_OS_LYNXOS:	os = "LynxOS";			break;
#endif
	default:		os = "Unknown OS";		break;
	}

	switch (hdr->ih_arch) {
	case IH_CPU_INVALID:	arch = "Invalid CPU";		break;
	case IH_CPU_ALPHA:	arch = "Alpha";			break;
	case IH_CPU_ARM:	arch = "ARM";			break;
	case IH_CPU_I386:	arch = "Intel x86";		break;
	case IH_CPU_IA64:	arch = "IA64";			break;
	case IH_CPU_MIPS:	arch = "MIPS";			break;
	case IH_CPU_MIPS64:	arch = "MIPS 64 Bit";		break;
	case IH_CPU_PPC:	arch = "PowerPC";		break;
	case IH_CPU_S390:	arch = "IBM S390";		break;
	case IH_CPU_SH:		arch = "SuperH";		break;
	case IH_CPU_SPARC:	arch = "SPARC";			break;
	case IH_CPU_SPARC64:	arch = "SPARC 64 Bit";		break;
	case IH_CPU_M68K:	arch = "M68K"; 			break;
	case IH_CPU_MICROBLAZE:	arch = "Microblaze"; 		break;
	default:		arch = "Unknown Architecture";	break;
	}

	switch (hdr->ih_type) {
	case IH_TYPE_INVALID:	type = "Invalid Image";		break;
#ifdef IH_TYPE_STANDALONE_SUPPORT
	case IH_TYPE_STANDALONE:type = "Standalone Program";	break;
#endif // IH_TYPE_STANDALONE_SUPPORT //
	case IH_TYPE_KERNEL:	type = "Kernel Image";		break;
	case IH_TYPE_RAMDISK:	type = "RAMDisk Image";		break;
#ifdef IH_TYPE_MULTI_SUPPORT
	case IH_TYPE_MULTI:	type = "Multi-File Image";	break;
#endif // IH_TYPE_MULTI_SUPPORT //
	case IH_TYPE_FIRMWARE:	type = "Firmware";		break;
	case IH_TYPE_SCRIPT:	type = "Script";		break;
	default:		type = "Unknown Image";		break;
	}

	switch (hdr->ih_comp) {
	case IH_COMP_NONE:	comp = "uncompressed";		break;
	case IH_COMP_GZIP:	comp = "gzip compressed";	break;
	case IH_COMP_BZIP2:	comp = "bzip2 compressed";	break;
	case IH_COMP_LZMA:      comp = "lzma compressed";       break;
	case IH_COMP_XZ:        comp = "xz compressed";         break;
	default:		comp = "unknown compression";	break;
	}

	printf ("%s %s %s (%s)", arch, os, type, comp);
}

#ifdef CONFIG_GZIP
#define	ZALLOC_ALIGNMENT	16

static void *zalloc(void *x, unsigned items, unsigned size)
{
	void *p;

	size *= items;
	size = (size + ZALLOC_ALIGNMENT - 1) & ~(ZALLOC_ALIGNMENT - 1);

	p = malloc (size);

	return (p);
}

static void zfree(void *x, void *addr, unsigned nb)
{
	free (addr);
}


#define HEAD_CRC	2
#define EXTRA_FIELD	4
#define ORIG_NAME	8
#define COMMENT		0x10
#define RESERVED	0xe0

#define DEFLATED	8

int gunzip(void *dst, int dstlen, unsigned char *src, unsigned long *lenp)
{
	z_stream s;
	int r, i, flags;

	/* skip header */
	i = 10;
	flags = src[3];
	if (src[2] != DEFLATED || (flags & RESERVED) != 0) {
		puts ("Error: Bad gzipped data\n");
		return (-1);
	}
	if ((flags & EXTRA_FIELD) != 0)
		i = 12 + src[10] + (src[11] << 8);
	if ((flags & ORIG_NAME) != 0)
		while (src[i++] != 0)
			;
	if ((flags & COMMENT) != 0)
		while (src[i++] != 0)
			;
	if ((flags & HEAD_CRC) != 0)
		i += 2;
	if (i >= *lenp) {
		puts ("Error: gunzip out of data in header\n");
		return (-1);
	}

	s.zalloc = zalloc;
	s.zfree = zfree;
#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
	s.outcb = (cb_func)WATCHDOG_RESET;
#else
	s.outcb = Z_NULL;
#endif	/* CONFIG_HW_WATCHDOG */

	r = inflateInit2(&s, -MAX_WBITS);
	if (r != Z_OK) {
		printf ("Error: inflateInit2() returned %d\n", r);
		return (-1);
	}
	s.next_in = src + i;
	s.avail_in = *lenp - i;
	s.next_out = dst;
	s.avail_out = dstlen;
	r = inflate(&s, Z_FINISH);
	if (r != Z_OK && r != Z_STREAM_END) {
		printf ("Error: inflate() returned %d\n", r);
		return (-1);
	}
	*lenp = s.next_out - (unsigned char *) dst;
	inflateEnd(&s);

	return (0);
}
#endif // CONFIG_GZIP //
#ifdef CONFIG_BZIP2
void bz_internal_error(int errcode)
{
	printf ("BZIP2 internal error %d\n", errcode);
}
#endif /* CONFIG_BZIP2 */

#ifdef CONFIG_RTEMS
static void
do_bootm_rtems (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[],
		ulong addr, ulong *len_ptr, int verify)
{
	DECLARE_GLOBAL_DATA_PTR;
	image_header_t *hdr = &header;
	void	(*entry_point)(bd_t *);

	entry_point = (void (*)(bd_t *)) hdr->ih_ep;

	printf ("## Transferring control to RTEMS (at address %08lx) ...\n",
		(ulong)entry_point);

	SHOW_BOOT_PROGRESS (15);

	/*
	 * RTEMS Parameters:
	 *   r3: ptr to board info data
	 */

	(*entry_point ) ( gd->bd );
}
#endif

#if (CONFIG_COMMANDS & CFG_CMD_ELF)
static void
do_bootm_vxworks (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[],
		  ulong addr, ulong *len_ptr, int verify)
{
	image_header_t *hdr = &header;
	char str[80];

	sprintf(str, "%x", hdr->ih_ep); /* write entry-point into string */
	setenv("loadaddr", str);
	do_bootvx(cmdtp, 0, 0, NULL);
}

static void
do_bootm_qnxelf (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[],
		 ulong addr, ulong *len_ptr, int verify)
{
	image_header_t *hdr = &header;
	char *local_args[2];
	char str[16];

	sprintf(str, "%x", hdr->ih_ep); /* write entry-point into string */
	local_args[0] = argv[0];
	local_args[1] = str;	/* and provide it via the arguments */
	do_bootelf(cmdtp, 0, 2, local_args);
}
#endif /* CFG_CMD_ELF */

#ifdef CONFIG_LYNXKDI
static void
do_bootm_lynxkdi (cmd_tbl_t *cmdtp, int flag,
		 int	argc, char *argv[],
		 ulong	addr,
		 ulong	*len_ptr,
		 int	verify)
{
	lynxkdi_boot( &header );
}

#endif /* CONFIG_LYNXKDI */

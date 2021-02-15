#include <iostream>
#include <cstdio>
#include <sys/stat.h>  
#define _CRT_SECURE_NO_WARNINGS
using namespace std;

bool compare_char(uint8_t* a, uint8_t* b, int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (a[i] != b[i])  return false;
    }
    return true;
}

long file_size2(char* filename)
{
    struct stat statbuf;
    stat(filename, &statbuf);
    long size = statbuf.st_size;
    return size;
}/*
file 1:
F20000: DE AD C0 DE FF FF FF FF     FF FF FF FF FF FF FF FF                                     85 19 03 20 0C 00 00 00     B1 B0 1E E4 FF FF FF FF 
F30000: FF FF FF FF FF FF FF FF     FF FF FF FF FF FF FF FF                                     85 19 03 20 0C 00 00 00     B1 B0 1E E4 FF FF FF FF
F40000: DE AD C0 DE 00 00 00 00     00 00 00 00 7B 20 20 22                                     85 19 03 20 0C 00 00 00     B1 B0 1E E4 FF FF FF FF

file2:
930000: DE AD C0 DE FF FF FF FF     FF FF FF FF FF FF FF FF                                     85 19 03 20 0C 00 00 00     B1 B0 1E E4 FF FF FF FF
940000: DE AD C0 DE 00 00 00 00     00 00 00 00 7B 20 20 22                                     85 19 03 20 0C 00 00 00     B1 B0 1E E4 FF FF FF FF        */

uint8_t deadc0deffffffff[] = { 0xDE, 0xAD, 0xC0, 0xDE, 0xFF, 0xFF, 0xFF, 0xFF,     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
uint8_t ffffffffffffffff[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
uint8_t deadc0de00000000[] = { 0xDE, 0xAD ,0xC0, 0xDE, 0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00, 0x7B, 0x20, 0x20, 0x22 };
uint8_t _851903200C000000[] ={ 0x85, 0x19 ,0x03, 0x20 ,0x0C ,0x00 ,0x00 ,0x00     ,0xB1 ,0xB0 ,0x1E, 0xE4, 0xFF, 0xFF, 0xFF, 0xFF };

int main()
{
    char init_filename[] = "../make_mtd8/bin_files_1/small3.bin";   //"../write_mtd/bin_files/big_init.bin";
    long init_file_length = file_size2(init_filename),i;
    FILE* init_file = fopen(init_filename, "rb");
    FILE* output_file = fopen("output_file.bin", "wb");
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


    printf("\nDone!\n");
    return 0;
}
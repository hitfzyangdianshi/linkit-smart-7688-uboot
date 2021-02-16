#include <iostream>
#include<cstdio>
#include <sys/stat.h>  
#define _CRT_SECURE_NO_WARNINGS
using namespace std;

long file_size2(const char* filename)
{
    struct stat statbuf;
    stat(filename, &statbuf);
    long size = statbuf.st_size;
    return size;
}

int main(int argc, char **argv)
{
    char* initfilepath, *outfilepath,c;
    if (argc == 2) {
        printf("argc==2\n");
        initfilepath = argv[1];
        char outfilepath_[] = "out_mtd3_minus_mtd6.bin";
        outfilepath = outfilepath_;
    }
    else if (argc == 3) {
        printf("argc==3");
        initfilepath = argv[1];
        outfilepath = argv[2];
    }
    else {
        printf("argc!=2 or 3\n");
        char initfilepath_[] = "init.bin", outfilepath_[]="out_mtd3_minus_mtd6.bin";
        initfilepath = initfilepath_;
        outfilepath = outfilepath_;
    }

    long initsize = file_size2(initfilepath);
    long outsize = initsize - 0x357,i;
    printf("initsize: %d  \noutsize: %d\n", initsize, outsize);

    FILE* initfw = fopen(initfilepath, "rb");
    FILE* outcutfw = fopen(outfilepath, "wb");
    for (i = 0; i < outsize; i++) {
        c = fgetc(initfw);
        fputc(c, outcutfw);
    }


    return 0;
}



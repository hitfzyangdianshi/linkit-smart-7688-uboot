// make_mtd3_bin.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <cstdio>
#include <sys/stat.h>  
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

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

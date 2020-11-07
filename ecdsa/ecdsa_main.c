/*# find your curve
openssl ecparam -list_curves

# generate a private key for a curve
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

# generate corresponding public key
openssl ec -in private-key.pem -pubout -out public-key.pem

# optional: create a self-signed certificate
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360

# optional: convert pem to pfx
cat private-key.pem cert.pem > cert-with-private-key
openssl pkcs12 -export -inkey private-key.pem -in cert-with-private-key -out cert.pfx*/

#include<openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include<stdio.h>
#include<string.h>

//#include "ecdsa_f.c"

//#define TEST_INCORRECT_SIGNATURE
#ifdef TEST_INCORRECT_SIGNATURE
const char* publickeyfile = "publickeytest.pem";//publickeytest.pem , public-key.pem
#else //TEST_INCORRECT_SIGNATURE
const char* publickeyfile = "public-key.pem";//publickeytest.pem , public-key.pem
#endif //TEST_INCORRECT_SIGNATURE
const char* privatekeyfile = "private-key.pem";

#define PRIVATE "static unsigned char privkey[%d]={"
#define PUBLIC "static const unsigned char pubkey[%d]={"
#define ENDKEY "\n};\n"
#define SIGN "static unsigned char signature[%d]={"

char digest[] = "11111111111111111111111111111111";
#define TEST4

#ifdef TEST0
int test0() {

    int        ret;
    ECDSA_SIG* sig;
    EC_KEY* eckey;
    //EC_KEY* eckeypri,eckeypub;
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    //if (eckey == NULL) {
    //    /* error */
    //    printf("eckey == NULL\n");
    //}
    //if (EC_KEY_generate_key(eckey) == 0) {
    //    /* error */
    //    printf("EC_KEY_generate_key(eckey) == 0\n");
    //}


    /*BIO* pBio = BIO_new_file("publickeytest.pem", "wb");
    PEM_write_bio_EC_PUBKEY(pBio, eckey);*/

    BIO* pBIOprivate = BIO_new_file(privatekeyfile, "rb");
    PEM_read_bio_ECPrivateKey(pBIOprivate, &eckey, NULL, NULL);


    sig = ECDSA_do_sign(digest, 32, eckey);
    if (sig == NULL) {
        /* error */
        printf("sig == NULL\n");
    }

    BIO* pBIOpublic = BIO_new_file(publickeyfile, "rb");
    PEM_read_bio_EC_PUBKEY(pBIOpublic, &eckey, NULL, NULL);

    ret = ECDSA_do_verify(digest, 32, sig, eckey);


    if (ret == 1) {
        /* signature ok */
        printf("ok\n");
    }
    else if (ret == 0) {
        /* incorrect signature */
        printf("incorrect signature\n");
    }
    else {
        /* error */
        printf("error\n");
    }

    return 0;
}
#endif //TEST0

#ifdef TEST1



int test1() {
    ECDSA_SIG* sig;
    EC_KEY* eckey;
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    BIO* pBIOprivate = BIO_new_file(privatekeyfile, "rb");
    PEM_read_bio_ECPrivateKey(pBIOprivate, &eckey, NULL, NULL);

    unsigned char buf[1024];
    unsigned char* pp;
    int i, len;

    pp = buf;
    len = i2d_ECPrivateKey(eckey, &pp);
    if (!len) {
        printf("error,i2d_ECPrivateKey(eckey, &pp); \n ");
        EC_KEY_free(eckey);
    }

    printf(PRIVATE, len);
    for (i = 0; i < len; i++) {
        if (!(i % 8))
            printf("\n");
        if (i == len - 1)
            printf("0x%02X ", buf[i]);
        else
            printf("0x%02X , ", buf[i]);
    }
    printf(ENDKEY);



    return 0;
}
#endif // TEST1

#ifdef TEST2



int test2() {
    ECDSA_SIG* sig;
    EC_KEY* eckey;
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    BIO* pBIOpublic = BIO_new_file(publickeyfile, "rb");
    PEM_read_bio_EC_PUBKEY(pBIOpublic, &eckey, NULL, NULL);

    unsigned char buf[1024];
    unsigned char* pp;
    int i, len;

    pp = buf;
    len = i2o_ECPublicKey(eckey, &pp);
    if (!len) {
        printf("error, i2o_ECPublicKey(eckey, &pp); \n ");
        EC_KEY_free(eckey);
    }

    printf(PUBLIC, len);
    for (i = 0; i < len; i++) {
        if (!(i % 8))
            printf("\n");
        if (i == len - 1)
            printf("0x%02X ", buf[i]);
        else
            printf("0x%02X , ", buf[i]);
    }
    printf(ENDKEY);



    return 0;
}
#endif // TEST2

#ifdef TEST3 
static unsigned char privkey[121] = {
0x30 , 0x77 , 0x02 , 0x01 , 0x01 , 0x04 , 0x20 , 0x82 ,
0x8B , 0x01 , 0x85 , 0x55 , 0x41 , 0x52 , 0xC1 , 0xAB ,
0xA6 , 0x57 , 0x78 , 0x9B , 0xB3 , 0x6E , 0x5B , 0x7B ,
0x6B , 0x57 , 0x1A , 0x29 , 0xA8 , 0xA2 , 0x6C , 0x3D ,
0xEA , 0xF1 , 0x7D , 0xCD , 0x34 , 0xB1 , 0xF5 , 0xA0 ,
0x0A , 0x06 , 0x08 , 0x2A , 0x86 , 0x48 , 0xCE , 0x3D ,
0x03 , 0x01 , 0x07 , 0xA1 , 0x44 , 0x03 , 0x42 , 0x00 ,
0x04 , 0x93 , 0x7B , 0x5D , 0x1D , 0x27 , 0xEC , 0xA7 ,
0xE8 , 0xEC , 0xD1 , 0x31 , 0xE8 , 0x93 , 0x16 , 0x83 ,
0xB5 , 0x2C , 0x9E , 0xF4 , 0x05 , 0xDA , 0xBC , 0x1F ,
0xB4 , 0x29 , 0x5B , 0x97 , 0x0A , 0xEC , 0xD1 , 0x2A ,
0xA3 , 0x20 , 0x73 , 0xB1 , 0x1F , 0x3A , 0x42 , 0xE7 ,
0x9B , 0x60 , 0xAA , 0x6C , 0x4E , 0x31 , 0x28 , 0x30 ,
0x2A , 0x97 , 0x26 , 0xEB , 0x50 , 0x3C , 0x98 , 0x87 ,
0x8A , 0x1C , 0x7D , 0xB4 , 0x04 , 0x92 , 0xDD , 0xAB ,
0xD4
};

static const unsigned char pubkey[65] = {
0x04 , 0x93 , 0x7B , 0x5D , 0x1D , 0x27 , 0xEC , 0xA7 ,
0xE8 , 0xEC , 0xD1 , 0x31 , 0xE8 , 0x93 , 0x16 , 0x83 ,
0xB5 , 0x2C , 0x9E , 0xF4 , 0x05 , 0xDA , 0xBC , 0x1F ,
0xB4 , 0x29 , 0x5B , 0x97 , 0x0A , 0xEC , 0xD1 , 0x2A ,
0xA3 , 0x20 , 0x73 , 0xB1 , 0x1F , 0x3A , 0x42 , 0xE7 ,
0x9B , 0x60 , 0xAA , 0x6C , 0x4E , 0x31 , 0x28 , 0x30 ,
0x2A , 0x97 , 0x26 , 0xEB , 0x50 , 0x3C , 0x98 , 0x87 ,
0x8A , 0x1C , 0x7D , 0xB4 , 0x04 , 0x92 , 0xDD , 0xAB ,
0xD4
};

#define ENDKEY "\n};\n"
#define MAXSIGLEN 128

int test3() {
    unsigned int sign_len = MAXSIGLEN;
    ECDSA_SIG* sig;
    EC_KEY* eckey = NULL;
    //eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    unsigned char* pp = (unsigned char*)privkey;
    eckey = d2i_ECPrivateKey(&eckey, (const unsigned char**)&pp, sizeof(privkey));
    if (eckey == NULL) {
        printf("error, eckey = d2i_ECPrivateKey(&eckey, (const unsigned char**)&pp, sizeof(privkey)); eckey == NULL\n");
        return -1;
    }
    sig = ECDSA_do_sign(digest, 32, eckey);
    if (sig == NULL) {
        /* error */
        printf("sig == NULL\n");
        return -1;
    }
    unsigned char buf[1024];
    unsigned char* pp1;
    pp = buf;
    int i, len;
    len = i2d_ECDSA_SIG(sig, &pp1);
    if (!len) {
        printf("error, i2d_ECDSA_SIG(sig, &pp1); \n ");
        return -1;
    }
    printf(SIGN, len);
    for (i = 0; i < len; i++) {
        if (!(i % 8))
            printf("\n");
        if (i == len - 1)
            printf("0x%02X ", buf[i]);
        else
            printf("0x%02X , ", buf[i]);
    }

    return 0;

}

#endif // TEST3






#ifdef TEST4
int test4() {
    char* privatekey = "\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIIKLAYVVQVLBq6ZXeJuzblt7a1caKaiibD3q8X3NNLH1oAoGCCqGSM49\n\
AwEHoUQDQgAEk3tdHSfsp+js0THokxaDtSye9AXavB+0KVuXCuzRKqMgc7EfOkLn\n\
m2CqbE4xKDAqlybrUDyYh4ocfbQEkt2r1A==\n\
-----END EC PRIVATE KEY-----";
    ECDSA_SIG* sig;
    EC_KEY* eckey;
    int ret;
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    BIO* biopr = BIO_new_mem_buf(privatekey, strlen(privatekey));
    if (biopr == NULL) {
        printf("error, biopr == NULL \n ");
        return -1;
    }
    //EC_KEY_free(eckey);
    eckey = PEM_read_bio_ECPrivateKey(biopr, &eckey, NULL, NULL);
    if (eckey == NULL) {
        printf("error, eckey = PEM_read_bio_ECPrivateKey(biopr, &eckey, NULL, NULL); \n");
        return -1;
    }

    sig = ECDSA_do_sign(digest, strlen(digest), eckey);//32
    if (sig == NULL) {
        /* error */
        printf("sig == NULL\n");
        return -1;
    }

    //printf("(sig->r, sig->s): (%s,%s)", BN_bn2hex(sig->r), BN_bn2hex(sig->s));
    unsigned char buf[1024];
    unsigned char* pp;
    pp = buf;
    int i, len;
    len = i2d_ECDSA_SIG(sig, &pp);
    if (!len) {
        printf("error, i2d_ECDSA_SIG(sig,&pp); \n ");
        return -1;
    }
    for (i = 0; i < len; i++)
        printf("%c", buf[i]);
    printf("\nsig length= %d\n", len);
    printf(SIGN, len);
    for (i = 0; i < len; i++) {
        if (!(i % 8))
            printf("\n");
        if (i == len - 1)
            printf("0x%02X ", buf[i]);
        else
            printf("0x%02X , ", buf[i]);
    }
    printf("};\n");

    char* publickey = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3tdHSfsp+js0THokxaDtSye9AXa\n\
vB+0KVuXCuzRKqMgc7EfOkLnm2CqbE4xKDAqlybrUDyYh4ocfbQEkt2r1A==\n\
-----END PUBLIC KEY-----";
    char* publickey_wrong_incorrect = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5kf6AvYDktru4WWb8KK6qAyfQpi7\n\
LhCpGwIx6nRDNtTy//A2fBjyvB5cKWkJtv68ZAyQ3WE9k5hTGdzuDBv/jg==\n\
-----END PUBLIC KEY-----";

    BIO* biopub = BIO_new_mem_buf(publickey, strlen(publickey));
    eckey = PEM_read_bio_EC_PUBKEY(biopub, &eckey, NULL, NULL);
    if (eckey == NULL) {
        printf("error, eckey = PEM_read_bio_EC_PUBKEY(biopub, & eckey, NULL, NULL); \n");
        return -1;
    }



    ret = ECDSA_do_verify(digest, strlen(digest), sig, eckey);


    if (ret == 1) {
        /* signature ok */
        printf("ok\n");
    }
    else if (ret == 0) {
        /* incorrect signature */
        printf("incorrect signature\n");
    }
    else {
        /* error */
        printf("error, ECDSA_do_verify\n");
    }






    const unsigned char signature_test0[71] = {
0x30 , 0x45 , 0x02 , 0x20 , 0x5B , 0xDA , 0x92 , 0x9D ,
0xFA , 0x81 , 0x26 , 0xB2 , 0x49 , 0x24 , 0x96 , 0xB4 ,
0x63 , 0x49 , 0xD1 , 0x6D , 0x09 , 0x61 , 0xBA , 0x50 ,
0x84 , 0x8F , 0xED , 0x77 , 0x49 , 0xE6 , 0x8E , 0x6B ,
0x82 , 0xE9 , 0x04 , 0x73 , 0x02 , 0x21 , 0x00 , 0xE7 ,
0x7B , 0x68 , 0xCF , 0x24 , 0xBC , 0xD4 , 0xF0 , 0x1B ,
0x85 , 0x13 , 0xD0 , 0xA1 , 0x64 , 0x34 , 0xB2 , 0x3B ,
0x38 , 0x18 , 0x0A , 0x95 , 0x7F , 0xF7 , 0x31 , 0x73 ,
0x82 , 0x15 , 0xE1 , 0x63 , 0x6A , 0xCB , 0x20 };
    //ECDSA_SIG* sig_test;
    //sig_test = d2i_ECDSA_SIG(&sig_test, (const unsigned char*)&signature_test0, sizeof(signature_test0));
    //if (sig_test == NULL) {
    //    /* error */
    //    printf("error, sig_test == NULL\n");
    //    return -2;
    //}

    //ret = ECDSA_do_verify(digest, strlen(digest), sig_test, eckey);
    ret = ECDSA_verify(0, (const unsigned char*)digest, strlen(digest), signature_test0, sizeof(signature_test0), eckey);
    if (ret == 1) {
        /* signature ok */
        printf("ok\n");
    }
    else if (ret == 0) {
        /* incorrect signature */
        printf("incorrect signature\n");
    }
    else {
        /* error */
        printf("error, ECDSA_do_verify\n");
    }



    return 0;


}

#endif // TEST4




int main() {

    test4();
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


    printf("test ecdsa_sign_and_verify: \n");
    ecdsa_sign_and_verify(privatekey, publickey, digest);

    printf("\n\ntest ecdsa_verify_signature: \n");
    ecdsa_verify_signature(publickey, signature_test0, sizeof(signature_test0), digest);
    return 0;
}







#define BOOTLOADER_BIN_FILENAME "lks7688.ldr"

//https://www.scottbrady91.com/OpenSSL/Creating-Elliptical-Curve-Keys-using-OpenSSL
//https://wenku.baidu.com/view/cd1de8cdba0d4a7303763a29.htmlrn#
//https://www.openssl.org/docs/man1.1.0/man3/ECDSA_do_sign.html
//https://www.openssl.org/docs/man1.0.2/man3/i2d_ECDSA_SIG.html
//https://blog.csdn.net/jiangwlee/article/details/11817579
//https://www.cnblogs.com/LiuYanYGZ/p/12540577.html
//https://zhuanlan.zhihu.com/p/31671646#:~:text=%E6%A4%AD%E5%9C%86%E6%9B%B2%E7%BA%BF%E6%95%B0%E5%AD%97%E7%AD%BE%E5%90%8D%E7%AE%97%E6%B3%95,ISO%E7%9A%84%E8%80%83%E8%99%91%E4%B9%8B%E4%B8%AD%E3%80%82
//https://openssl-programing.readthedocs.io/en/latest/20.html#opensslecc
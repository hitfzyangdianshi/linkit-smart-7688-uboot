#include<openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include<stdio.h>
#include<string.h>



#define SIGN "static unsigned char signature[%d]={"

int ecdsa_sign_and_verify(char* privatekey, char* publickey, char* digest) {
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



    return 0;
}



int ecdsa_verify_signature(char * publickey, char *signature,int signature_length ,char *digest) {
   
    ECDSA_SIG* sig;
    EC_KEY* eckey;
    int ret;
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);


    BIO* biopub = BIO_new_mem_buf(publickey, strlen(publickey));
    eckey = PEM_read_bio_EC_PUBKEY(biopub, &eckey, NULL, NULL);
    if (eckey == NULL) {
        printf("error, eckey = PEM_read_bio_EC_PUBKEY(biopub, & eckey, NULL, NULL); \n");
        return -1;
    }


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
    //ECDSA_SIG* sig_test;
    //sig_test = d2i_ECDSA_SIG(&sig_test, (const unsigned char*)&signature_test0, sizeof(signature_test0));
    //if (sig_test == NULL) {
    //    /* error */
    //    printf("error, sig_test == NULL\n");
    //    return -2;
    //}

    //ret = ECDSA_do_verify(digest, strlen(digest), sig_test, eckey);
    ret = ECDSA_verify(0, (const unsigned char*)digest, strlen(digest), (const unsigned char*)signature, signature_length, eckey);
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
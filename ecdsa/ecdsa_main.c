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
//https://www.scottbrady91.com/OpenSSL/Creating-Elliptical-Curve-Keys-using-OpenSSL

#include<openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include<stdio.h>
#include<string.h>

#define TEST_INCORRECT_SIGNATURE
#ifdef TEST_INCORRECT_SIGNATURE
const char* publickeyfile = "publickeytest.pem";//publickeytest.pem , public-key.pem
#else
const char* publickeyfile = "public-key.pem";//publickeytest.pem , public-key.pem
#endif
const char* privatekeyfile = "private-key.pem";


int main() {

    char digest[] = "11111111111111111111111111111111";
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

    BIO* pBIOprivate= BIO_new_file(privatekeyfile, "rb");
    PEM_read_bio_ECPrivateKey(pBIOprivate, &eckey,NULL,NULL);


    sig = ECDSA_do_sign(digest, 32, eckey);
    if (sig == NULL) {
        /* error */
        printf("sig == NULL\n");
    }
    
    BIO* pBIOpublic = BIO_new_file(publickeyfile, "rb");
    PEM_read_bio_EC_PUBKEY(pBIOpublic, &eckey,NULL,NULL);

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






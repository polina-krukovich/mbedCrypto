#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/aes.h>
#include <assert.h>
#include "aes.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "pbkdf2.h"
#include "drbg.h"

#include "hmac_sha1.h"
#include "hmac_sha256.h"
#include "hmac_sha512.h"
#include "kbkdf.h"
#include "pbkdf2.h"


void print_arr(uint8_t *data, uint32_t data_len)
{
    for (int i = 0; i < data_len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

#define DATA_SIZE 256

char sha_test[][DATA_SIZE] = 
{
    "f43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgjf43wigjoeirgj",
    "dfgdsfgwrdfgdsfgwrdfgdsfgwrdfgdsfgwrdfgdsfgwrdfgdsfgwrdfgdsfgwrdfgdsfgwrdfgdsfgwrdfgdsfgwr",
    "fewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwkfewfjwk",
    "qweflkwje",
    "feklwqfjewk",
    "djkfdfajsdjkdjkfdfajsdjkdjkfdfajsdjkdjkfdfajsdjkdjkfdfajsdjkdjkfdfajsdkdjkfdfajsdjk",
    "11212",
    "123",
    "flkds;lafddddddddddddddddddddddddddddddddddddddddddlfklskdlfksldkflsdfkld",
};
const uint8_t sha_test_len = sizeof(sha_test)/DATA_SIZE;


#define TEST_SHA1
#define TEST_SHA256
#define TEST_SHA512
#define TEST_HMAC_SHA1
#define TEST_HMAC_SHA256
#define TEST_HMAC_SHA512
#define TEST_PBKDF2
#define TEST_KBKDF
#define TEST_DRBG
#define TEST_ENTROPY
#define TEST_RSA
#define TEST_AES
#define TEST_RC4
#define TEST_BLOWFISH
#define TEST_CHACHA
#define TEST_SALSA20
#define TEST_DH



#if defined(TEST_SHA1)

void test_sha1()
{
    printf("SHA1 test\n");
    uint8_t *out[SHA1_HASH_SIZE];
    uint8_t *out1[SHA1_HASH_SIZE];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        sha1_t ctx;
        sha1_init(&ctx);
        for (int j = 0; j < DATA_SIZE; j++)
            sha1_update(&ctx, &sha_test[i][j], 1);
        sha1_finish(&ctx, out);
        
        print_arr(out, SHA1_HASH_SIZE);

        SHA1(sha_test[i], DATA_SIZE, out1);
        print_arr(out1, SHA1_HASH_SIZE);
        if(!memcmp(out, out1, SHA1_HASH_SIZE)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("sha1 tests finished\n");
    assert(cnt == sha_test_len);
}

#endif /* TEST_SHA1 */


#if defined(TEST_SHA256)

void test_sha256()
{
    printf("SHA256 test\n");
    uint8_t *out[SHA256_HASH_SIZE];
    uint8_t *out1[SHA256_HASH_SIZE];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        sha256_t ctx;
        sha256_init(&ctx);
        for (int j = 0; j < DATA_SIZE; j++)
            sha256_update(&ctx, &sha_test[i][j], 1);
        sha256_finish(&ctx, out);
        
        print_arr(out, SHA256_HASH_SIZE);

        SHA256(sha_test[i], DATA_SIZE, out1);
        print_arr(out1, SHA256_HASH_SIZE);
        if(!memcmp(out, out1, SHA256_HASH_SIZE)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("sha256 tests finished\n");
    assert(cnt == sha_test_len);
}

#endif /* TEST_SHA256 */


#if defined(TEST_SHA512)

void test_sha512()
{
    printf("SHA512 test\n");
    uint8_t *out[SHA512_HASH_SIZE];
    uint8_t *out1[SHA512_HASH_SIZE];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        sha512_t ctx;
        sha512_init(&ctx);
        for (int j = 0; j < DATA_SIZE; j++)
            sha512_update(&ctx, &sha_test[i][j], 1);
        sha512_finish(&ctx, out);
        
        print_arr(out, SHA512_HASH_SIZE);

        SHA512(sha_test[i], DATA_SIZE, out1);
        print_arr(out1, SHA512_HASH_SIZE);
        if(!memcmp(out, out1, SHA512_HASH_SIZE)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("sha512 tests finished\n");
    assert(cnt == sha_test_len);
}

#endif /* TEST_SHA512 */


#if defined(TEST_HMAC_SHA1)

hmac_sha1_t hmac1;

uint32_t hmac1_init(uint8_t *key, uint32_t key_len)
{
     hmac_sha1_init(&hmac1, key, key_len);
     return 0;

}

uint32_t hmac1_update(uint8_t *data, uint32_t data_len)
{
     hmac_sha1_update(&hmac1, data, data_len);
     return 0;

}

uint32_t hmac1_final(uint8_t *hmac)
{
     hmac_sha1_finish(&hmac1, hmac);
     return 0;
}

void test_hmac_sha1()
{
    printf("HMAC_SHA1 test\n");
    uint8_t *out[SHA1_HASH_SIZE];
    uint8_t *out1[SHA1_HASH_SIZE];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        hmac_sha1_t ctx;
        hmac_sha1_init(&ctx, sha_test[i], strlen(sha_test[i]));
        for (int j = 0; j < strlen(sha_test[i]); j++)
            hmac_sha1_update(&ctx, &sha_test[i][j], 1);
        hmac_sha1_finish(&ctx, out);
        
        print_arr(out, SHA1_HASH_SIZE);
        uint32_t len;
        HMAC(EVP_sha1(), sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), out1, &len);
        print_arr(out1, SHA1_HASH_SIZE);
        if(!memcmp(out, out1, SHA1_HASH_SIZE)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("HMAC_sha1 tests finished\n");
    assert(cnt == sha_test_len);
}

#endif /* TEST_HMAC_SHA1 */


#if defined(TEST_HMAC_SHA256)

void test_hmac_sha256()
{
    printf("HMAC_sha256 test\n");
    uint8_t *out[SHA256_HASH_SIZE];
    uint8_t *out1[SHA256_HASH_SIZE];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        hmac_sha256_t ctx;
        hmac_sha256_init(&ctx, sha_test[i], strlen(sha_test[i]));
        for (int j = 0; j < strlen(sha_test[i]); j++)
            hmac_sha256_update(&ctx, &sha_test[i][j], 1);
        hmac_sha256_finish(&ctx, out);
        
        print_arr(out, SHA256_HASH_SIZE);
        uint32_t len;
        HMAC(EVP_sha256(), sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), out1, &len);
        print_arr(out1, SHA256_HASH_SIZE);
        if(!memcmp(out, out1, SHA256_HASH_SIZE)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("HMAC_sha256 tests finished\n");
    assert(cnt == sha_test_len);
}

#endif /* TEST_HMAC_SHA256 */


#if defined(TEST_HMAC_SHA512)

void test_hmac_sha512()
{
    printf("HMAC_sha512 test\n");
    uint8_t *out[SHA512_HASH_SIZE];
    uint8_t *out1[SHA512_HASH_SIZE];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        hmac_sha512_t ctx;
        hmac_sha512_init(&ctx, sha_test[i], strlen(sha_test[i]));
        for (int j = 0; j < strlen(sha_test[i]); j++)
            hmac_sha512_update(&ctx, &sha_test[i][j], 1);
        hmac_sha512_finish(&ctx, out);
        
        print_arr(out, SHA512_HASH_SIZE);
        uint32_t len;
        HMAC(EVP_sha512(), sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), out1, &len);
        print_arr(out1, SHA512_HASH_SIZE);
        if(!memcmp(out, out1, SHA512_HASH_SIZE)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("HMAC_sha512 tests finished\n");
    assert(cnt == sha_test_len);
}

#endif /* TEST_HMAC_SHA512 */


#if defined(TEST_PBKDF2)

void test_pbkdf2_hmac_sha1()
{
    printf("PBKDF2_HMAC_SHA1 test\n");
    uint8_t *out[32];
    uint8_t *out1[32];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        hmac_sha512_t ctx;

        pbkdf2_hmac_sha1(sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), 433, out, 32);

        print_arr(out, 32);
        PKCS5_PBKDF2_HMAC_SHA1(sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), 433, 32, out1);
        print_arr(out1, 32);
        if(!memcmp(out, out1, 32)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("PBKDF2_HMAC_SHA1 tests finished\n");
    assert(cnt == sha_test_len);
}
void test_pbkdf2_hmac_sha256()
{
    printf("PBKDF2_HMAC_SHA256 test\n");
    uint8_t *out[32];
    uint8_t *out1[32];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        hmac_sha256_t ctx;

        pbkdf2_hmac_sha256(sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), 433, out, 32);

        print_arr(out, 32);
        PKCS5_PBKDF2_HMAC(sha_test[i], strlen(sha_test[i]), sha_test[i], 
                        strlen(sha_test[i]), 433, EVP_sha256(), 32, out1);
        print_arr(out1, 32);
        if(!memcmp(out, out1, 32)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("PBKDF2_HMAC_SHA256 tests finished\n");
    assert(cnt == sha_test_len);
}

void test_pbkdf2_hmac_sha512()
{
    printf("PBKDF2_HMAC_SHA512 test\n");
    uint8_t *out[32];
    uint8_t *out1[32];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        hmac_sha512_t ctx;

        pbkdf2_hmac_sha512(sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), 433, out, 32);

        print_arr(out, 32);
        PKCS5_PBKDF2_HMAC(sha_test[i], strlen(sha_test[i]), sha_test[i], 
                        strlen(sha_test[i]), 433, EVP_sha512(), 32, out1);
        print_arr(out1, 32);
        if(!memcmp(out, out1, 32)){
            cnt++;
        } else {
            printf("ERROR!\n");
        }
        printf("===============================================\n");
    }
    printf("PBKDF2_HMAC_SHA512 tests finished\n");
    assert(cnt == sha_test_len);
}

#endif /* TEST_PBKDF2 */


#if defined(TEST_KBKDF)

void test_kbkdf_ctr()
{

}

void test_kbkdf_fb()
{
    
}

void test_kbkdf_dp()
{
    
}
#endif /* TEST_KBKDF */

#ifdef RRR

void aes_tests()
{
    uint8_t out1[128];

    uint8_t data[] = "1234567812345678123456781234567812345432234234234234234332";
    uint8_t iv[] = "1234567812345678";
    uint8_t key[] = "1234567812345678";

    aes_input_t in;
    aes_output_t out;

    in.data = data;
    in.data_len = sizeof(data) - 1;

    in.iv = iv;
    in.iv_len = sizeof(iv) - 1;

    in.key = key;
    in.key_len = sizeof(key) - 1;

    out.out = out1;
/* ECB */
    printf("##########################################################\n");
    printf("AES ECB test\n");

    memset(out.out, 0, 128);
    aes_encrypt(AES_ECB, AES128, AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("6DAC1C56E747FAE03ACF8C6891E428E06DAC1C56E747FAE03ACF8C6891E428E0D176DCCE30D0E5B0E5A1D726E706F7F16D4878ABC1B9FC4EB40C8AF75D4D5577\n");

/* CBC */ 
    printf("##########################################################\n");
    printf("AES CBC test\n");

    memset(out.out, 0, 128);
    aes_encrypt(AES_CBC, AES128, AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("6DAC1C56E747FAE03ACF8C6891E428E06DAC1C56E747FAE03ACF8C6891E428E0D176DCCE30D0E5B0E5A1D726E706F7F16D4878ABC1B9FC4EB40C8AF75D4D5577\n");


/* CFB */ 
    printf("##########################################################\n");
    printf("AES CFB test\n");

    memset(out.out, 0, 128);
    aes_encrypt(AES_CFB, AES128, AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("9AE8FD02B340288A0E7BBFF0F0BA54D67ABDAC9471AF10FB31CC31D23845D53E9728A7FDABB4D17DD6EC55090A39490A0D32898226DE6A9D02116889CC79977F\n");

/* OFB */ 
    printf("##########################################################\n");
    printf("AES OFB test\n");

    memset(out.out, 0, 128);
    aes_encrypt(AES_OFB, AES128, AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("9AE8FD02B340288A0E7BBFF0F0BA54D67ABDAC9471AF10FB31CC31D23845D53E9728A7FDABB4D17DD6EC55090A39490A0D32898226DE6A9D02116889CC79977F\n");


/* CTR */ 
    printf("##########################################################\n");
    printf("AES CTR test\n");

    memset(out.out, 0, 128);
    aes_encrypt(AES_CTR, AES128, AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("9AE8FD02B340288A0E7BBFF0F0BA54D67ABDAC9471AF10FB31CC31D23845D53E9728A7FDABB4D17DD6EC55090A39490A0D32898226DE6A9D02116889CC79977F\n");


/* XTS */ 
    printf("##########################################################\n");
    printf("AES XTS test\n");

    memset(out.out, 0, 128);
    aes_encrypt(AES_XTS, AES128, AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("9AE8FD02B340288A0E7BBFF0F0BA54D67ABDAC9471AF10FB31CC31D23845D53E9728A7FDABB4D17DD6EC55090A39490A0D32898226DE6A9D02116889CC79977F\n");
}
#endif

int main()
{


#if defined(TEST_SHA1)
    test_sha1();
#endif


#if defined(TEST_SHA256)
    test_sha256();
#endif


#if defined(TEST_SHA512)
    test_sha512();
#endif


#if defined(TEST_HMAC_SHA1)
    test_hmac_sha1();
#endif


#if defined(TEST_HMAC_SHA256)
    test_hmac_sha256();
#endif


#if defined(TEST_HMAC_SHA512)
    test_hmac_sha512();
#endif


#if defined(TEST_PBKDF2)
    test_pbkdf2_hmac_sha1();
    test_pbkdf2_hmac_sha256();
    test_pbkdf2_hmac_sha512();
#endif


#if defined(TEST_KBKDF)
    test_kbkdf_ctr();
    test_kbkdf_fb();
    test_kbkdf_dp();
#endif


#if defined(TEST_DRBG)
    test_drbg_ctr();
    test_drbg_hash();
    test_drbg_hmac();
#endif


#if defined(TEST_ENTROPY)
    test_entropy();
#endif


#if defined(TEST_RSA)
    test_rsa();
    test_rsa_pss();
#endif


#if defined(TEST_AES)
    test_aes_ecb();
    test_aes_cbc();
    test_aes_ofb();
    test_aes_cfb();
    test_aes_ctr();
    test_aes_xts();
    test_aes_aead();
#endif


#if defined(TEST_RC4)
    test_rc4();
#endif


#if defined(TEST_BLOWFISH)
    test_rc4();
#endif


#if defined(TEST_CHACHA)
    test_chacha();
#endif


#if defined(TEST_SALSA20)
    test_chacha();
#endif


#if defined(TEST_DH)
    test_dh();
#endif

  return 0;
}   
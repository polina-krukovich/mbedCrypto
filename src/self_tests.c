#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/aes.h>
#include <assert.h>

#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

#include "hmac.h"
#include "pbkdf2.h"
#include "kbkdf.h"


int s_mp_rand_source(void *out, size_t size){
    char *p = out;
    for (int i = 0; i < size; i++)
    {
        p[i] = rand() & 0xFF;
    }
    return 0;
}

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
//#define TEST_DRBG
//#define TEST_ENTROPY
//#define TEST_RSA
//#define TEST_AES
//#define TEST_RC4
//#define TEST_BLOWFISH
//#define TEST_CHACHA
//#define TEST_SALSA20
//#define TEST_DH



#if defined(TEST_SHA1)

void test_sha1()
{
    printf("SHA1 test\n");
    uint8_t *out[MBCRYPT_SHA1_HASH_SIZE];
    uint8_t *out1[MBCRYPT_SHA1_HASH_SIZE];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        mbcrypt_sha1_t ctx;
        mbcrypt_sha1_init(&ctx);
        for (int j = 0; j < DATA_SIZE; j++)
            mbcrypt_sha1_update(&ctx, &sha_test[i][j], 1);
        mbcrypt_sha1_final(&ctx, out);
        
        print_arr(out, MBCRYPT_SHA1_HASH_SIZE);

        SHA1(sha_test[i], DATA_SIZE, out1);
        print_arr(out1, MBCRYPT_SHA1_HASH_SIZE);
        if(!memcmp(out, out1, MBCRYPT_SHA1_HASH_SIZE)){
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
    const uint32_t hash_size = MBCRYPT_SHA256_HASH_SIZE;
    uint8_t *out[hash_size];
    uint8_t *out1[hash_size];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        mbcrypt_sha256_t ctx;
        mbcrypt_sha256_init(&ctx);
        for (int j = 0; j < DATA_SIZE; j++)
            mbcrypt_sha256_update(&ctx, &sha_test[i][j], 1);
        mbcrypt_sha256_final(&ctx, out);
        
        print_arr(out, hash_size);

        SHA256(sha_test[i], DATA_SIZE, out1);
        print_arr(out1, hash_size);
        if(!memcmp(out, out1, hash_size)){
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
    const uint32_t hash_size = MBCRYPT_SHA512_HASH_SIZE;
    uint8_t *out[hash_size];
    uint8_t *out1[hash_size];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        mbcrypt_sha512_t ctx;
        mbcrypt_sha512_init(&ctx);
        for (int j = 0; j < DATA_SIZE; j++)
            mbcrypt_sha512_update(&ctx, &sha_test[i][j], 1);
        mbcrypt_sha512_final(&ctx, out);
        
        print_arr(out, hash_size);

        SHA512(sha_test[i], DATA_SIZE, out1);
        print_arr(out1, hash_size);
        if(!memcmp(out, out1, hash_size)){
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

void test_hmac_sha1()
{
    printf("HMAC_SHA1 test\n");
    uint8_t *out[32];
    uint8_t *out1[32];
    int cnt = 0;
    uint32_t hash_size = GET_HASH_SIZE_BY_HASH_TYPE(MBCRYPT_HASH_TYPE_SHA1);

    for(int i = 0; i < sha_test_len; i++)
    {
        mbcrypt_hmac_t ctx;
        mbcrypt_sha1_t sha;
        mbcrypt_hash_callbacks_t cbs = {&sha, mbcrypt_sha1_init, mbcrypt_sha1_update, mbcrypt_sha1_final};

        ctx.cbs = &cbs;
        ctx.hash_type = MBCRYPT_HASH_TYPE_SHA1;
        mbcrypt_hmac_init(&ctx, sha_test[i], strlen(sha_test[i]));
        for (int j = 0; j < strlen(sha_test[i]); j++)
            mbcrypt_hmac_update(&ctx, &sha_test[i][j], 1);
        mbcrypt_hmac_final(&ctx, out);
        
        print_arr(out, hash_size);
        uint32_t len;
        HMAC(EVP_sha1(), sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), out1, &len);
        print_arr(out1, hash_size);
        if(!memcmp(out, out1, hash_size)){
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
    uint8_t *out[128];
    uint8_t *out1[128];
    int cnt = 0;
    uint32_t hash_size = GET_HASH_SIZE_BY_HASH_TYPE(MBCRYPT_HASH_TYPE_SHA256);

    for(int i = 0; i < sha_test_len; i++)
    {
        mbcrypt_sha256_t sha;
        mbcrypt_hash_callbacks_t cbs = {&sha, mbcrypt_sha256_init, 
                                        mbcrypt_sha256_update, mbcrypt_sha256_final};
        mbcrypt_hmac_t ctx;

        ctx.cbs = &cbs;
        ctx.hash_type = MBCRYPT_HASH_TYPE_SHA256;
        mbcrypt_hmac_init(&ctx, sha_test[i], strlen(sha_test[i]));
        for (int j = 0; j < strlen(sha_test[i]); j++)
            mbcrypt_hmac_update(&ctx, &sha_test[i][j], 1);
        mbcrypt_hmac_final(&ctx, out);
        
        print_arr(out, hash_size);
        uint32_t len;
        HMAC(EVP_sha256(), sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), out1, &len);
        print_arr(out1, hash_size);
        if(!memcmp(out, out1, hash_size)){
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
    uint8_t *out[128];
    uint8_t *out1[128];
    int cnt = 0;
    uint32_t hash_size = GET_HASH_SIZE_BY_HASH_TYPE(MBCRYPT_HASH_TYPE_SHA512);

    for(int i = 0; i < sha_test_len; i++)
    {

        mbcrypt_sha512_t sha;
        mbcrypt_hash_callbacks_t cbs = {&sha, mbcrypt_sha512_init, 
                            mbcrypt_sha512_update, mbcrypt_sha512_final};
        mbcrypt_hmac_t ctx;

        ctx.cbs = &cbs;
        ctx.hash_type = MBCRYPT_HASH_TYPE_SHA512;
        mbcrypt_hmac_init(&ctx, sha_test[i], strlen(sha_test[i]));
        for (int j = 0; j < strlen(sha_test[i]); j++)
            mbcrypt_hmac_update(&ctx, &sha_test[i][j], 1);
        mbcrypt_hmac_final(&ctx, out);
        
        print_arr(out, hash_size);
        uint32_t len;
        HMAC(EVP_sha512(), sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), out1, &len);
        print_arr(out1, hash_size);
        if(!memcmp(out, out1, hash_size)){
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

void test_mbcrypt_pbkdf2_hmac_sha1()
{
    printf("PBKDF2_HMAC_SHA1 test\n");
    uint8_t *out[32];
    uint8_t *out1[32];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {

        mbcrypt_sha1_t sha_ctx;
        mbcrypt_hash_callbacks_t sha_cbs = {&sha_ctx, mbcrypt_sha1_init, 
                                            mbcrypt_sha1_update, mbcrypt_sha1_final};
        mbcrypt_hmac_t hmac_ctx;

        hmac_ctx.cbs = &sha_cbs;
        hmac_ctx.hash_type = MBCRYPT_HASH_TYPE_SHA1;

        mbcrypt_hmac_callbacks_t hmac_cbs = {&hmac_ctx, mbcrypt_hmac_init,
                                                mbcrypt_hmac_update,mbcrypt_hmac_final};

        mbcrypt_pbkdf2_hmac(MBCRYPT_HASH_TYPE_SHA1, &hmac_cbs, sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), 433, out, 32);

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
void test_mbcrypt_pbkdf2_hmac_sha256()
{
    printf("PBKDF2_HMAC_SHA256 test\n");
    uint8_t *out[32];
    uint8_t *out1[32];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        mbcrypt_sha256_t sha_ctx;
        mbcrypt_hash_callbacks_t sha_cbs = {&sha_ctx, mbcrypt_sha256_init, 
                                            mbcrypt_sha256_update, mbcrypt_sha256_final};
        mbcrypt_hmac_t hmac_ctx;

        hmac_ctx.cbs = &sha_cbs;
        hmac_ctx.hash_type = MBCRYPT_HASH_TYPE_SHA256;

        mbcrypt_hmac_callbacks_t hmac_cbs = {&hmac_ctx, mbcrypt_hmac_init,
                                                mbcrypt_hmac_update,mbcrypt_hmac_final};

        mbcrypt_pbkdf2_hmac(MBCRYPT_HASH_TYPE_SHA256, &hmac_cbs, sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), 433, out, 32);

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

void test_mbcrypt_pbkdf2_hmac_sha512()
{
    printf("PBKDF2_HMAC_SHA512 test\n");
    uint8_t *out[32];
    uint8_t *out1[32];
    int cnt = 0;
    for(int i = 0; i < sha_test_len; i++)
    {
        mbcrypt_sha512_t sha_ctx;
        mbcrypt_hash_callbacks_t sha_cbs = {&sha_ctx, mbcrypt_sha512_init, 
                                            mbcrypt_sha512_update, mbcrypt_sha512_final};
        mbcrypt_hmac_t hmac_ctx;

        hmac_ctx.cbs = &sha_cbs;
        hmac_ctx.hash_type = MBCRYPT_HASH_TYPE_SHA512;

        mbcrypt_hmac_callbacks_t hmac_cbs = {&hmac_ctx, mbcrypt_hmac_init,
                                                mbcrypt_hmac_update, mbcrypt_hmac_final};

        mbcrypt_pbkdf2_hmac(MBCRYPT_HASH_TYPE_SHA512, &hmac_cbs, sha_test[i], strlen(sha_test[i]), sha_test[i], strlen(sha_test[i]), 433, out, 32);

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

void test_mbcrypt_kbkdf_ctr()
{
    mbcrypt_sha1_t sha_ctx;
    mbcrypt_hash_callbacks_t sha_cbs = {&sha_ctx, mbcrypt_sha1_init, 
                                        mbcrypt_sha1_update, mbcrypt_sha1_final};
    mbcrypt_hmac_t hmac_ctx;

    hmac_ctx.cbs = &sha_cbs;
    hmac_ctx.hash_type = MBCRYPT_HASH_TYPE_SHA1;

    mbcrypt_hmac_callbacks_t hmac_cbs = {&hmac_ctx, mbcrypt_hmac_init,
                                            mbcrypt_hmac_update,mbcrypt_hmac_final};

    uint8_t key_out[128];
    uint8_t *_in = "00a39bd547fb88b2d98727cf64c195c61e1cad6c";
    uint8_t *_fixed = "98132c1ffaf59ae5cbc0a3133d84c551bb97e0c75ecaddfc30056f6876f59803009bffc7d75c4ed46f40b8f80426750d15bc1ddb14ac5dcb69a68242";
    uint8_t *_iv = "0198132c1ffaf59ae5cbc0a3133d84c551bb97e0c75ecaddfc30056f6876f59803009bffc7d75c4ed46f40b8f80426750d15bc1ddb14ac5dcb69a68242";
    uint8_t key_exp = "0611e1903609b47ad7a5fc2c82e47702";

    uint8_t in[128];
    uint8_t fixed[128];
    uint8_t iv[128];
    uint8_t *p = in;
    #define GET_LET(x) (((x) >= '0' && (x) <= '9') ? ((x)-'0') : (((x)-'a') + 10))
    for (int i = 0; i < strlen(_in); i += 2, p++)
    {
        *p = (GET_LET(_in[i])) * 16 | (GET_LET(_in[i + 1]));
    }
    p = fixed;
    for (int i = 0; i < strlen(_fixed); i += 2, p++)
    {
        *p = (GET_LET(_fixed[i])) * 16 | (GET_LET(_fixed[i + 1]));
    }
    p = iv;
    for (int i = 0; i < strlen(iv); i += 2, p++)
    {
        *p = (GET_LET(_iv[i])) * 16 | (GET_LET(_iv[i + 1]));
    }
    mbcrypt_kbkdf_opts_t t = {1,0};
    kbkdf(MBCRYPT_KBKDF_MODE_COUNTER, MBCRYPT_HASH_TYPE_SHA1,
                        &hmac_cbs,
                        in, strlen(_in)/2,
                        iv, strlen(_iv)/2,
                        fixed, strlen(_fixed)/2,
                        key_out, 128,
                        &t);
    for (int i = 0; i < 128 / 8; i++)
    {
        printf("%02x", key_out[i]);
    }
    printf("\n");
}

void test_mbcrypt_kbkdf_fb()
{
    
}

void test_mbcrypt_kbkdf_dp()
{
    
}
#endif /* TEST_KBKDF */
#if 0
void test_rc4() 
{
    uint8_t key[] = "12";
    uint8_t in[] = "The quick brown fox jumps over the lazy dog.";
    uint8_t out[333];

    rc4(key, 2, in, sizeof(in)-1, out, 555);
   // RC4(key,in,out);
    print_arr(out, 44);
}





void test_rsa()
{
    rsa();
}
void test_rsa_pss()
{

}
void test_rsa_oaep()
{

}
void test_rsa_kem()
{

}
void test_rsa_kw()
{

}
#endif

#ifdef RRR

void mbcrypt_aes_tests()
{
    uint8_t out1[128];

    uint8_t data[] = "1234567812345678123456781234567812345432234234234234234332";
    uint8_t iv[] = "1234567812345678";
    uint8_t key[] = "1234567812345678";

    mbcrypt_aes_input_t in;
    mbcrypt_aes_output_t out;

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
    mbcrypt_aes_encrypt(MBCRYPT_AES_ECB, AES128, MBCRYPT_AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("6DAC1C56E747FAE03ACF8C6891E428E06DAC1C56E747FAE03ACF8C6891E428E0D176DCCE30D0E5B0E5A1D726E706F7F16D4878ABC1B9FC4EB40C8AF75D4D5577\n");

/* CBC */ 
    printf("##########################################################\n");
    printf("AES CBC test\n");

    memset(out.out, 0, 128);
    mbcrypt_aes_encrypt(MBCRYPT_AES_CBC, AES128, MBCRYPT_AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("6DAC1C56E747FAE03ACF8C6891E428E06DAC1C56E747FAE03ACF8C6891E428E0D176DCCE30D0E5B0E5A1D726E706F7F16D4878ABC1B9FC4EB40C8AF75D4D5577\n");


/* CFB */ 
    printf("##########################################################\n");
    printf("AES CFB test\n");

    memset(out.out, 0, 128);
    mbcrypt_aes_encrypt(MBCRYPT_AES_CFB, AES128, MBCRYPT_AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("9AE8FD02B340288A0E7BBFF0F0BA54D67ABDAC9471AF10FB31CC31D23845D53E9728A7FDABB4D17DD6EC55090A39490A0D32898226DE6A9D02116889CC79977F\n");

/* OFB */ 
    printf("##########################################################\n");
    printf("AES OFB test\n");

    memset(out.out, 0, 128);
    mbcrypt_aes_encrypt(MBCRYPT_AES_OFB, AES128, MBCRYPT_AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("9AE8FD02B340288A0E7BBFF0F0BA54D67ABDAC9471AF10FB31CC31D23845D53E9728A7FDABB4D17DD6EC55090A39490A0D32898226DE6A9D02116889CC79977F\n");


/* CTR */ 
    printf("##########################################################\n");
    printf("AES CTR test\n");

    memset(out.out, 0, 128);
    mbcrypt_aes_encrypt(MBCRYPT_AES_CTR, AES128, MBCRYPT_AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
    printf("Res: ");
    print_arr(out.out, 64);
    printf("exp: ");
    printf("9AE8FD02B340288A0E7BBFF0F0BA54D67ABDAC9471AF10FB31CC31D23845D53E9728A7FDABB4D17DD6EC55090A39490A0D32898226DE6A9D02116889CC79977F\n");


/* XTS */ 
    printf("##########################################################\n");
    printf("AES XTS test\n");

    memset(out.out, 0, 128);
    mbcrypt_aes_encrypt(MBCRYPT_AES_XTS, AES128, MBCRYPT_AES_KEY_EXPANSION_NOT_REQUIRED, &in, &out);
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
    test_mbcrypt_pbkdf2_hmac_sha1();
    test_mbcrypt_pbkdf2_hmac_sha256();
    test_mbcrypt_pbkdf2_hmac_sha512();
#endif


#if defined(TEST_KBKDF)
    test_mbcrypt_kbkdf_ctr();
    test_mbcrypt_kbkdf_fb();
    test_mbcrypt_kbkdf_dp();
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
    test_rsa_oaep();
    test_rsa_kem();
    test_rsa_kw();
#endif


#if defined(TEST_AES)
    test_mbcrypt_aes_ecb();
    test_mbcrypt_aes_cbc();
    test_mbcrypt_aes_ofb();
    test_mbcrypt_aes_cfb();
    test_mbcrypt_aes_ctr();
    test_mbcrypt_aes_xts();
    test_mbcrypt_aes_aead();
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
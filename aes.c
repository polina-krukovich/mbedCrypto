#include "aes.h"

#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

#define AES_MAX_KEY_SIZE            (32)

typedef enum
{
    AES_INFO_NK = 0, 
    AES_INFO_NR = 1, 
};

static const uint32_t _aes_info[][3] = 
{ // Nk, Nr
    {4, 10}, // AES128
    {6, 12}, // AES192
    {8, 14}, // AES256
};

#define Nk              _aes_info[aes_type][AES_INFO_NK]
#define Nr              _aes_info[aes_type][AES_INFO_NR]
/* In NIST standart is only Nb 4 applied*/
#define Nb              (4)

static const uint8_t _mix_coloums_vector[] = {0x02, 0x01, 0x01, 0x03};
static const uint8_t _inv_mix_coloums_vector[] = {0x0e, 0x09, 0x0d, 0x0b};

static const uint8_t _s_box[256] = 
{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t _inv_s_box[256] = 
{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t _rcon[] = 
{
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

static INLINE uint8_t _xtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

static INLINE uint8_t _gf_mult(uint8_t a, uint8_t b)
{
    uint8_t c = 0;
    uint8_t d = b;

    for (uint8_t i = 0; i < 8; ++i)
    {
        if (a & 1) 
        {
            c ^= d;
        }
        a >>= 1;
        d = _xtime(d);
    }
    return c;
}

static INLINE void _coef_mult(uint8_t a[4], uint8_t b[4], uint8_t d[4]) 
{
	d[0] = _gf_mult(a[0], b[0]) ^ _gf_mult(a[3], b[1]) ^ _gf_mult(a[2], b[2]) ^ _gf_mult(a[1], b[3]);
	d[1] = _gf_mult(a[1], b[0]) ^ _gf_mult(a[0], b[1]) ^ _gf_mult(a[3], b[2]) ^ _gf_mult(a[2], b[3]);
	d[2] = _gf_mult(a[2], b[0]) ^ _gf_mult(a[1], b[1]) ^ _gf_mult(a[0], b[2]) ^ _gf_mult(a[3], b[3]);
	d[3] = _gf_mult(a[3], b[0]) ^ _gf_mult(a[2], b[1]) ^ _gf_mult(a[1], b[2]) ^ _gf_mult(a[0], b[3]);
}

static INLINE void _rot_left_word(uint8_t word[4])
{
    uint8_t tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

static INLINE void _rot_right_word(uint8_t word[4])
{
    uint8_t tmp = word[3];
    word[3] = word[2];
    word[2] = word[1];
    word[1] = word[0];
    word[0] = tmp;
}

static INLINE void _sub_word(uint8_t word[4])
{
    word[0] = _s_box[word[0]];
    word[1] = _s_box[word[1]];
    word[2] = _s_box[word[2]];
    word[3] = _s_box[word[3]];
}

static INLINE void _inv_sub_word(uint8_t word[4])
{
    word[0] = _inv_s_box[word[0]];
    word[1] = _inv_s_box[word[1]];
    word[2] = _inv_s_box[word[2]];
    word[3] = _inv_s_box[word[3]];
}

static void _sub_bytes(uint8_t state[AES_BLOCK_SIZE])
{
#define SBOX(i) state[i] = _s_box[state[i]]

    SBOX(0);
    SBOX(1);
    SBOX(2);
    SBOX(3);
    SBOX(4);
    SBOX(5);
    SBOX(6);
    SBOX(7);
    SBOX(8);
    SBOX(9);
    SBOX(10);
    SBOX(11);
    SBOX(12);
    SBOX(13);
    SBOX(14);
    SBOX(15);

#undef SBOX
}

static void _inv_sub_bytes(uint8_t state[AES_BLOCK_SIZE])
{
#define INV_SBOX(i) state[i] = _inv_s_box[state[i]]

    INV_SBOX(0);
    INV_SBOX(1);
    INV_SBOX(2);
    INV_SBOX(3);
    INV_SBOX(4);
    INV_SBOX(5);
    INV_SBOX(6);
    INV_SBOX(7);
    INV_SBOX(8);
    INV_SBOX(9);
    INV_SBOX(10);
    INV_SBOX(11);
    INV_SBOX(12);
    INV_SBOX(13);
    INV_SBOX(14);
    INV_SBOX(15);
    
#undef INV_SBOX
}

static void _shift_rows(uint8_t state[AES_BLOCK_SIZE])
{
    _rot_left_word(state + 4);

    _rot_left_word(state + 8);
    _rot_left_word(state + 8);

    _rot_left_word(state + 12);
    _rot_left_word(state + 12);
    _rot_left_word(state + 12);
}

static void _inv_shift_rows(uint8_t state[AES_BLOCK_SIZE])
{
    _rot_right_word(state + 4);

    _rot_right_word(state + 8);
    _rot_right_word(state + 8);

    _rot_right_word(state + 12);
    _rot_right_word(state + 12);
    _rot_right_word(state + 12);
}

static void _mix_coloums(uint8_t state[AES_BLOCK_SIZE], uint8_t *vect)
{

   	uint8_t *a = vect; 
	uint8_t col[4], res[4];

	for (uint8_t i = 0; i < Nb; ++i)
    {
		col[0] = state[0 + i];// Nb * 0 + i
        col[1] = state[4 + i];// Nb * 1 + i
        col[2] = state[8 + i];// Nb * 2 + i
        col[3] = state[12 + i];// Nb * 3 + i

		_coef_mult(a, col, res);

        state[0 + i] = res[0];// Nb * 0 + i
        state[4 + i] = res[1];// Nb * 1 + i
        state[8 + i] = res[2];// Nb * 2 + i
        state[12 + i] = res[3];// Nb * 3 + i
	}
}

static void _aes_expand_key(aes_type_e aes_type, uint8_t *key, uint8_t *w)
{
    uint32_t k;
    uint32_t j;
    uint8_t tempa[4];

    for (uint32_t i = 0; i < Nk; ++i)
    {
        w[(i << 2) + 0] = key[(i << 2) + 0];
        w[(i << 2) + 1] = key[(i << 2) + 1];
        w[(i << 2) + 2] = key[(i << 2) + 2];
        w[(i << 2) + 3] = key[(i << 2) + 3];
    }

    for (uint32_t i = Nk; i < Nb * (Nr + 1); ++i)
    {
        k = (i - 1) * 4;
        tempa[0] = w[k + 0];
        tempa[1] = w[k + 1];
        tempa[2] = w[k + 2];
        tempa[3] = w[k + 3];

        if (i % Nk == 0)
        {
            _rot_left_word(tempa);
            _sub_word(tempa);
            tempa[0] = tempa[0] ^ _rcon[i / Nk];//i / Nk
        }
        if (Nk > 6 && i % Nk == 4)
        {
            _sub_word(tempa);
        }

        j = i * 4; 
        k = (i - Nk) * 4;

        w[j + 0] = w[k + 0] ^ tempa[0];
        w[j + 1] = w[k + 1] ^ tempa[1];
        w[j + 2] = w[k + 2] ^ tempa[2];
        w[j + 3] = w[k + 3] ^ tempa[3];
    }
}

static INLINE void _add_round_key(uint32_t round, uint8_t state[AES_BLOCK_SIZE], uint8_t w[AES_BLOCK_SIZE])
{
	for (uint8_t i = 0; i < Nb; ++i) 
    {
        uint8_t k = 4 * Nb * round + 4 * i;
		state[0 + i] ^= w[k + 0];
		state[4 + i] ^= w[k + 1];
		state[8 + i] ^= w[k + 2];
		state[12 + i] ^= w[k + 3];	
	}
}

static void _aes_encrypt_block(aes_key_t *key, const uint8_t in[AES_BLOCK_SIZE], 
                                uint8_t out[AES_BLOCK_SIZE])
{
    uint8_t state[AES_BLOCK_SIZE];
    aes_type_e aes_type = key->aes_type;
    uint8_t *w = key->w;

	for (uint32_t i = 0; i < 4; ++i) 
    {
        uint8_t k = Nb * i;
        state[k + 0] = in[i + 0];
        state[k + 1] = in[i + 4];
        state[k + 2] = in[i + 8];
        state[k + 3] = in[i + 12];
	}

    _add_round_key(0, state, w);

    for (uint32_t round = 1; round < Nr; ++round)
    {
        _sub_bytes(state);
        _shift_rows(state);
        _mix_coloums(state, _mix_coloums_vector);
        _add_round_key(round, state, w);
    }

    _sub_bytes(state);
    _shift_rows(state);
    _add_round_key(Nr, state, w);
    
    for (uint32_t i = 0; i < 4; ++i) 
    {
        uint8_t k = Nb * i;
        out[i + 0] = state[k + 0];
        out[i + 4] = state[k + 1];
        out[i + 8] = state[k + 2];
        out[i + 12] = state[k + 3];
	}
}   

static void _aes_decrypt_block(aes_key_t *key, const uint8_t in[AES_BLOCK_SIZE], 
                                uint8_t out[AES_BLOCK_SIZE])
{
    uint8_t state[AES_BLOCK_SIZE];
    aes_type_e aes_type = key->aes_type;
    uint8_t *w = key->w;

	for (uint32_t i = 0; i < 4; ++i) 
    {
        uint8_t k = Nb * i;
        state[k + 0] = in[i + 0];
        state[k + 1] = in[i + 4];
        state[k + 2] = in[i + 8];
        state[k + 3] = in[i + 12];
	}

    _add_round_key(Nr, state, w);

    for (uint32_t round = Nr - 1; round > 0; --round)
    {
        _inv_shift_rows(state);
        _inv_sub_bytes(state);
        _add_round_key(round, state, w);
        _mix_coloums(state, _inv_mix_coloums_vector);

    }

    _inv_shift_rows(state);
    _inv_sub_bytes(state);
    _add_round_key(0, state, w);
    
    for (uint32_t i = 0; i < 4; ++i) 
    {
        uint8_t k = Nb * i;
        out[i + 0] = state[k + 0];
        out[i + 4] = state[k + 1];
        out[i + 8] = state[k + 2];
        out[i + 12] = state[k + 3];
	}
}


security_status_e aes_key_init(aes_type_e aes_type, aes_key_t *aes_key)
{
SECURITY_FUNCTION_BEGIN;

    SECURITY_CHECK_VALID_NOT_NULL(aes_key);

    if (aes_type != AES128 && 
        aes_type != AES192 && 
        aes_type != AES256)
    {
        SECURITY_FUNCTION_RET_VAR = SECURITY_STATUS_FAIL_INCORRECT_FUNCTION_PARAM;
        goto SECURITY_FUNCTION_EXIT;
    }

    aes_key->aes_type = aes_type;
    aes_key->w = malloc(4 * Nb * (Nr + 1));

    SECURITY_CHECK_VALID_NOT_NULL(aes_key->w);

SECURITY_FUNCTION_EXIT:
    SECURITY_FUNCTION_RETURN;
}

security_status_e aes_key_expand(aes_key_expansion_hash_type_e key_exp_hash_type,
                                    const uint8_t *key_in, uint32_t key_in_len, aes_key_t *key_out)
{
SECURITY_FUNCTION_BEGIN;
    
    SECURITY_CHECK_VALID_NOT_NULL(key_out);
    SECURITY_CHECK_VALID_NOT_NULL(key_in);
    
    uint8_t tmp_key[AES_MAX_KEY_SIZE * 2];
    uint32_t aes_type = key_out->aes_type;

    SECURITY_CHECK_VALID_NOT_NULL(memset(tmp_key, 0x00, sizeof(tmp_key)));

    if (key_exp_hash_type == AES_KEY_EXPANSION_SHA1 && 
        (key_out->aes_type == AES192 || key_out->aes_type == AES256))
    {
        SECURITY_FUNCTION_RET_VAR = SECURITY_STATUS_FAIL_INCORRECT_FUNCTION_PARAM;
        goto SECURITY_FUNCTION_EXIT;
    }

    switch (key_exp_hash_type)
    {
    case AES_KEY_EXPANSION_SHA1:
        SECURITY_CHECK_RES(sha1(key_in, key_in_len, tmp_key));
        break;
    case AES_KEY_EXPANSION_SHA256:
        SECURITY_CHECK_RES(sha256(key_in, key_in_len, tmp_key));
        break;
    case AES_KEY_EXPANSION_SHA512:
        SECURITY_CHECK_RES(sha512(key_in, key_in_len, tmp_key));
        break;
    case AES_KEY_EXPANSION_NOT_REQUIRED:
        if (key_in_len != Nk * 4)
        {
            SECURITY_FUNCTION_RET_VAR = SECURITY_STATUS_FAIL_INCORRECT_FUNCTION_PARAM;
            goto SECURITY_FUNCTION_EXIT;
        }
        else 
        {
            SECURITY_CHECK_VALID_NOT_NULL(memcpy(tmp_key, key_in, key_in_len));
        }
        break;
    default:
        SECURITY_FUNCTION_RET_VAR = SECURITY_STATUS_FAIL_INCORRECT_FUNCTION_PARAM;
        goto SECURITY_FUNCTION_EXIT;
        break;
    }
    _aes_expand_key(key_out->aes_type, tmp_key, key_out->w);

SECURITY_FUNCTION_EXIT:
    SECURITY_FUNCTION_RETURN;
}

security_status_e aes_ecb_encrypt_block(aes_key_t *key, const uint8_t in[AES_BLOCK_SIZE], 
                                        uint8_t out[AES_BLOCK_SIZE])
{
SECURITY_FUNCTION_BEGIN;
    
    SECURITY_CHECK_VALID_NOT_NULL(key);
    SECURITY_CHECK_VALID_NOT_NULL(in);
    SECURITY_CHECK_VALID_NOT_NULL(out);

    _aes_encrypt_block(key, in, out);

SECURITY_FUNCTION_EXIT:
    SECURITY_FUNCTION_RETURN;
    
}

security_status_e aes_ecb_decrypt_block(aes_key_t *key, const uint8_t in[AES_BLOCK_SIZE], 
                                    uint8_t out[AES_BLOCK_SIZE])
{
SECURITY_FUNCTION_BEGIN;
    
    SECURITY_CHECK_VALID_NOT_NULL(key);
    SECURITY_CHECK_VALID_NOT_NULL(in);
    SECURITY_CHECK_VALID_NOT_NULL(out);

    _aes_decrypt_block(key, in, out);

SECURITY_FUNCTION_EXIT:
    SECURITY_FUNCTION_RETURN;
}

static void _aes_ecb_encrypt_ex(aes_key_t *key,
                                const uint8_t *data, uint32_t data_len, 
                                const uint8_t *iv, uint32_t iv_len, 
                                uint8_t *out)
{

    uint8_t buf[AES_BLOCK_SIZE] = {0};
    uint32_t full_blocks = data_len >> 4;
    uint32_t left_data = data_len & 15;

    for (uint32_t i = 0; i < full_blocks; ++i, data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
    {
        _aes_encrypt_block(key, data, out);
    }

    if (left_data)
    {
        uint8_t pad = 16 - left_data;

        memcpy(buf, data, left_data);

        for (uint32_t i = left_data; i <= AES_BLOCK_SIZE; ++i)
        {
            buf[i] = pad;
        }
        _aes_encrypt_block(key, buf, out);
    }
}

static void _aes_cbc_encrypt_ex(aes_key_t *key,
                                const uint8_t *data, uint32_t data_len, 
                                const uint8_t *iv, uint32_t iv_len, 
                                uint8_t *out)
{
    uint8_t buf[AES_BLOCK_SIZE] = {0};
    uint32_t full_blocks = data_len >> 4;
    uint32_t left_data = data_len & 15;

    memcpy(buf, iv, AES_BLOCK_SIZE);

    for (uint32_t i = 0; i < full_blocks; ++i, data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
    {
        for (uint32_t j = 0; j < 16; ++j)
        {
            buf[j] = data[j] ^ buf[j];
        }
        _aes_encrypt_block(key, buf, out);
        memcpy(buf, out, AES_BLOCK_SIZE);
    }

    if (left_data)
    {   
        uint8_t pad = 16 - left_data;

        for (uint32_t i = left_data; i <= AES_BLOCK_SIZE; ++i)
        {
            buf[i] ^= pad;
        }

        for (uint32_t i = 0; i < left_data; ++i)
        {
            buf[i] ^= data[i];
        }
        _aes_encrypt_block(key, buf, out);
    }
}


static void _aes_ofb_encrypt_ex(aes_key_t *key,
                                const uint8_t *data, uint32_t data_len, 
                                const uint8_t *iv, uint32_t iv_len, 
                                uint8_t *out)
{
    uint8_t buf[AES_BLOCK_SIZE] = {0};
    uint32_t full_blocks = data_len >> 4;
    uint32_t left_data = data_len & 15;

    memcpy(buf, iv, AES_BLOCK_SIZE);

    for (uint32_t i = 0; i < full_blocks; ++i, data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
    {
        _aes_encrypt_block(key, buf, out);

        memcpy(buf, out, AES_BLOCK_SIZE);

        for (uint32_t j = 0; j < 16; j++)
        {
            out[j] ^= data[j];
        }
        
    }
    if (left_data)
    {
        uint8_t tmp[AES_BLOCK_SIZE] = {0};

        _aes_encrypt_block(key, buf, tmp);

        memcpy(buf, tmp, AES_BLOCK_SIZE);

        for (uint32_t j = 0; j < left_data; j++)
        {
            out[j] = buf[j] ^ data[j];
        }
    }
}

static void _aes_cfb_encrypt_ex(aes_key_t *key,
                                const uint8_t *data, uint32_t data_len, 
                                const uint8_t *iv, uint32_t iv_len, 
                                uint8_t *out)
{
    uint8_t buf[AES_BLOCK_SIZE] = {0};
    uint32_t full_blocks = data_len >> 4;
    uint32_t left_data = data_len & 15;

    memcpy(buf, iv, AES_BLOCK_SIZE);

    for (uint32_t i = 0; i < full_blocks; ++i, data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
    {
        _aes_encrypt_block(key, buf, out);

        for (uint32_t j = 0; j < 16; ++j)
        {
            buf[j] = data[j] ^ out[j];
        }
        memcpy(out, buf, AES_BLOCK_SIZE);
    }
    if (left_data)
    {
        uint8_t tmp[AES_BLOCK_SIZE] = {0};

        _aes_encrypt_block(key, buf, tmp);

        for (uint32_t j = 0; j < left_data; j++)
        {
            out[j] = tmp[j] ^ data[j];
        }
    }
}

static void _aes_ctr_encrypt_ex(aes_key_t *key,
                                const uint8_t *data, uint32_t data_len, 
                                const uint8_t *iv, uint32_t iv_len, 
                                uint8_t *out)
{
    uint8_t buf[AES_BLOCK_SIZE] = {0};
    uint32_t full_blocks = data_len >> 4;
    uint32_t left_data = data_len & 15;

    memcpy(buf, iv, AES_BLOCK_SIZE);

    for (uint32_t i = 0; i < full_blocks; ++i, data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
    {
        _aes_encrypt_block(key, buf, out);

        for (uint32_t j = 0; j < 16; j++)
        {
            out[j] ^= data[j];
        }

        for (int32_t j = 15; j >= 0; --j)
        {
            if ((++buf[j]) == 0)
                continue;
            break;
        }
    }
    if (left_data)
    {
        uint8_t tmp[AES_BLOCK_SIZE] = {0};

        _aes_encrypt_block(key, buf, tmp);

        for (uint32_t i = 0; i < left_data; ++i)
        {
            out[i] = tmp[i] ^ data[i];
        }
    }
    
}


static void _aes_xts_encrypt_ex(aes_key_t *key,
                                const uint8_t *data, uint32_t data_len, 
                                const uint8_t *iv, uint32_t iv_len, 
                                uint8_t *out)
{
    uint8_t buf[AES_BLOCK_SIZE] = {0};
    uint8_t T[AES_BLOCK_SIZE] = {0};
    uint32_t full_blocks = data_len >> 4;
    uint32_t left_data = data_len & 15;

    _aes_encrypt_block(key, iv, T);

    for (uint32_t i = 0; i < full_blocks; i++, data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
    {
        for (uint32_t j = 0; j < 16; j++)
        {
            buf[j] = data[j] ^ T[j];
        }

        _aes_encrypt_block(key, buf, out);

        for (uint32_t j = 0; j < 16; j++)
        {
            out[j] ^= T[j];
        }

        memcpy(T, out, 16);
    }
    if (left_data)
    {
        memcpy(buf, data, left_data);
        for (uint32_t j = 0; j < 16; j++)
        {
            buf[j] = data[j] ^ T[j];
        }

        _aes_encrypt_block(key, buf, out);

        for (uint32_t j = 0; j < 16; j++)
        {
            out[j] ^= T[j];
        }

        memcpy(T, out, 16);

    }
}

static void _aes_gcm_encrypt_ex(aes_key_t *key,
                                const uint8_t *data, uint32_t data_len, 
                                const uint8_t *iv, uint32_t iv_len, 
                                uint8_t *out)
{
    uint8_t buf[AES_BLOCK_SIZE] = {0};
    uint8_t T[AES_BLOCK_SIZE] = {0};
    uint32_t full_blocks = data_len >> 4;
    uint32_t left_data = data_len & 15;


    memcpy(buf, iv, AES_BLOCK_SIZE);


    for (uint32_t i = 0; i < full_blocks; ++i, data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
    {
        for (uint32_t j = 0; j < 16; j++)
        {
            buf[j] = data[j] ^ T[j];
        }

        _aes_encrypt_block(key, buf, out);

        for (uint32_t j = 0; j < 16; j++)
        {
            out[j] ^= T[j];
        }

        memcpy(T, out, 16);
    }
    if (left_data)
    {
        memcpy(buf, data, left_data);
        for (uint32_t j = 0; j < 16; j++)
        {
            buf[j] = data[j] ^ T[j];
        }

        _aes_encrypt_block(key, buf, out);

        for (uint32_t j = 0; j < 16; j++)
        {
            out[j] ^= T[j];
        }

        memcpy(T, out, 16);

    }
} 

security_status_e aes_encrypt(aes_mode_e aes_mode, aes_type_e aes_type,
                                aes_key_expansion_hash_type_e key_exp_hash_type, 
                                const uint8_t *data, uint32_t data_len, 
                                const uint8_t *iv, uint32_t iv_len, 
                                uint8_t *key, uint32_t key_len, uint8_t *out)
{
SECURITY_FUNCTION_BEGIN;
    
    aes_key_t aes_key;
    
    SECURITY_CHECK_RES(aes_key_init(aes_type, &aes_key));
    SECURITY_CHECK_RES(aes_key_expand(key_exp_hash_type, key, key_len, &aes_key));

    switch (aes_mode)
    {
    case AES_ECB:
        _aes_ecb_encrypt_ex(&aes_key, data, data_len, iv, iv_len, out);
        break;
    case AES_CBC:
        _aes_cbc_encrypt_ex(&aes_key, data, data_len, iv, iv_len, out);
        break;
    case AES_OFB:
        _aes_ofb_encrypt_ex(&aes_key, data, data_len, iv, iv_len, out);
        break;
    case AES_CFB:
        _aes_cfb_encrypt_ex(&aes_key, data, data_len, iv, iv_len, out);
        break;
    case AES_CTR:
        _aes_ctr_encrypt_ex(&aes_key, data, data_len, iv, iv_len, out);
        break;
    case AES_GCM:
        _aes_gcm_encrypt_ex(&aes_key, data, data_len, iv, iv_len, out);
        break;
        /*
    case AES_AEAD:
        _aes_cfb_encrypt_ex(&aes_key, data, data_len, iv, iv_len, out);
        break;
    case AES_XTS:
        _aes_xts_encrypt_ex(&aes_key, data, data_len, iv, iv_len, out);
        break;
        */
    default:
        break;
    }
 
SECURITY_FUNCTION_EXIT:
    aes_key_free(&aes_key);
    SECURITY_FUNCTION_RETURN;   
}

void aes_key_free(aes_key_t *aes_key)
{
    if (aes_key != NULL && aes_key->w != NULL)
    {
        free(aes_key->w);
    }
}
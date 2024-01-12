#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <mbedtls/bignum.h>
#include <mbedtls/platform.h>
#include <mbedtls/config.h>
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdint.h>
#include <stdlib.h>
#include <paillier_ta.h>


/*-------define constant--------*/
mbedtls_ctr_drbg_context CTR_DRBG_CTX;
mbedtls_entropy_context ENTROPY;
int seed_switch = 0;
/*--------------*/

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param __maybe_unused params[4],
                                    void __maybe_unused **sess_ctx)
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Unused parameters */
    (void)&params;
    (void)&sess_ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
    (void)&sess_ctx; /* Unused parameter */
}

static TEE_Result compute_multi(uint32_t param_types, TEE_Param params[4])
{
    // 可能过于大导致无法放进去
    char buf[1024]; // assuse buffer is very large
    size_t olen;
    uint32_t expected_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_NONE);

    if (param_types != expected_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    // 假设传递过来的指针参数都可用
    mbedtls_mpi *a = params[0].memref.buffer;
    mbedtls_mpi *b = params[1].memref.buffer;
    paillierKeys *keys = params[2].memref.buffer;

    mbedtls_mpi_write_string(a, 10, buf, sizeof(buf), &olen);
    printf("a value: %s\n", buf);
    mbedtls_mpi_write_string(b, 10, buf, sizeof(buf), &olen);
    printf("b value: %s\n", buf);


    mbedtls_mpi t1;
    mbedtls_mpi t2;
    mbedtls_mpi t3;
    mbedtls_mpi_init(&t1);
    mbedtls_mpi_init(&t2);
    mbedtls_mpi_init(&t3);

    decrypt(&t1,a,&keys->priv);
    decrypt(&t2,b,&keys->priv);
    mbedtls_mpi_add_mpi(&t3,&t1,&t2);
    encrypt(&t1, &t3, &keys->pub);
    
    mbedtls_mpi_write_string(&t1, 10, buf, sizeof(buf), &olen);
    params[0].memref.buffer = buf;

    mbedtls_mpi_free(&t1);
    mbedtls_mpi_free(&t2);
    mbedtls_mpi_free(&t3);

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(
    void __maybe_unused *sess_ctx,
    uint32_t __maybe_unused cmd_id, uint32_t param_types, TEE_Param params[4])
{
    (void)&sess_ctx;

    return compute_multi(param_types, params);
}

/*-------------------------------------------*/

/*-----函数实现，先放这里------*/

static int init_seed()
{
    if (!seed_switch)
    {
        mbedtls_ctr_drbg_init(&CTR_DRBG_CTX);
        mbedtls_entropy_init(&ENTROPY);
        if (mbedtls_ctr_drbg_seed(&CTR_DRBG_CTX, mbedtls_entropy_func, &ENTROPY,
                                  NULL, 0) != 0)
        {
            fprintf(stderr, "init random seed error!\n");
        }
        seed_switch = 1;
    }
}
// lcm函数 LCM function
// 计算两个大数的最小公倍数 Calculate the least common multiple of two large numbers
static int mpi_lcm(mbedtls_mpi *result, const mbedtls_mpi *A, const mbedtls_mpi *B)
{
    int ret = 1;
    mbedtls_mpi product, gcd_result;

    mbedtls_mpi_init(&product);
    mbedtls_mpi_init(&gcd_result);

    // 计算 A 和 B 的最大公约数 Calculate the maximum common divisor of A and B

    if ((ret = mbedtls_mpi_gcd(&gcd_result, A, B)) != 0)
    {
        goto end;
    }

    // 计算 A 和 B 的乘积 Calculate the product of A and B
    if ((ret = mbedtls_mpi_mul_mpi(&product, A, B)) != 0)
    {
        goto end;
    }

    // 使用最大公约数计算最小公倍数 Calculate the minimum common multiple using the maximum common divisor
    if ((ret = mbedtls_mpi_div_mpi(result, NULL, &product, &gcd_result)) != 0)
    {
        goto end;
    }

end:
    mbedtls_mpi_free(&product);
    mbedtls_mpi_free(&gcd_result);
    return ret;
}

// L函数 L function
static int L(mbedtls_mpi *res, mbedtls_mpi *x, mbedtls_mpi *n)
{
    int ret = 1;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    if (ret = mbedtls_mpi_sub_int(&tmp, x, 1) != 0)
        goto end;
    if ((ret = mbedtls_mpi_div_mpi(res, NULL, &tmp, n)) != 0)
        goto end;
    ret = 0;
end:
    mbedtls_mpi_free(&tmp);
    return ret;
}
// 函数用于为 mbedtls_mpi 结构体的指针申请内存 The function is used for mbedtls_ Pointer to MPI structure to apply for memory
static int allocate_mpi_on_heap(mbedtls_mpi **mpi_ptr)
{
    *mpi_ptr = (mbedtls_mpi *)malloc(sizeof(mbedtls_mpi));

    if (*mpi_ptr == NULL)
    {
        fprintf(stderr, "error malloc memory");
        return -1;
    }

    mbedtls_mpi_init(*mpi_ptr); // 初始化分配的内存 Initialize allocated memory

    return 0; // 成功返回 0 Successfully returned 0
}
// 申请空间 Apply for space
static int init_paillierKeys(paillierKeys *keys)
{

    allocate_mpi_on_heap(&keys->priv.n);

    allocate_mpi_on_heap(&keys->priv.n2);

    allocate_mpi_on_heap(&keys->priv.mu);

    allocate_mpi_on_heap(&keys->priv.lamda);

    allocate_mpi_on_heap(&keys->pub.n2);

    allocate_mpi_on_heap(&keys->pub.n);

    allocate_mpi_on_heap(&keys->pub.g);
}

// 随机生成密钥 Randomly generate key
int generateRandomKeys(paillierKeys *keys, int *key_len)
{
    char buf[4000]; // assuse buffer is very large
    size_t olen;
    /*-----------*/
    init_seed();
    int ret = 1, final_key_1 = 0;
    mbedtls_mpi tmp1, tmp2, n, n2, g, lamda, mu;
    if ((key_len != NULL && *key_len == 0) || key_len == NULL)
    {
        final_key_1 = DEFAULT_KEY_LEN;
    }
    else if (key_len != NULL)
    {
        final_key_1 = *key_len;
    }

    if (final_key_1 < 32)
    {
        fprintf(stderr, "Key lenght too short,Minimum lenght 32 bits\n");
        goto end;
    }
    // 初始化数字 init section....

    mbedtls_mpi_init(&tmp1);
    mbedtls_mpi_init(&tmp2);
    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&n2);
    mbedtls_mpi_init(&g);
    mbedtls_mpi_init(&lamda);
    mbedtls_mpi_init(&mu);

    mbedtls_rsa_context rsa_ctx;
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);

    // 生成随机的质数 P 和 Q Generate random prime numbers P and Q
    if ((ret = mbedtls_rsa_gen_key(&rsa_ctx, mbedtls_ctr_drbg_random, &CTR_DRBG_CTX,
                                   final_key_1, 65537)) != 0)
    {
        goto end;
    }
    // 计算得到n
    mbedtls_mpi_mul_mpi(&n, &rsa_ctx.P, &rsa_ctx.Q);

    // 计算得到n2
    mbedtls_mpi_mul_mpi(&n2, &n, &n);

    // 计算lamda
    mbedtls_mpi_sub_int(&tmp1, &rsa_ctx.P, 1);
    mbedtls_mpi_sub_int(&tmp2, &rsa_ctx.Q, 1);

    mpi_lcm(&lamda, &tmp1, &tmp2);
    // 计算g和u
    do
    {
        // 选择在n2范围内的随机整数 Select random integers within the range of n2
        do
        {
            mbedtls_mpi_fill_random(&g, mbedtls_mpi_size(&n2), mbedtls_ctr_drbg_random, &CTR_DRBG_CTX);
            // 使用 mbedtls_mpi_mod_mpi 函数确保 g < n2 Using mbedtls_ MPI_ Mod_ The mpi function ensures that g<n2
            mbedtls_mpi_mod_mpi(&g, &g, &n2);
        } while (mbedtls_mpi_cmp_int(&g, 0) == 0);

        mbedtls_mpi_exp_mod(&tmp1, &g, &lamda, &n2, NULL); // tmp = g^lamda mod n2
        if (ret = L(&tmp1, &tmp1, &n) != 0)
            goto end;

        if (mbedtls_mpi_inv_mod(&mu, &tmp1, &n) == 0)
        {
            break; // Found valid g and mu
        }

    } while (1);

    init_paillierKeys(keys);
    // 填充到我们的公钥和私钥里面 Fill in our public and private keys
    mbedtls_mpi_copy(keys->priv.lamda, &lamda);
    mbedtls_mpi_copy(keys->priv.mu, &mu);
    mbedtls_mpi_copy(keys->priv.n, &n);
    mbedtls_mpi_copy(keys->priv.n2, &n2);

    mbedtls_mpi_copy(keys->pub.g, &g);
    mbedtls_mpi_copy(keys->pub.n, &n);
    mbedtls_mpi_copy(keys->pub.n2, &n2);

    ret = 0;
end:
    // 清理释放资源 Clean up and release resources

    mbedtls_mpi_free(&tmp1);
    mbedtls_mpi_free(&tmp2);
    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&n2);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&lamda);
    mbedtls_mpi_free(&mu);

    mbedtls_rsa_free(&rsa_ctx);

    return ret;
}

// 加密
int encrypt(mbedtls_mpi *res, const mbedtls_mpi *plain, pubKey *pbkey)
{
    init_seed();
    int ret = 1;

    mbedtls_mpi r;
    mbedtls_mpi tmp1;
    mbedtls_mpi tmp2;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&tmp1);
    mbedtls_mpi_init(&tmp2);
    // 检测范围是否在 0 - n Is the detection range between 0 and n
    if (mbedtls_mpi_cmp_mpi(plain, pbkey->n) >= 0)
    {
        fprintf(stderr, "Message not range in N\n");
        goto end;
    }
    mbedtls_mpi_fill_random(&r, mbedtls_mpi_size(pbkey->n), mbedtls_ctr_drbg_random, &CTR_DRBG_CTX);
    mbedtls_mpi_mod_mpi(&r, &r, pbkey->n);

    if ((ret = mbedtls_mpi_exp_mod(&tmp1, pbkey->g, plain, pbkey->n2, NULL)) != 0)
        goto end;

    if (ret = mbedtls_mpi_exp_mod(&tmp2, &r, pbkey->n, pbkey->n2, NULL) != 0)
        goto end;
    if ((ret = mbedtls_mpi_mul_mpi(res, &tmp1, &tmp2)) != 0)
        goto end;

    if ((ret = mbedtls_mpi_mod_mpi(res, res, pbkey->n2)) != 0)
        goto end;
    ret = 0;
end:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&tmp1);
    mbedtls_mpi_free(&tmp2);
    return ret;
}

// 解密
int decrypt(mbedtls_mpi *res, const mbedtls_mpi *c, privKey *pvkey)
{
    int ret = 1;

    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    // 检测范围是否在 0 - n2 Is the detection range between 0 and n2
    if (mbedtls_mpi_cmp_mpi(c, pvkey->n2) >= 0)
    {
        fprintf(stderr, "Message not range in N^2\n");
        goto end;
    }
    // m = L(c^lamda mod n2)*mu mod n
    if ((ret = mbedtls_mpi_exp_mod(&tmp, c, pvkey->lamda, pvkey->n2, NULL)) != 0)
    {
        goto end;
    }
    if ((ret = L(&tmp, &tmp, pvkey->n)) != 0)
    {
        goto end;
    }
    if ((ret = mbedtls_mpi_mul_mpi(&tmp, &tmp, pvkey->mu)) != 0)
        goto end;
    if (ret = (mbedtls_mpi_mod_mpi(res, &tmp, pvkey->n) != 0))
        goto end;
    ret = 0;
end:
    mbedtls_mpi_free(&tmp);
    return ret;
}
// 密文加法
int enc_mpi_add(mbedtls_mpi *res, const mbedtls_mpi *a, const mbedtls_mpi *b, paillierKeys *keys)
{
    int ret = 1;
    mbedtls_mpi tmp;
    mbedtls_mpi_free(&tmp);
    if ((ret = mbedtls_mpi_mul_mpi(&tmp, a, b)) != 0)
        goto end;
    if (ret = mbedtls_mpi_mod_mpi(res, &tmp, keys->priv.n2) != 0)
        goto end;
end:
    mbedtls_mpi_free(&tmp);
    return ret;
}
// 密文 + 明文加法 Ciphertext+plaintext addition
int encPlain_mpi_add(mbedtls_mpi *res, const mbedtls_mpi *a, const mbedtls_mpi *Plain, paillierKeys *keys)
{
    int ret = 1;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    encrypt(&tmp, Plain, &keys->pub);
    if ((ret = mbedtls_mpi_mul_mpi(&tmp, a, &tmp)) != 0)
        goto end;
    if (ret = mbedtls_mpi_mod_mpi(res, &tmp, keys->priv.n2) != 0)
        goto end;
end:
    mbedtls_mpi_free(&tmp);
    return ret;
}
// 与明文乘法 Multiplication with plaintext
int mpi_mul_plain(mbedtls_mpi *res, const mbedtls_mpi *a, const mbedtls_mpi *plain, paillierKeys *keys)
{
    int ret = 1;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_exp_mod(res, a, plain, keys->priv.n2, NULL);
    ret = 0;
end:
    mbedtls_mpi_free(&tmp);
    return ret;
}

// 与密文的减法 Subtraction from ciphertext
int enc_mpi_sub(mbedtls_mpi *res, const mbedtls_mpi *a, const mbedtls_mpi *b, paillierKeys *keys)
{
    int ret = 0;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    // 计算模反 Computational inversion
    if ((ret = mbedtls_mpi_inv_mod(&tmp, b, keys->priv.n2)) != 0)
        goto end;
    if ((ret = mbedtls_mpi_mul_mpi(res, a, &tmp)) != 0)
        goto end;
    if ((ret = mbedtls_mpi_mod_mpi(res, res, keys->priv.n2)) != 0)
        goto end;
end:
    mbedtls_mpi_free(&tmp);
    return ret;
}
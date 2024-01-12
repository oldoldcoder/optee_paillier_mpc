#include <err.h>
#include <stdio.h>
#include <tee_client_api.h>

#include <mbedtls/bignum.h>
#include <mbedtls/platform.h>
#include <mbedtls/config.h>
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <paillier_ta.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/*-------define constant--------*/
mbedtls_ctr_drbg_context CTR_DRBG_CTX;
mbedtls_entropy_context ENTROPY;
int seed_switch = 0;
#define KEY_LEN 64
#define MAX_M_BITS 32

#define MAX_SUB_LEN MAX_M_BITS
#define SUB_CORRECTION_FACTOR MAX_M_BITS + 1

#define MAX_MULT_FACTOR_LEN KEY_LEN - MAX_M_BITS - 1
/*-------define structure---------*/
typedef struct
{
    TEEC_Context ctx;
    TEEC_Session sess;
} tee_ctx;

/*准备工作代码*/
void prepare_work(tee_ctx *ctx)
{
    TEEC_Result res;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_PAILLIER_UUID;
    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
             res, err_origin);
}
/*销毁内容*/
void terminate_tee_session(tee_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}
static void init_seed();

/*--------------------------------*/
int main(void)
{
    tee_ctx ctxx;
    prepare_work(&ctxx);
    init_seed();
    
    printf("------开始执行---------");
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    int ret = 1;
    // useage is show middle value
    char buf[4000]; // assuse buffer is very large
    size_t olen;

    /*-------创建变量工作--------*/
    paillierKeys keys;
    mbedtls_mpi tmp, m1, cm1,
        m2, cm2,
        r1, cr1,
        r2, cr2,
        
        e_m1_add_r1,
        e_m2_add_r2,
        e_m1_mul_r2,
        e_m2_mul_r1,
        e_r1_mul_r2,
        e_3_party_add,
        e_m1r1_mul_m2r2,
        correction_factor;
    mbedtls_mpi_init(&m1);
    mbedtls_mpi_init(&m2);
    mbedtls_mpi_init(&r1);
    mbedtls_mpi_init(&r2);
    mbedtls_mpi_init(&cm1);
    mbedtls_mpi_init(&cm2);
    mbedtls_mpi_init(&cr1);
    mbedtls_mpi_init(&cr2);
    mbedtls_mpi_init(&tmp);

    
    mbedtls_mpi_init(&e_m1_add_r1);
    mbedtls_mpi_init(&e_m2_add_r2);
    mbedtls_mpi_init(&e_m1_mul_r2);
    mbedtls_mpi_init(&e_m2_mul_r1);
    mbedtls_mpi_init(&e_r1_mul_r2);
    mbedtls_mpi_init(&e_3_party_add);
    mbedtls_mpi_init(&e_m1r1_mul_m2r2);
    mbedtls_mpi_init(&correction_factor);

    mbedtls_mpi_lset(&m1,1111);
    mbedtls_mpi_lset(&m2,2222);
    mbedtls_mpi_lset(&r1,1234);
    mbedtls_mpi_lset(&r2,4321);
    /*---------计算开始----------*/
    // 填充密钥
    if ((ret = generateRandomKeys(&keys,NULL)) != 0)
        goto end;
    
    /*-----------------*/
    if (encrypt(&cm1, &m1, &keys.pub ) != 0)
        goto end;
    if (encrypt(&cm2, &m2, &keys.pub ) != 0)
        goto end;
    if (encrypt(&cr1, &r1, &keys.pub ) != 0)
        goto end;
    if (encrypt(&cr2, &r2, &keys.pub ) != 0)
        goto end;
    if (enc_mpi_add(&e_m1_add_r1, &cm1, &cr1, &keys) != 0)
        goto end;
    if (enc_mpi_add(&e_m2_add_r2, &cm2, &cr2, &keys) != 0)
        goto end;
    /*-------REE传递参数---------*/
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE);
    op.params[0]
        .tmpref.buffer = &e_m1_add_r1;
    op.params[1]
        .tmpref.buffer = &e_m2_add_r2;
    op.params[2]
        .tmpref.buffer = &keys;

    printf("-----调用TEE-----");
    res = TEEC_InvokeCommand(&ctxx.sess, 0, &op, &err_origin);
    if (res != TEEC_SUCCESS){
         errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
    }
    printf("-----调用结束-----");
    mbedtls_mpi_read_string(&e_m1r1_mul_m2r2, 10, op.params[0].tmpref.buffer);
    // TODO 假设目前已知 e_m1r1_mul_m2r2
    if (mpi_mul_plain(&e_m1_mul_r2, &cm1, &r2, &keys) != 0)
        goto end;
    if (mpi_mul_plain(&e_m2_mul_r1, &cm2, &r1, &keys) != 0)
        goto end;
    mbedtls_mpi_mul_mpi(&tmp,&r1,&r2);
    if (encrypt(&e_r1_mul_r2, &tmp, &keys.pub) != 0)
        goto end;
    // 求三者之和
    if (encPlain_mpi_add(&tmp, &e_m1_mul_r2, &e_m2_mul_r1, &keys) != 0)
        goto end;
    if (encPlain_mpi_add(&e_3_party_add, &tmp, &e_r1_mul_r2, &keys) != 0)
        goto end;
    // 最终计算减法来获得值
    if (mbedtls_mpi_fill_random(&correction_factor, SUB_CORRECTION_FACTOR, mbedtls_ctr_drbg_random, &CTR_DRBG_CTX) != 0)
        goto end;

    if (enc_mpi_sub(&tmp, &e_m1r1_mul_m2r2, &e_3_party_add, &keys) != 0)
        goto end;
    if (encPlain_mpi_add(&tmp, &tmp, &correction_factor, &keys) != 0)
        goto end;

    if (decrypt(&tmp, &tmp, &keys.priv) != 0)
        goto end;
    if (mbedtls_mpi_sub_mpi(&tmp, &tmp, &correction_factor))
        goto end;
    mbedtls_mpi_write_string(&tmp, 10, buf, sizeof(buf), &olen);
    printf("m2 mul m1 value: %s\n", buf);
    ret = 0;
end:
    mbedtls_mpi_free(&m1);
    mbedtls_mpi_free(&m2);
    mbedtls_mpi_free(&r1);
    mbedtls_mpi_free(&r2);
    mbedtls_mpi_free(&cm1);
    mbedtls_mpi_free(&cm2);
    mbedtls_mpi_free(&cr1);
    mbedtls_mpi_free(&cr2);

    mbedtls_mpi_free(&e_m1_add_r1);
    mbedtls_mpi_free(&e_m2_add_r2);
    mbedtls_mpi_free(&e_m1_mul_r2);
    mbedtls_mpi_free(&e_m2_mul_r1);
    mbedtls_mpi_free(&e_r1_mul_r2);
    mbedtls_mpi_free(&e_3_party_add);
    mbedtls_mpi_free(&e_m1r1_mul_m2r2);
    mbedtls_mpi_free(&correction_factor);
    return ret;
}






/*-----函数实现，先放这里------*/

static void init_seed()
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
static void init_paillierKeys(paillierKeys *keys)
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
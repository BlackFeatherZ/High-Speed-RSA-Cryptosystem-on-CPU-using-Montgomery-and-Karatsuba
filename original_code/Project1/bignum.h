/*****************************************************************************
Filename    : bignum.h
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-8-31 10:31:23
Description :
*****************************************************************************/
#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <stdint.h>

typedef uint64_t dbn_t;
typedef uint32_t bn_t;

#define BN_DIGIT_BITS               32      // For uint32_t
#define BN_MAX_DIGITS              129      // RSA_MAX_MODULUS_LEN + 1

#define BN_MAX_DIGIT                0xFFFFFFFF

#define DIGIT_2MSB(x)               (uint32_t)(((x) >> (BN_DIGIT_BITS - 2)) & 0x03)


void bn_decode(bn_t *bn, uint32_t digits, uint8_t *hexarr, uint32_t size);
void bn_encode(uint8_t *hexarr, uint32_t size, bn_t *bn, uint32_t digits);

void bn_assign(bn_t *a, bn_t *b, uint32_t digits);                                          // a = b
void bn_assign_zero(bn_t *a, uint32_t digits);                                              // a = 0

bn_t bn_add(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                    // a = b + c, return carry
bn_t bn_sub(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                    // a = b - c, return borrow
void bn_mul(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                    // a = b * c
void bn_div(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits);        // a = b / c, d = b % c
bn_t bn_shift_l(bn_t *a, bn_t *b, uint32_t c, uint32_t digits);                             // a = b << c (a = b * 2^c)
bn_t bn_shift_r(bn_t *a, bn_t *b, uint32_t c, uint32_t digits);                             // a = b >> c (a = b / 2^c)

void bn_mod(bn_t *a, bn_t *b, uint32_t bdigits, bn_t *c, uint32_t cdigits);                 // a = b mod c
void bn_mod_mul(bn_t *a, bn_t *b, bn_t *c, bn_t *d, uint32_t digits);                       // a = b * c mod d
void bn_mod_exp(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits);    // a = b ^ c mod d

int bn_cmp(bn_t *a, bn_t *b, uint32_t digits);                                              // returns sign of a - b

uint32_t bn_digits(bn_t *a, uint32_t digits);                                               // returns significant length of a in digits
int length(bn_t value);//计算位数
void Karatsub(uint32_t *result, uint32_t *x,uint32_t *y);//计算大数乘法
void mulhilo(uint32_t x, uint32_t y, uint32_t *hi, uint32_t *lo);
uint32_t big_add(int count, uint32_t *res, uint32_t *x, uint32_t *y);
uint32_t big_sub(int count, uint32_t *res, uint32_t *x, uint32_t *y);
uint32_t leq(int count, uint32_t *x, uint32_t *y);
void mmul(uint32_t *res, uint32_t *x, uint32_t *y, uint32_t *m, uint32_t *mprime);
void modexp(uint32_t *res, uint32_t *base, uint32_t *exponent, uint32_t *m, uint32_t *m_prime, uint32_t *r_modp, uint32_t *r2_modp);


#define BN_ASSIGN_DIGIT(a, b, digits)   {bn_assign_zero(a, digits); a[0] = b;}

#endif  // __BIGNUM_H__

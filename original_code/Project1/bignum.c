/*****************************************************************************
Filename    : bignum.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-8-31 10:31:23
Description : 整理数据
*****************************************************************************/
#include <string.h>
#include "bignum.h"

static bn_t bn_sub_digit_mul(bn_t *a, bn_t *b, bn_t c, bn_t *d, uint32_t digits);
static bn_t bn_add_digit_mul(bn_t *a, bn_t *b, bn_t c, bn_t *d, uint32_t digits);
static uint32_t bn_digit_bits(bn_t a);

void bn_decode(bn_t *bn, uint32_t digits, uint8_t *hexarr, uint32_t size)
{
    bn_t t;
    int j;
    uint32_t i, u;
    for(i=0,j=size-1; i<digits && j>=0; i++) {
        t = 0;
        for(u=0; j>=0 && u<BN_DIGIT_BITS; j--, u+=8) {
            t |= ((bn_t)hexarr[j]) << u;
        }
        bn[i] = t;
    }

    for(; i<digits; i++) {
        bn[i] = 0;
    }
}

void bn_encode(uint8_t *hexarr, uint32_t size, bn_t *bn, uint32_t digits)
{
    bn_t t;
    int j;
    uint32_t i, u;

    for(i=0,j=size-1; i<digits && j>=0; i++) {
        t = bn[i];
        for(u=0; j>=0 && u<BN_DIGIT_BITS; j--, u+=8) {
            hexarr[j] = (uint8_t)(t >> u);
        }
    }

    for(; j>=0; j--) {
        hexarr[j] = 0;
    }
}

void bn_assign(bn_t *a, bn_t *b, uint32_t digits)
{
    uint32_t i;
    for(i=0; i<digits; i++) {
        a[i] = b[i];
    }
}

void bn_assign_zero(bn_t *a, uint32_t digits)
{
    uint32_t i;
    for(i=0; i<digits; i++) {
        a[i] = 0;
    }
}

bn_t bn_add(bn_t *a, bn_t *b, bn_t *c, uint32_t digits)
{
    bn_t ai, carry;
    uint32_t i;

    carry = 0;
    for(i=0; i<digits; i++) {
        if((ai = b[i] + carry) < carry) {
            ai = c[i];
        } else if((ai += c[i]) < c[i]) {
            carry = 1;
        } else {
            carry = 0;
        }
        a[i] = ai;
    }

    return carry;
}

bn_t bn_sub(bn_t *a, bn_t *b, bn_t *c, uint32_t digits)
{
    bn_t ai, borrow;
    uint32_t i;

    borrow = 0;
    for(i=0; i<digits; i++) {
        if((ai = b[i] - borrow) > (BN_MAX_DIGIT - borrow)) {
            ai = BN_MAX_DIGIT - c[i];
        } else if((ai -= c[i]) > (BN_MAX_DIGIT - c[i])) {
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[i] = ai;
    }

    return borrow;
}

void bn_mul(bn_t *a, bn_t *b, bn_t *c, uint32_t digits)
{
    bn_t t[2*BN_MAX_DIGITS];
    uint32_t bdigits, cdigits, i;

    bn_assign_zero(t, 2*digits);
    bdigits = bn_digits(b, digits);
    cdigits = bn_digits(c, digits);

    for(i=0; i<bdigits; i++) {
        t[i+cdigits] += bn_add_digit_mul(&t[i], &t[i], b[i], c, cdigits);
    }

    bn_assign(a, t, 2*digits);

    // Clear potentially sensitive information
    memset((uint8_t *)t, 0, sizeof(t));
}

void bn_div(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits)
{
    dbn_t tmp;
    bn_t ai, t, cc[2*BN_MAX_DIGITS+1], dd[BN_MAX_DIGITS];
    int i;
    uint32_t dddigits, shift;

    dddigits = bn_digits(d, ddigits);
    if(dddigits == 0)
        return;

    shift = BN_DIGIT_BITS - bn_digit_bits(d[dddigits-1]);
    bn_assign_zero(cc, dddigits);
    cc[cdigits] = bn_shift_l(cc, c, shift, cdigits);
    bn_shift_l(dd, d, shift, dddigits);
    t = dd[dddigits-1];

    bn_assign_zero(a, cdigits);
    i = cdigits - dddigits;
    for(; i>=0; i--) {
        if(t == BN_MAX_DIGIT) {
            ai = cc[i+dddigits];
        } else {
            tmp = cc[i+dddigits-1];
            tmp += (dbn_t)cc[i+dddigits] << BN_DIGIT_BITS;
            ai = tmp / (t + 1);
        }

        cc[i+dddigits] -= bn_sub_digit_mul(&cc[i], &cc[i], ai, dd, dddigits);
        // printf("cc[%d]: %08X\n", i, cc[i+dddigits]);
        while(cc[i+dddigits] || (bn_cmp(&cc[i], dd, dddigits) >= 0)) {
            ai++;
            cc[i+dddigits] -= bn_sub(&cc[i], &cc[i], dd, dddigits);
        }
        a[i] = ai;
        // printf("ai[%d]: %08X\n", i, ai);
    }

    bn_assign_zero(b, ddigits);
    bn_shift_r(b, cc, shift, dddigits);

    // Clear potentially sensitive information
    memset((uint8_t *)cc, 0, sizeof(cc));
    memset((uint8_t *)dd, 0, sizeof(dd));
}

bn_t bn_shift_l(bn_t *a, bn_t *b, uint32_t c, uint32_t digits)
{
    bn_t bi, carry;
    uint32_t i, t;

    if(c >= BN_DIGIT_BITS)
        return 0;

    t = BN_DIGIT_BITS - c;
    carry = 0;
    for(i=0; i<digits; i++) {
        bi = b[i];
        a[i] = (bi << c) | carry;
        carry = c ? (bi >> t) : 0;
    }

    return carry;
}

bn_t bn_shift_r(bn_t *a, bn_t *b, uint32_t c, uint32_t digits)
{
    bn_t bi, carry;
    int i;
    uint32_t t;

    if(c >= BN_DIGIT_BITS)
        return 0;

    t = BN_DIGIT_BITS - c;
    carry = 0;
    i = digits - 1;
    for(; i>=0; i--) {
        bi = b[i];
        a[i] = (bi >> c) | carry;
        carry = c ? (bi << t) : 0;
    }

    return carry;
}

void bn_mod(bn_t *a, bn_t *b, uint32_t bdigits, bn_t *c, uint32_t cdigits)
{
    bn_t t[2*BN_MAX_DIGITS] = {0};

    bn_div(t, a, b, bdigits, c, cdigits);

    // Clear potentially sensitive information
    memset((uint8_t *)t, 0, sizeof(t));
}

void bn_mod_mul(bn_t *a, bn_t *b, bn_t *c, bn_t *d, uint32_t digits)
{
    bn_t t[2*BN_MAX_DIGITS];

    bn_mul(t, b, c, digits);
    bn_mod(a, t, 2*digits, d, digits);

    // Clear potentially sensitive information
    memset((uint8_t *)t, 0, sizeof(t));
}

void bn_mod_exp(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits)
{
    bn_t bpower[3][BN_MAX_DIGITS], ci, t[BN_MAX_DIGITS];
    int i;
    uint32_t ci_bits, j, s;

    bn_assign(bpower[0], b, ddigits);
    bn_mod_mul(bpower[1], bpower[0], b, d, ddigits);
    bn_mod_mul(bpower[2], bpower[1], b, d, ddigits);

    BN_ASSIGN_DIGIT(t, 1, ddigits);

    cdigits = bn_digits(c, cdigits);
    i = cdigits - 1;
    for(; i>=0; i--) {
        ci = c[i];
        ci_bits = BN_DIGIT_BITS;

        if(i == (int)(cdigits - 1)) {
            while(!DIGIT_2MSB(ci)) {
                ci <<= 2;
                ci_bits -= 2;
            }
        }

        for(j=0; j<ci_bits; j+=2) {
            bn_mod_mul(t, t, t, d, ddigits);
            bn_mod_mul(t, t, t, d, ddigits);
            if((s = DIGIT_2MSB(ci)) != 0) {
                bn_mod_mul(t, t, bpower[s-1], d, ddigits);
            }
            ci <<= 2;
        }
    }

    bn_assign(a, t, ddigits);

    // Clear potentially sensitive information
    memset((uint8_t *)bpower, 0, sizeof(bpower));
    memset((uint8_t *)t, 0, sizeof(t));
}

int bn_cmp(bn_t *a, bn_t *b, uint32_t digits)
{
    int i;
    for(i=digits-1; i>=0; i--) {
        if(a[i] > b[i])     return 1;
        if(a[i] < b[i])     return -1;
    }

    return 0;
}

uint32_t bn_digits(bn_t *a, uint32_t digits)
{
    int i;
    for(i=digits-1; i>=0; i--) {
        if(a[i])    break;
    }

    return (i + 1);
}

static bn_t bn_add_digit_mul(bn_t *a, bn_t *b, bn_t c, bn_t *d, uint32_t digits)
{
    dbn_t result;
    bn_t carry, rh, rl;
    uint32_t i;

    if(c == 0)
        return 0;

    carry = 0;
    for(i=0; i<digits; i++) {
        result = (dbn_t)c * d[i];
        rl = result & BN_MAX_DIGIT;
        rh = (result >> BN_DIGIT_BITS) & BN_MAX_DIGIT;
        if((a[i] = b[i] + carry) < carry) {
            carry = 1;
        } else {
            carry = 0;
        }
        if((a[i] += rl) < rl) {
            carry++;
        }
        carry += rh;
    }

    return carry;
}

static bn_t bn_sub_digit_mul(bn_t *a, bn_t *b, bn_t c, bn_t *d, uint32_t digits)
{
    dbn_t result;
    bn_t borrow, rh, rl;
    uint32_t i;

    if(c == 0)
        return 0;

    borrow = 0;
    for(i=0; i<digits; i++) {
        result = (dbn_t)c * d[i];
        rl = result & BN_MAX_DIGIT;
        rh = (result >> BN_DIGIT_BITS) & BN_MAX_DIGIT;
        if((a[i] = b[i] - borrow) > (BN_MAX_DIGIT - borrow)) {
            borrow = 1;
        } else {
            borrow = 0;
        }
        if((a[i] -= rl) > (BN_MAX_DIGIT - rl)) {
            borrow++;
        }
        borrow += rh;
    }

    return borrow;
}

static uint32_t bn_digit_bits(bn_t a)
{
    uint32_t i;
    for(i=0; i<BN_DIGIT_BITS; i++) {
        if(a == 0)  break;
        a >>= 1;
    }

    return i;
}

uint32_t square(uint32_t m,uint32_t n)
{
	int a[50]={1};
	int i;

	int k=0;
	for(i=0;i<n;i++)
		k=10*k+a[i];
	return k;
}
int length(bn_t value)//计算位数
{
    int counter=0;
    while(value!=0)
    {
        counter++;
        value/=10;
    }
    return counter;
}
void Karatsub(bn_t *result, bn_t *x,bn_t *y)//计算大数乘法
{
	int N;
    int xlength=length(x);
    int ylength=length(y);
	uint32_t digits=0;
	uint32_t temp=0;
	uint32_t b=0;
	uint32_t d=0;
	uint32_t ydigits = bn_digits(x, digits);
    if(xlength>ylength)
        N=xlength;
    else
        N=ylength;
    if(N<10)
        bn_mul(result, x, y,ydigits);
	
    N=(N/2)+(N%2);
	
	
    uint32_t multi=square(10,N);
    bn_div(b, x, multi, ydigits, temp, ydigits);
    uint32_t a=x-(b*multi);
    bn_div(d, y, multi, ydigits, temp, ydigits);
    uint32_t c=y-(d*N);
    uint32_t h=square(10,(N*2));
    uint32_t g=square(10,N);
    result = (h*(b*d))+(g*((b*c)+(a*d)))+(c*a);
	
	// Clear potentially sensitive information
    memset((uint8_t *)multi, 0, sizeof(multi));
	memset((uint8_t *)a, 0, sizeof(a));
	memset((uint8_t *)b, 0, sizeof(b));
	memset((uint8_t *)c, 0, sizeof(c));
	memset((uint8_t *)d, 0, sizeof(d));
	memset((uint8_t *)g, 0, sizeof(g));
	memset((uint8_t *)h, 0, sizeof(h));
}
void mulhilo(uint32_t x, uint32_t y, uint32_t *hi, uint32_t *lo)
{
    uint64_t res = (uint64_t) x * (uint64_t) y;
    *lo = res;
    *hi = res >> 32;
}
uint32_t big_add(int count, uint32_t *res, uint32_t *x, uint32_t *y)
{
    int i;
    uint32_t carry = 0;
    for(i=0; i<count; i++)
	{
        res[i] = x[i] + y[i];
        uint32_t carry1 = res[i] < x[i];
        res[i] += carry;
        uint32_t carry2 = res[i] < carry;
        carry  = carry1 | carry2;
    }
    return carry;
}
uint32_t big_sub(int count, uint32_t *res, uint32_t *x, uint32_t *y)
{
    int i;
    uint32_t carry = 0;
    for(i=0; i<count; i++)
	{
        uint32_t temp = x[i] - y[i];
        uint32_t carry1 = temp > x[i];
        res[i] = temp - carry;
        uint32_t carry2 = res[i] > temp;
        carry  = carry1 | carry2;
    }
    return carry;
}
uint32_t leq(int count, uint32_t *x, uint32_t *y)
{
    int i;
    for(i=count - 1; i>=0; i--)
	{
        if(x[i]>y[i]) return 0;
        if(x[i]<y[i]) return 1;
    }
    return 1;
}
void mmul(uint32_t *res, uint32_t *x, uint32_t *y, uint32_t *m, uint32_t *mprime)
{
    uint32_t t[128], tm[64], tmm[128], u[128];

    int i;

    Karatsub(t, x, y);
    Karatsub(tm, t, mprime);
    Karatsub(tmm, tm, m);

    uint32_t ov = big_add(128, u, t, tmm);

    for(i=0; i<64; i++){
        res[i] = u[i+64];
    }

    if(ov>0 || leq(64, m, res)){
        big_sub(64, res, res, m);
    }
}
void modexp(uint32_t *res, uint32_t *base, uint32_t *exponent, uint32_t *m, uint32_t *m_prime, uint32_t *r_modp, uint32_t *r2_modp)
{
    int i, j;
    uint32_t base2[64];
    mmul(base2, base, r2_modp, m, m_prime);
    for(i=0; i<64; i++)
        res[i] = r_modp[i];

    for(i=0; i<64; i++)
	{
        uint32_t exp = exponent[i];
        for(j=0; j<32; j++)
		{
            if(exp & 0x1)
                mmul(res, res, base2, m, m_prime);
            mmul(base2, base2, base2, m, m_prime);
            exp >>= 1;
        }
    }

    uint32_t one[64];
    one[0] = 1;
    for(i=1; i<64; i++)
        one[i]=0;
	
    mmul(res, res, one, m, m_prime);
}

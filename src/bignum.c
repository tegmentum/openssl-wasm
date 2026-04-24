// bignum interface — BIGNUM arithmetic.
//
// Resource rep is the raw BIGNUM* (cast to our opaque struct pointer).
// This keeps allocation costs to a single BN per handle.

#include "bindings/openssl.h"
#include "include/support.h"

#include <openssl/bn.h>
#include <openssl/err.h>

#define BN_ERR_PARSE        EXPORTS_OPENSSL_COMPONENT_BIGNUM_BN_ERROR_PARSE_FAILED
#define BN_ERR_DIV_ZERO     EXPORTS_OPENSSL_COMPONENT_BIGNUM_BN_ERROR_DIV_BY_ZERO
#define BN_ERR_NOT_INV      EXPORTS_OPENSSL_COMPONENT_BIGNUM_BN_ERROR_NOT_INVERTIBLE
#define BN_ERR_RANGE        EXPORTS_OPENSSL_COMPONENT_BIGNUM_BN_ERROR_OUT_OF_RANGE
#define BN_ERR_INTERNAL     EXPORTS_OPENSSL_COMPONENT_BIGNUM_BN_ERROR_INTERNAL

static inline BIGNUM *as_bn(exports_openssl_component_bignum_borrow_bn_t b) {
    return (BIGNUM *)b;
}
static inline BIGNUM *as_bn_rep(exports_openssl_component_bignum_bn_t *r) {
    return (BIGNUM *)r;
}

static exports_openssl_component_bignum_own_bn_t handle_of(BIGNUM *bn) {
    return exports_openssl_component_bignum_bn_new(
        (exports_openssl_component_bignum_bn_t *)bn);
}

// Constructors -------------------------------------------------------------

exports_openssl_component_bignum_own_bn_t
exports_openssl_component_bignum_static_bn_zero(void) {
    BIGNUM *bn = BN_new();
    if (!bn) abort();
    return handle_of(bn);
}

exports_openssl_component_bignum_own_bn_t
exports_openssl_component_bignum_static_bn_from_u64(uint64_t v) {
    BIGNUM *bn = BN_new();
    if (!bn) abort();
    BN_set_word(bn, (BN_ULONG)v);
    // BN_ULONG is 32-bit on wasm32; upper 32 bits need an explicit lshift.
    if (sizeof(BN_ULONG) < sizeof(uint64_t) && (v >> 32)) {
        BIGNUM *hi = BN_new();
        BN_set_word(hi, (BN_ULONG)(v >> 32));
        BN_lshift(hi, hi, 32);
        BN_add(bn, bn, hi);
        BN_free(hi);
    }
    return handle_of(bn);
}

bool exports_openssl_component_bignum_static_bn_from_dec(
        openssl_string_t *s,
        exports_openssl_component_bignum_own_bn_t *ret,
        exports_openssl_component_bignum_bn_error_t *err) {
    BIGNUM *bn = NULL;
    char *nul = xmalloc(s->len + 1);
    memcpy(nul, s->ptr, s->len);
    nul[s->len] = 0;
    int rc = BN_dec2bn(&bn, nul);
    free(nul);
    if (rc == 0 || !bn) {
        if (bn) BN_free(bn);
        err->tag = BN_ERR_PARSE;
        return false;
    }
    *ret = handle_of(bn);
    return true;
}

bool exports_openssl_component_bignum_static_bn_from_hex(
        openssl_string_t *s,
        exports_openssl_component_bignum_own_bn_t *ret,
        exports_openssl_component_bignum_bn_error_t *err) {
    BIGNUM *bn = NULL;
    char *nul = xmalloc(s->len + 1);
    memcpy(nul, s->ptr, s->len);
    nul[s->len] = 0;
    int rc = BN_hex2bn(&bn, nul);
    free(nul);
    if (rc == 0 || !bn) {
        if (bn) BN_free(bn);
        err->tag = BN_ERR_PARSE;
        return false;
    }
    *ret = handle_of(bn);
    return true;
}

exports_openssl_component_bignum_own_bn_t
exports_openssl_component_bignum_static_bn_from_be_bytes(openssl_list_u8_t *bytes) {
    BIGNUM *bn = BN_bin2bn(bytes->ptr, (int)bytes->len, NULL);
    if (!bn) abort();
    return handle_of(bn);
}

exports_openssl_component_bignum_own_bn_t
exports_openssl_component_bignum_method_bn_clone(
        exports_openssl_component_bignum_borrow_bn_t self) {
    BIGNUM *dup = BN_dup(as_bn(self));
    if (!dup) abort();
    return handle_of(dup);
}

// Output -------------------------------------------------------------------

void exports_openssl_component_bignum_method_bn_to_dec(
        exports_openssl_component_bignum_borrow_bn_t self,
        openssl_string_t *ret) {
    char *s = BN_bn2dec(as_bn(self));
    size_t n = s ? strlen(s) : 0;
    string_take(ret, s ? s : "", n);
    if (s) OPENSSL_free(s);
}

void exports_openssl_component_bignum_method_bn_to_hex(
        exports_openssl_component_bignum_borrow_bn_t self,
        openssl_string_t *ret) {
    char *s = BN_bn2hex(as_bn(self));
    size_t n = s ? strlen(s) : 0;
    string_take(ret, s ? s : "", n);
    if (s) OPENSSL_free(s);
}

void exports_openssl_component_bignum_method_bn_to_be_bytes(
        exports_openssl_component_bignum_borrow_bn_t self,
        uint32_t *maybe_pad_to, openssl_list_u8_t *ret) {
    int nat = BN_num_bytes(as_bn(self));
    int out_len = nat;
    if (maybe_pad_to && *maybe_pad_to > (uint32_t)nat) {
        out_len = (int)*maybe_pad_to;
    }
    ret->ptr = xmalloc(out_len ? out_len : 1);
    ret->len = out_len;
    BN_bn2binpad(as_bn(self), ret->ptr, out_len);
}

// Predicates ---------------------------------------------------------------

uint32_t exports_openssl_component_bignum_method_bn_bits(
        exports_openssl_component_bignum_borrow_bn_t self) {
    return (uint32_t)BN_num_bits(as_bn(self));
}

bool exports_openssl_component_bignum_method_bn_is_zero(
        exports_openssl_component_bignum_borrow_bn_t self) {
    return BN_is_zero(as_bn(self)) != 0;
}

bool exports_openssl_component_bignum_method_bn_is_one(
        exports_openssl_component_bignum_borrow_bn_t self) {
    return BN_is_one(as_bn(self)) != 0;
}

bool exports_openssl_component_bignum_method_bn_is_odd(
        exports_openssl_component_bignum_borrow_bn_t self) {
    return BN_is_odd(as_bn(self)) != 0;
}

bool exports_openssl_component_bignum_method_bn_is_negative(
        exports_openssl_component_bignum_borrow_bn_t self) {
    return BN_is_negative(as_bn(self)) != 0;
}

bool exports_openssl_component_bignum_method_bn_equals(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t other) {
    return BN_cmp(as_bn(self), as_bn(other)) == 0;
}

int8_t exports_openssl_component_bignum_method_bn_compare(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t other) {
    int c = BN_cmp(as_bn(self), as_bn(other));
    return c > 0 ? 1 : (c < 0 ? -1 : 0);
}

// Arithmetic ---------------------------------------------------------------

exports_openssl_component_bignum_own_bn_t
exports_openssl_component_bignum_method_bn_add(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t other) {
    BIGNUM *r = BN_new();
    if (!r) abort();
    BN_add(r, as_bn(self), as_bn(other));
    return handle_of(r);
}

exports_openssl_component_bignum_own_bn_t
exports_openssl_component_bignum_method_bn_sub(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t other) {
    BIGNUM *r = BN_new();
    if (!r) abort();
    BN_sub(r, as_bn(self), as_bn(other));
    return handle_of(r);
}

exports_openssl_component_bignum_own_bn_t
exports_openssl_component_bignum_method_bn_mul(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t other) {
    BN_CTX *c = BN_CTX_new();
    BIGNUM *r = BN_new();
    if (!c || !r) abort();
    BN_mul(r, as_bn(self), as_bn(other), c);
    BN_CTX_free(c);
    return handle_of(r);
}

bool exports_openssl_component_bignum_method_bn_div(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t other,
        exports_openssl_component_bignum_tuple2_own_bn_own_bn_t *ret,
        exports_openssl_component_bignum_bn_error_t *err) {
    if (BN_is_zero(as_bn(other))) {
        err->tag = BN_ERR_DIV_ZERO; return false;
    }
    BN_CTX *c = BN_CTX_new();
    BIGNUM *q = BN_new(), *r = BN_new();
    if (!c || !q || !r) abort();
    int rc = BN_div(q, r, as_bn(self), as_bn(other), c);
    BN_CTX_free(c);
    if (rc != 1) {
        BN_free(q); BN_free(r);
        err->tag = BN_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->f0 = handle_of(q);
    ret->f1 = handle_of(r);
    return true;
}

bool exports_openssl_component_bignum_method_bn_modulo(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t m,
        exports_openssl_component_bignum_own_bn_t *ret,
        exports_openssl_component_bignum_bn_error_t *err) {
    if (BN_is_zero(as_bn(m))) { err->tag = BN_ERR_DIV_ZERO; return false; }
    BN_CTX *c = BN_CTX_new();
    BIGNUM *r = BN_new();
    if (!c || !r) abort();
    int rc = BN_mod(r, as_bn(self), as_bn(m), c);
    BN_CTX_free(c);
    if (rc != 1) {
        BN_free(r);
        err->tag = BN_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = handle_of(r);
    return true;
}

bool exports_openssl_component_bignum_method_bn_mod_exp(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t exp,
        exports_openssl_component_bignum_borrow_bn_t m,
        exports_openssl_component_bignum_own_bn_t *ret,
        exports_openssl_component_bignum_bn_error_t *err) {
    if (BN_is_zero(as_bn(m))) { err->tag = BN_ERR_DIV_ZERO; return false; }
    BN_CTX *c = BN_CTX_new();
    BIGNUM *r = BN_new();
    if (!c || !r) abort();
    int rc = BN_mod_exp(r, as_bn(self), as_bn(exp), as_bn(m), c);
    BN_CTX_free(c);
    if (rc != 1) {
        BN_free(r);
        err->tag = BN_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = handle_of(r);
    return true;
}

bool exports_openssl_component_bignum_method_bn_mod_inverse(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t m,
        exports_openssl_component_bignum_own_bn_t *ret,
        exports_openssl_component_bignum_bn_error_t *err) {
    BN_CTX *c = BN_CTX_new();
    if (!c) abort();
    BIGNUM *r = BN_new();
    BIGNUM *got = BN_mod_inverse(r, as_bn(self), as_bn(m), c);
    BN_CTX_free(c);
    if (!got) {
        BN_free(r);
        err->tag = BN_ERR_NOT_INV;
        return false;
    }
    *ret = handle_of(r);
    return true;
}

exports_openssl_component_bignum_own_bn_t
exports_openssl_component_bignum_method_bn_gcd(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_borrow_bn_t other) {
    BN_CTX *c = BN_CTX_new();
    BIGNUM *r = BN_new();
    if (!c || !r) abort();
    BN_gcd(r, as_bn(self), as_bn(other), c);
    BN_CTX_free(c);
    return handle_of(r);
}

bool exports_openssl_component_bignum_method_bn_random_below(
        exports_openssl_component_bignum_borrow_bn_t self,
        exports_openssl_component_bignum_own_bn_t *ret,
        exports_openssl_component_bignum_bn_error_t *err) {
    if (BN_is_zero(as_bn(self))) { err->tag = BN_ERR_RANGE; return false; }
    BIGNUM *r = BN_new();
    if (!r) abort();
    if (!BN_rand_range(r, as_bn(self))) {
        BN_free(r);
        err->tag = BN_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = handle_of(r);
    return true;
}

bool exports_openssl_component_bignum_method_bn_is_prime(
        exports_openssl_component_bignum_borrow_bn_t self) {
    BN_CTX *c = BN_CTX_new();
    int rc = BN_check_prime(as_bn(self), c, NULL);
    BN_CTX_free(c);
    return rc == 1;
}

bool exports_openssl_component_bignum_static_bn_generate_prime(
        uint32_t bits, bool safe,
        exports_openssl_component_bignum_own_bn_t *ret,
        exports_openssl_component_bignum_bn_error_t *err) {
    if (bits < 2) { err->tag = BN_ERR_RANGE; return false; }
    BIGNUM *r = BN_new();
    if (!r) abort();
    if (!BN_generate_prime_ex(r, (int)bits, safe ? 1 : 0, NULL, NULL, NULL)) {
        BN_free(r);
        err->tag = BN_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = handle_of(r);
    return true;
}

// Resource destructor ------------------------------------------------------

void exports_openssl_component_bignum_bn_destructor(
        exports_openssl_component_bignum_bn_t *rep) {
    if (rep) BN_free(as_bn_rep(rep));
}

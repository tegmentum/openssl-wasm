// x509 interface — construction paths.
//
// These were deferred during the initial x509 pass because they need
// programmatic ASN.1/extension plumbing. Kept in a separate file to
// keep x509.c (parse/verify) from ballooning.

#include "bindings/openssl.h"
#include "include/support.h"
#include "include/algs.h"

#include <stdio.h>
#include <strings.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define XE_SIGN        EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_SIGN_FAILED
#define XE_BAD_NAME    EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_BAD_NAME
#define XE_BAD_EXT     EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_BAD_EXTENSION
#define XE_ENCODING    EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_ENCODING_FAILED
#define XE_INTERNAL    EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_INTERNAL

static X509_NAME *build_name(const exports_openssl_component_x509_name_t *n) {
    X509_NAME *nm = X509_NAME_new();
    if (!nm) return NULL;
    for (size_t i = 0; i < n->len; i++) {
        char oid[128] = {0};
        size_t on = n->ptr[i].oid.len;
        if (on >= sizeof(oid)) on = sizeof(oid) - 1;
        memcpy(oid, n->ptr[i].oid.ptr, on);

        char val[1024] = {0};
        size_t vn = n->ptr[i].value.len;
        if (vn >= sizeof(val)) vn = sizeof(val) - 1;
        memcpy(val, n->ptr[i].value.ptr, vn);

        int nid = OBJ_txt2nid(oid);
        int ok;
        if (nid != NID_undef) {
            ok = X509_NAME_add_entry_by_NID(nm, nid, MBSTRING_UTF8,
                                            (unsigned char *)val, (int)vn, -1, 0);
        } else {
            ok = X509_NAME_add_entry_by_txt(nm, oid, MBSTRING_UTF8,
                                            (unsigned char *)val, (int)vn, -1, 0);
        }
        if (!ok) { X509_NAME_free(nm); return NULL; }
    }
    return nm;
}

// Build a GENERAL_NAMES stack from the WIT list.
static GENERAL_NAMES *build_sans(
        const exports_openssl_component_x509_list_general_name_t *sans) {
    if (sans->len == 0) return NULL;
    GENERAL_NAMES *gens = GENERAL_NAMES_new();
    if (!gens) return NULL;
    for (size_t i = 0; i < sans->len; i++) {
        GENERAL_NAME *gn = GENERAL_NAME_new();
        if (!gn) { GENERAL_NAMES_free(gens); return NULL; }
        const exports_openssl_component_x509_general_name_t *s = &sans->ptr[i];
        switch (s->tag) {
        case 0: { // dns
            ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
            ASN1_STRING_set(ia5, s->val.dns.ptr, (int)s->val.dns.len);
            GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);
            break;
        }
        case 1: { // email
            ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
            ASN1_STRING_set(ia5, s->val.email.ptr, (int)s->val.email.len);
            GENERAL_NAME_set0_value(gn, GEN_EMAIL, ia5);
            break;
        }
        case 2: { // uri
            ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
            ASN1_STRING_set(ia5, s->val.uri.ptr, (int)s->val.uri.len);
            GENERAL_NAME_set0_value(gn, GEN_URI, ia5);
            break;
        }
        case 3: { // ip
            ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
            ASN1_STRING_set(os, s->val.ip.ptr, (int)s->val.ip.len);
            GENERAL_NAME_set0_value(gn, GEN_IPADD, os);
            break;
        }
        default:
            GENERAL_NAME_free(gn);
            continue;
        }
        sk_GENERAL_NAME_push(gens, gn);
    }
    return gens;
}

// Encode the list<extended-key-usage> enum values into an
// EXTENDED_KEY_USAGE extension structure (a stack of ASN1_OBJECT).
static EXTENDED_KEY_USAGE *build_eku(
        const exports_openssl_component_x509_list_extended_key_usage_t *eku) {
    if (eku->len == 0) return NULL;
    EXTENDED_KEY_USAGE *ek = EXTENDED_KEY_USAGE_new();
    if (!ek) return NULL;
    for (size_t i = 0; i < eku->len; i++) {
        int nid;
        switch (eku->ptr[i]) {
        case 0: nid = NID_server_auth; break;
        case 1: nid = NID_client_auth; break;
        case 2: nid = NID_code_sign; break;
        case 3: nid = NID_email_protect; break;
        case 4: nid = NID_time_stamp; break;
        case 5: nid = NID_OCSP_sign; break;
        case 6: nid = NID_anyExtendedKeyUsage; break;
        default: continue;
        }
        ASN1_OBJECT *o = OBJ_nid2obj(nid);
        if (o) sk_ASN1_OBJECT_push(ek, OBJ_dup(o));
    }
    return ek;
}

static ASN1_BIT_STRING *build_ku(uint16_t flags) {
    ASN1_BIT_STRING *bs = ASN1_BIT_STRING_new();
    if (!bs) return NULL;
    for (int i = 0; i < 9; i++) {
        if (flags & (1u << i)) ASN1_BIT_STRING_set_bit(bs, i, 1);
    }
    return bs;
}

// Parse the ISO 8601 timestamp our WIT uses ("YYYY-MM-DDTHH:MM:SSZ").
static ASN1_TIME *parse_iso(const openssl_string_t *s) {
    char buf[32] = {0};
    size_t n = s->len < sizeof(buf) - 1 ? s->len : sizeof(buf) - 1;
    memcpy(buf, s->ptr, n);

    struct tm tm; memset(&tm, 0, sizeof(tm));
    int y, mo, d, h, mi, se;
    if (sscanf(buf, "%d-%d-%dT%d:%d:%dZ",
               &y, &mo, &d, &h, &mi, &se) != 6) return NULL;
    tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d;
    tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = se;
    time_t t = timegm(&tm);
    if (t == (time_t)-1) return NULL;
    return ASN1_TIME_set(NULL, t);
}

static int add_ext_d2i(X509 *cert, int nid, void *val) {
    X509_EXTENSION *ex = X509V3_EXT_i2d(nid, 0, val);
    if (!ex) return 0;
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return ok;
}

static int add_req_ext_d2i(STACK_OF(X509_EXTENSION) *exts, int nid, void *val) {
    X509_EXTENSION *ex = X509V3_EXT_i2d(nid, 0, val);
    if (!ex) return 0;
    sk_X509_EXTENSION_push(exts, ex);
    return 1;
}

static exports_openssl_component_x509_own_certificate_t cert_handle_(X509 *c) {
    return exports_openssl_component_x509_certificate_new(
        (exports_openssl_component_x509_certificate_t *)c);
}
static exports_openssl_component_x509_own_csr_t csr_handle_(X509_REQ *r) {
    return exports_openssl_component_x509_csr_new(
        (exports_openssl_component_x509_csr_t *)r);
}

// ---------------------------------------------------------------------------
// certificate::build-and-sign
// ---------------------------------------------------------------------------

bool exports_openssl_component_x509_build_and_sign(
        exports_openssl_component_x509_certificate_builder_input_t *input,
        exports_openssl_component_x509_borrow_pkey_t signer,
        exports_openssl_component_x509_own_certificate_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    X509 *c = X509_new();
    if (!c) { err->tag = XE_INTERNAL; return false; }

    X509_set_version(c, X509_VERSION_3);

    // Serial number: parse from hex if supplied, otherwise random 128-bit.
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (input->serial_hex.is_some) {
        BIGNUM *bn = NULL;
        char *nul = xmalloc(input->serial_hex.val.len + 1);
        memcpy(nul, input->serial_hex.val.ptr, input->serial_hex.val.len);
        nul[input->serial_hex.val.len] = 0;
        BN_hex2bn(&bn, nul);
        free(nul);
        if (bn) { BN_to_ASN1_INTEGER(bn, serial); BN_free(bn); }
    } else {
        unsigned char rnd[16];
        if (RAND_bytes(rnd, sizeof(rnd)) == 1) {
            rnd[0] &= 0x7f;  /* positive */
            BIGNUM *bn = BN_bin2bn(rnd, sizeof(rnd), NULL);
            if (bn) { BN_to_ASN1_INTEGER(bn, serial); BN_free(bn); }
        }
    }
    X509_set_serialNumber(c, serial);
    ASN1_INTEGER_free(serial);

    X509_NAME *subj = build_name(&input->subject);
    X509_NAME *iss = build_name(&input->issuer);
    if (!subj || !iss) {
        if (subj) X509_NAME_free(subj);
        if (iss) X509_NAME_free(iss);
        X509_free(c);
        err->tag = XE_BAD_NAME; return false;
    }
    X509_set_subject_name(c, subj);
    X509_set_issuer_name(c, iss);
    X509_NAME_free(subj); X509_NAME_free(iss);

    ASN1_TIME *nb = parse_iso(&input->validity.not_before);
    ASN1_TIME *na = parse_iso(&input->validity.not_after);
    if (!nb || !na) {
        if (nb) ASN1_TIME_free(nb);
        if (na) ASN1_TIME_free(na);
        X509_free(c);
        err->tag = XE_BAD_NAME; return false;
    }
    X509_set1_notBefore(c, nb);
    X509_set1_notAfter(c, na);
    ASN1_TIME_free(nb); ASN1_TIME_free(na);

    X509_set_pubkey(c, (EVP_PKEY *)exports_openssl_component_pkey_pkey_rep(input->subject_key));

    if (input->subject_alt_names.len > 0) {
        GENERAL_NAMES *gens = build_sans(&input->subject_alt_names);
        if (!gens || !add_ext_d2i(c, NID_subject_alt_name, gens)) {
            if (gens) GENERAL_NAMES_free(gens);
            X509_free(c); err->tag = XE_BAD_EXT; return false;
        }
        GENERAL_NAMES_free(gens);
    }
    if (input->key_usage.is_some) {
        ASN1_BIT_STRING *bs = build_ku(input->key_usage.val);
        if (!bs || !add_ext_d2i(c, NID_key_usage, bs)) {
            if (bs) ASN1_BIT_STRING_free(bs);
            X509_free(c); err->tag = XE_BAD_EXT; return false;
        }
        ASN1_BIT_STRING_free(bs);
    }
    if (input->extended_key_usage.len > 0) {
        EXTENDED_KEY_USAGE *ek = build_eku(&input->extended_key_usage);
        if (!ek || !add_ext_d2i(c, NID_ext_key_usage, ek)) {
            if (ek) EXTENDED_KEY_USAGE_free(ek);
            X509_free(c); err->tag = XE_BAD_EXT; return false;
        }
        EXTENDED_KEY_USAGE_free(ek);
    }
    if (input->basic_constraints.is_some) {
        BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
        bc->ca = input->basic_constraints.val.is_ca ? 1 : 0;
        if (input->basic_constraints.val.path_len.is_some) {
            bc->pathlen = ASN1_INTEGER_new();
            ASN1_INTEGER_set(bc->pathlen,
                input->basic_constraints.val.path_len.val);
        }
        if (!add_ext_d2i(c, NID_basic_constraints, bc)) {
            BASIC_CONSTRAINTS_free(bc);
            X509_free(c); err->tag = XE_BAD_EXT; return false;
        }
        BASIC_CONSTRAINTS_free(bc);
    }

    // Ed25519/Ed448 sign with built-in hash; pass NULL as the digest.
    int sid = EVP_PKEY_get_base_id((EVP_PKEY *)signer);
    const EVP_MD *md = (sid == EVP_PKEY_ED25519 || sid == EVP_PKEY_ED448)
        ? NULL : wit_digest_md(input->signature_hash);
    if (!X509_sign(c, (EVP_PKEY *)signer, md)) {
        X509_free(c);
        err->tag = XE_SIGN; err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = cert_handle_(c);
    return true;
}

// ---------------------------------------------------------------------------
// csr::build-and-sign
// ---------------------------------------------------------------------------

bool exports_openssl_component_x509_static_csr_build_and_sign(
        exports_openssl_component_x509_csr_info_t *info,
        exports_openssl_component_x509_borrow_pkey_t key,
        exports_openssl_component_x509_hash_t signature_hash,
        exports_openssl_component_x509_own_csr_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    X509_REQ *r = X509_REQ_new();
    if (!r) { err->tag = XE_INTERNAL; return false; }
    X509_REQ_set_version(r, X509_REQ_VERSION_1);

    X509_NAME *subj = build_name(&info->subject);
    if (!subj) { X509_REQ_free(r); err->tag = XE_BAD_NAME; return false; }
    X509_REQ_set_subject_name(r, subj);
    X509_NAME_free(subj);

    X509_REQ_set_pubkey(r, (EVP_PKEY *)key);

    if (info->subject_alt_names.len > 0) {
        GENERAL_NAMES *gens = build_sans(&info->subject_alt_names);
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
        if (!gens || !add_req_ext_d2i(exts, NID_subject_alt_name, gens)) {
            if (gens) GENERAL_NAMES_free(gens);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            X509_REQ_free(r); err->tag = XE_BAD_EXT; return false;
        }
        GENERAL_NAMES_free(gens);
        X509_REQ_add_extensions(r, exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    int sid = EVP_PKEY_get_base_id((EVP_PKEY *)key);
    const EVP_MD *md = (sid == EVP_PKEY_ED25519 || sid == EVP_PKEY_ED448)
        ? NULL : wit_digest_md(signature_hash);
    if (!X509_REQ_sign(r, (EVP_PKEY *)key, md)) {
        X509_REQ_free(r);
        err->tag = XE_SIGN; err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = csr_handle_(r);
    return true;
}

// ---------------------------------------------------------------------------
// pkcs12-build
// ---------------------------------------------------------------------------

bool exports_openssl_component_x509_pkcs12_build(
        exports_openssl_component_x509_pkcs12_build_input_t *input,
        openssl_list_u8_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    char *name = NULL;
    if (input->friendly_name.is_some) {
        name = xmalloc(input->friendly_name.val.len + 1);
        memcpy(name, input->friendly_name.val.ptr, input->friendly_name.val.len);
        name[input->friendly_name.val.len] = 0;
    }
    char *pass = xmalloc(input->passphrase.len + 1);
    memcpy(pass, input->passphrase.ptr, input->passphrase.len);
    pass[input->passphrase.len] = 0;

    STACK_OF(X509) *ca = sk_X509_new_null();
    for (size_t i = 0; i < input->extra_certs.len; i++) {
        X509 *c = (X509 *)exports_openssl_component_x509_certificate_rep(
            input->extra_certs.ptr[i]);
        X509_up_ref(c);
        sk_X509_push(ca, c);
    }

    PKCS12 *p12 = PKCS12_create(
        pass, name,
        (EVP_PKEY *)exports_openssl_component_pkey_pkey_rep(input->key),
        (X509 *)exports_openssl_component_x509_certificate_rep(input->cert),
        ca,
        0, 0, 0, 0, 0);

    sk_X509_pop_free(ca, X509_free);
    free(pass); if (name) free(name);
    if (!p12) { err->tag = XE_ENCODING; err->val.internal = ERR_peek_last_error(); return false; }

    BIO *b = BIO_new(BIO_s_mem());
    int ok = i2d_PKCS12_bio(b, p12);
    PKCS12_free(p12);
    if (!ok) { BIO_free(b); err->tag = XE_ENCODING; return false; }

    const unsigned char *buf = NULL;
    long n = BIO_get_mem_data(b, &buf);
    ret->ptr = xmalloc(n > 0 ? n : 1);
    memcpy(ret->ptr, buf, n);
    ret->len = (size_t)n;
    BIO_free(b);
    return true;
}

// ---------------------------------------------------------------------------
// cms-encrypt / cms-decrypt
// ---------------------------------------------------------------------------

static const EVP_CIPHER *cipher_by_name(const char *name) {
    // Fast path for a few common names; otherwise fetch.
    if (strcasecmp(name, "AES-128-GCM") == 0) return EVP_aes_128_gcm();
    if (strcasecmp(name, "AES-256-GCM") == 0) return EVP_aes_256_gcm();
    if (strcasecmp(name, "AES-128-CBC") == 0) return EVP_aes_128_cbc();
    if (strcasecmp(name, "AES-256-CBC") == 0) return EVP_aes_256_cbc();
    if (strcasecmp(name, "CHACHA20-POLY1305") == 0) return EVP_chacha20_poly1305();
    return NULL;
}

bool exports_openssl_component_x509_cms_encrypt(
        openssl_list_u8_t *content,
        exports_openssl_component_x509_list_borrow_certificate_t *recipients,
        openssl_string_t *cipher,
        exports_openssl_component_x509_encoding_t enc,
        openssl_list_u8_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    char cname[64] = {0};
    size_t n = cipher->len < sizeof(cname) - 1 ? cipher->len : sizeof(cname) - 1;
    memcpy(cname, cipher->ptr, n);
    const EVP_CIPHER *ec = cipher_by_name(cname);
    if (!ec) { err->tag = XE_ENCODING; return false; }

    STACK_OF(X509) *rcerts = sk_X509_new_null();
    for (size_t i = 0; i < recipients->len; i++) {
        sk_X509_push(rcerts, (X509 *)recipients->ptr[i]);
    }
    BIO *data = BIO_new_mem_buf(content->ptr, (int)content->len);
    CMS_ContentInfo *cms = CMS_encrypt(rcerts, data, ec, CMS_BINARY);
    sk_X509_free(rcerts);
    BIO_free(data);
    if (!cms) {
        err->tag = XE_ENCODING; err->val.internal = ERR_peek_last_error();
        return false;
    }
    BIO *out = BIO_new(BIO_s_mem());
    int ok = enc == 0 ? PEM_write_bio_CMS(out, cms) : i2d_CMS_bio(out, cms);
    CMS_ContentInfo_free(cms);
    if (!ok) { BIO_free(out); err->tag = XE_ENCODING; return false; }
    const unsigned char *buf = NULL;
    long nn = BIO_get_mem_data(out, &buf);
    ret->ptr = xmalloc(nn > 0 ? nn : 1);
    memcpy(ret->ptr, buf, nn);
    ret->len = (size_t)nn;
    BIO_free(out);
    return true;
}

bool exports_openssl_component_x509_cms_decrypt(
        openssl_list_u8_t *cms_bytes,
        exports_openssl_component_x509_borrow_pkey_t recipient,
        exports_openssl_component_x509_borrow_certificate_t recipient_cert,
        exports_openssl_component_x509_encoding_t enc,
        openssl_list_u8_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *in = BIO_new_mem_buf(cms_bytes->ptr, (int)cms_bytes->len);
    CMS_ContentInfo *cms = enc == 0
        ? PEM_read_bio_CMS(in, NULL, NULL, NULL)
        : d2i_CMS_bio(in, NULL);
    BIO_free(in);
    if (!cms) { err->tag = XE_ENCODING; err->val.internal = ERR_peek_last_error(); return false; }
    BIO *out = BIO_new(BIO_s_mem());
    int ok = CMS_decrypt(cms,
                         (EVP_PKEY *)recipient,
                         (X509 *)recipient_cert,
                         NULL, out, CMS_BINARY);
    CMS_ContentInfo_free(cms);
    if (!ok) {
        BIO_free(out);
        err->tag = XE_ENCODING; err->val.internal = ERR_peek_last_error();
        return false;
    }
    const unsigned char *buf = NULL;
    long nn = BIO_get_mem_data(out, &buf);
    ret->ptr = xmalloc(nn > 0 ? nn : 1);
    memcpy(ret->ptr, buf, nn);
    ret->len = (size_t)nn;
    BIO_free(out);
    return true;
}

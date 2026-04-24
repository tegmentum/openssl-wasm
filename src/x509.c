// x509 interface — certificates, CSRs, CRLs, stores, chain validation, PKCS#12, CMS.
//
// Covers the common paths: parse/encode/info/clone/destructor for each
// resource, verify-chain, pkcs12-parse, cms-sign/verify. Deferred (fall
// through to gen-stubs.sh): build-and-sign (cert and CSR), pkcs12-build,
// cms-encrypt/decrypt. Those require extension-encoding plumbing that
// adds another few hundred lines without materially changing the
// component's usefulness for verification workflows.

#include "bindings/openssl.h"
#include "include/support.h"
#include "include/algs.h"

#include <stdio.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>         /* must precede cms.h for PEM_*_CMS_* */
#include <openssl/cms.h>
#include <openssl/pkcs12.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define XE_PARSE           EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_PARSE_FAILED
#define XE_ENCODING        EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_ENCODING_FAILED
#define XE_SIGN            EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_SIGN_FAILED
#define XE_VERIFY          EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_VERIFY_FAILED
#define XE_BAD_NAME        EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_BAD_NAME
#define XE_BAD_EXT         EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_BAD_EXTENSION
#define XE_KEY_MISMATCH    EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_KEY_MISMATCH
#define XE_EXPIRED         EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_EXPIRED
#define XE_NOT_YET_VALID   EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_NOT_YET_VALID
#define XE_UNKNOWN_ISSUER  EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_UNKNOWN_ISSUER
#define XE_UNTRUSTED       EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_UNTRUSTED
#define XE_REVOKED         EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_REVOKED
#define XE_HOSTNAME        EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_HOSTNAME_MISMATCH
#define XE_INTERNAL        EXPORTS_OPENSSL_COMPONENT_X509_X509_ERROR_INTERNAL

static inline X509    *as_cert(exports_openssl_component_x509_borrow_certificate_t b)    { return (X509 *)b; }
static inline X509_REQ *as_csr(exports_openssl_component_x509_borrow_csr_t b)            { return (X509_REQ *)b; }
static inline X509_CRL *as_crl(exports_openssl_component_x509_borrow_crl_t b)            { return (X509_CRL *)b; }
static inline X509_STORE *as_store(exports_openssl_component_x509_borrow_store_t b)      { return (X509_STORE *)b; }
static inline EVP_PKEY *as_pkey(exports_openssl_component_x509_borrow_pkey_t b)          { return (EVP_PKEY *)b; }

static exports_openssl_component_x509_own_certificate_t cert_handle(X509 *c) {
    return exports_openssl_component_x509_certificate_new(
        (exports_openssl_component_x509_certificate_t *)c);
}
static exports_openssl_component_x509_own_csr_t csr_handle(X509_REQ *r) {
    return exports_openssl_component_x509_csr_new(
        (exports_openssl_component_x509_csr_t *)r);
}
static exports_openssl_component_x509_own_crl_t crl_handle(X509_CRL *r) {
    return exports_openssl_component_x509_crl_new(
        (exports_openssl_component_x509_crl_t *)r);
}
static exports_openssl_component_x509_own_store_t store_handle(X509_STORE *s) {
    return exports_openssl_component_x509_store_new(
        (exports_openssl_component_x509_store_t *)s);
}
static exports_openssl_component_x509_own_pkey_t pkey_handle(EVP_PKEY *p) {
    return exports_openssl_component_pkey_pkey_new(
        (exports_openssl_component_pkey_pkey_t *)p);
}

// ASN.1 time → ISO 8601 UTC string "YYYY-MM-DDTHH:MM:SSZ".
static void asn1_time_to_iso(const ASN1_TIME *t, openssl_string_t *out) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    char buf[32] = {0};
    if (t && ASN1_TIME_to_tm(t, &tm)) {
        snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);
    }
    string_take(out, buf, strlen(buf));
}

// Render X509_NAME as one-shot RFC 2253 string packed into a single
// name-entry — structured RDN extraction would be a lot more code.
static void name_to_list(X509_NAME *nm, exports_openssl_component_x509_name_t *out) {
    int n = nm ? X509_NAME_entry_count(nm) : 0;
    out->ptr = n > 0
        ? xmalloc(n * sizeof(exports_openssl_component_x509_name_entry_t))
        : xmalloc(sizeof(exports_openssl_component_x509_name_entry_t));
    out->len = n > 0 ? (size_t)n : 0;
    for (int i = 0; i < n; i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(nm, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(e);
        char oidbuf[128] = {0};
        int sn_nid = OBJ_obj2nid(obj);
        const char *sn = sn_nid != NID_undef ? OBJ_nid2sn(sn_nid) : NULL;
        if (sn) strncpy(oidbuf, sn, sizeof(oidbuf) - 1);
        else OBJ_obj2txt(oidbuf, sizeof(oidbuf), obj, 1);
        string_take(&out->ptr[i].oid, oidbuf, strlen(oidbuf));

        ASN1_STRING *val = X509_NAME_ENTRY_get_data(e);
        unsigned char *utf = NULL;
        int utflen = ASN1_STRING_to_UTF8(&utf, val);
        if (utflen < 0) { utf = (unsigned char *)""; utflen = 0; }
        string_take(&out->ptr[i].value, (char *)utf, (size_t)utflen);
        if (utflen > 0) OPENSSL_free(utf);
    }
}

static void ext_sans(X509 *cert, int nid,
                     exports_openssl_component_x509_list_general_name_t *out) {
    GENERAL_NAMES *gens = X509_get_ext_d2i(cert, nid, NULL, NULL);
    int n = gens ? sk_GENERAL_NAME_num(gens) : 0;
    out->ptr = n > 0
        ? xmalloc(n * sizeof(exports_openssl_component_x509_general_name_t))
        : xmalloc(sizeof(exports_openssl_component_x509_general_name_t));
    out->len = 0;
    for (int i = 0; i < n; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);
        int type = 0;
        void *p = GENERAL_NAME_get0_value(gn, &type);
        exports_openssl_component_x509_general_name_t *slot = &out->ptr[out->len++];
        memset(slot, 0, sizeof(*slot));
        switch (type) {
        case GEN_DNS: {
            ASN1_IA5STRING *s = p;
            slot->tag = EXPORTS_OPENSSL_COMPONENT_X509_GENERAL_NAME_DNS;
            string_take(&slot->val.dns,
                        (char *)ASN1_STRING_get0_data(s),
                        ASN1_STRING_length(s));
            break;
        }
        case GEN_EMAIL: {
            ASN1_IA5STRING *s = p;
            slot->tag = EXPORTS_OPENSSL_COMPONENT_X509_GENERAL_NAME_EMAIL;
            string_take(&slot->val.email,
                        (char *)ASN1_STRING_get0_data(s),
                        ASN1_STRING_length(s));
            break;
        }
        case GEN_URI: {
            ASN1_IA5STRING *s = p;
            slot->tag = EXPORTS_OPENSSL_COMPONENT_X509_GENERAL_NAME_URI;
            string_take(&slot->val.uri,
                        (char *)ASN1_STRING_get0_data(s),
                        ASN1_STRING_length(s));
            break;
        }
        case GEN_IPADD: {
            ASN1_OCTET_STRING *s = p;
            slot->tag = EXPORTS_OPENSSL_COMPONENT_X509_GENERAL_NAME_IP;
            list_u8_take(&slot->val.ip,
                         ASN1_STRING_get0_data(s),
                         ASN1_STRING_length(s));
            break;
        }
        default: {
            unsigned char *der = NULL;
            int dlen = i2d_GENERAL_NAME(gn, &der);
            slot->tag = EXPORTS_OPENSSL_COMPONENT_X509_GENERAL_NAME_OTHER;
            list_u8_take(&slot->val.other, der, dlen > 0 ? (size_t)dlen : 0);
            if (der) OPENSSL_free(der);
            break;
        }
        }
    }
    if (gens) GENERAL_NAMES_free(gens);
}

// --- Certificate ---------------------------------------------------------

bool exports_openssl_component_x509_static_certificate_parse(
        openssl_list_u8_t *bytes, exports_openssl_component_x509_encoding_t enc,
        exports_openssl_component_x509_own_certificate_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *b = BIO_new_mem_buf(bytes->ptr, (int)bytes->len);
    if (!b) { err->tag = XE_INTERNAL; err->val.internal = 0; return false; }
    X509 *c = enc == 0
        ? PEM_read_bio_X509(b, NULL, NULL, NULL)
        : d2i_X509_bio(b, NULL);
    BIO_free(b);
    if (!c) { err->tag = XE_PARSE; err->val.internal = ERR_peek_last_error(); return false; }
    *ret = cert_handle(c);
    return true;
}

bool exports_openssl_component_x509_static_certificate_parse_chain(
        openssl_list_u8_t *pem,
        exports_openssl_component_x509_list_own_certificate_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *b = BIO_new_mem_buf(pem->ptr, (int)pem->len);
    if (!b) { err->tag = XE_INTERNAL; err->val.internal = 0; return false; }
    size_t cap = 4, n = 0;
    exports_openssl_component_x509_own_certificate_t *arr =
        xmalloc(cap * sizeof(*arr));
    for (;;) {
        X509 *c = PEM_read_bio_X509(b, NULL, NULL, NULL);
        if (!c) { ERR_clear_error(); break; }
        if (n == cap) { cap *= 2; arr = realloc(arr, cap * sizeof(*arr)); }
        arr[n++] = cert_handle(c);
    }
    BIO_free(b);
    if (n == 0) { free(arr); err->tag = XE_PARSE; return false; }
    ret->ptr = arr;
    ret->len = n;
    return true;
}

bool exports_openssl_component_x509_method_certificate_encode(
        exports_openssl_component_x509_borrow_certificate_t self,
        exports_openssl_component_x509_encoding_t enc,
        openssl_list_u8_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *b = BIO_new(BIO_s_mem());
    int ok = enc == 0 ? PEM_write_bio_X509(b, as_cert(self))
                      : i2d_X509_bio(b, as_cert(self));
    if (!ok) {
        BIO_free(b);
        err->tag = XE_ENCODING; err->val.internal = ERR_peek_last_error();
        return false;
    }
    const unsigned char *buf = NULL;
    long n = BIO_get_mem_data(b, &buf);
    ret->ptr = xmalloc(n > 0 ? (size_t)n : 1);
    memcpy(ret->ptr, buf, n);
    ret->len = (size_t)n;
    BIO_free(b);
    return true;
}

void exports_openssl_component_x509_method_certificate_info(
        exports_openssl_component_x509_borrow_certificate_t self,
        exports_openssl_component_x509_certificate_info_t *ret) {
    X509 *c = as_cert(self);
    memset(ret, 0, sizeof(*ret));
    ret->version = (uint32_t)(X509_get_version(c) + 1);

    const ASN1_INTEGER *serial = X509_get0_serialNumber(c);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    char *hx = bn ? BN_bn2hex(bn) : NULL;
    string_take(&ret->serial_hex, hx ? hx : "", hx ? strlen(hx) : 0);
    if (hx) OPENSSL_free(hx);
    if (bn) BN_free(bn);

    name_to_list(X509_get_issuer_name(c), &ret->issuer);
    name_to_list(X509_get_subject_name(c), &ret->subject);
    asn1_time_to_iso(X509_get0_notBefore(c), &ret->validity.not_before);
    asn1_time_to_iso(X509_get0_notAfter(c), &ret->validity.not_after);

    int sig_nid = X509_get_signature_nid(c);
    const char *sig_name = sig_nid != NID_undef ? OBJ_nid2ln(sig_nid) : "unknown";
    string_take(&ret->signature_algorithm, sig_name, strlen(sig_name));

    ext_sans(c, NID_subject_alt_name, &ret->subject_alt_names);
    ext_sans(c, NID_issuer_alt_name, &ret->issuer_alt_names);

    uint32_t ku = X509_get_key_usage(c);
    if (ku != UINT32_MAX) {
        ret->key_usage.is_some = true;
        ret->key_usage.val = (uint16_t)ku;
    }

    uint32_t xku = X509_get_extended_key_usage(c);
    if (xku != UINT32_MAX) {
        uint8_t tmp[8]; size_t tn = 0;
        if (xku & XKU_SSL_SERVER)   tmp[tn++] = 0;
        if (xku & XKU_SSL_CLIENT)   tmp[tn++] = 1;
        if (xku & XKU_CODE_SIGN)    tmp[tn++] = 2;
        if (xku & XKU_SMIME)        tmp[tn++] = 3;
        if (xku & XKU_TIMESTAMP)    tmp[tn++] = 4;
        if (xku & XKU_OCSP_SIGN)    tmp[tn++] = 5;
        if (xku & XKU_ANYEKU)       tmp[tn++] = 6;
        ret->extended_key_usage.ptr = xmalloc(tn ? tn : 1);
        memcpy(ret->extended_key_usage.ptr, tmp, tn);
        ret->extended_key_usage.len = tn;
    } else {
        ret->extended_key_usage.ptr = xmalloc(1);
        ret->extended_key_usage.len = 0;
    }

    BASIC_CONSTRAINTS *bc = X509_get_ext_d2i(c, NID_basic_constraints, NULL, NULL);
    if (bc) {
        ret->basic_constraints.is_some = true;
        ret->basic_constraints.val.is_ca = bc->ca != 0;
        if (bc->pathlen) {
            ret->basic_constraints.val.path_len.is_some = true;
            ret->basic_constraints.val.path_len.val =
                (uint32_t)ASN1_INTEGER_get(bc->pathlen);
        }
        BASIC_CONSTRAINTS_free(bc);
    }

    // SHA-256 fingerprint of DER encoding.
    unsigned char *der = NULL;
    int dlen = i2d_X509(c, &der);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    EVP_Digest(der, dlen, md, &mdlen, EVP_sha256(), NULL);
    list_u8_take(&ret->fingerprint_sha256, md, mdlen);
    if (der) OPENSSL_free(der);
}

exports_openssl_component_x509_own_pkey_t
exports_openssl_component_x509_method_certificate_public_key(
        exports_openssl_component_x509_borrow_certificate_t self) {
    EVP_PKEY *p = X509_get_pubkey(as_cert(self));
    if (!p) abort();
    return pkey_handle(p);
}

bool exports_openssl_component_x509_method_certificate_verify_signature(
        exports_openssl_component_x509_borrow_certificate_t self,
        exports_openssl_component_x509_borrow_pkey_t issuer,
        bool *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    int rc = X509_verify(as_cert(self), as_pkey(issuer));
    if (rc < 0) {
        err->tag = XE_VERIFY; err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = (rc == 1);
    return true;
}

void exports_openssl_component_x509_method_certificate_fingerprint(
        exports_openssl_component_x509_borrow_certificate_t self,
        exports_openssl_component_x509_hash_t alg, openssl_list_u8_t *ret) {
    const EVP_MD *md = wit_digest_md(alg);
    if (!md) { list_u8_take(ret, NULL, 0); return; }
    unsigned char *der = NULL;
    int dlen = i2d_X509(as_cert(self), &der);
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hlen = 0;
    EVP_Digest(der, dlen > 0 ? dlen : 0, hash, &hlen, md, NULL);
    list_u8_take(ret, hash, hlen);
    if (der) OPENSSL_free(der);
}

exports_openssl_component_x509_own_certificate_t
exports_openssl_component_x509_method_certificate_clone(
        exports_openssl_component_x509_borrow_certificate_t self) {
    X509 *c = as_cert(self);
    X509_up_ref(c);
    return cert_handle(c);
}

void exports_openssl_component_x509_certificate_destructor(
        exports_openssl_component_x509_certificate_t *rep) {
    if (rep) X509_free((X509 *)rep);
}

// --- CSR ------------------------------------------------------------------

bool exports_openssl_component_x509_static_csr_parse(
        openssl_list_u8_t *bytes, exports_openssl_component_x509_encoding_t enc,
        exports_openssl_component_x509_own_csr_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *b = BIO_new_mem_buf(bytes->ptr, (int)bytes->len);
    X509_REQ *r = enc == 0
        ? PEM_read_bio_X509_REQ(b, NULL, NULL, NULL)
        : d2i_X509_REQ_bio(b, NULL);
    BIO_free(b);
    if (!r) { err->tag = XE_PARSE; err->val.internal = ERR_peek_last_error(); return false; }
    *ret = csr_handle(r);
    return true;
}

bool exports_openssl_component_x509_method_csr_encode(
        exports_openssl_component_x509_borrow_csr_t self,
        exports_openssl_component_x509_encoding_t enc,
        openssl_list_u8_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *b = BIO_new(BIO_s_mem());
    int ok = enc == 0 ? PEM_write_bio_X509_REQ(b, as_csr(self))
                      : i2d_X509_REQ_bio(b, as_csr(self));
    if (!ok) { BIO_free(b); err->tag = XE_ENCODING; return false; }
    const unsigned char *buf = NULL;
    long n = BIO_get_mem_data(b, &buf);
    ret->ptr = xmalloc(n > 0 ? (size_t)n : 1);
    memcpy(ret->ptr, buf, n);
    ret->len = (size_t)n;
    BIO_free(b);
    return true;
}

void exports_openssl_component_x509_method_csr_info(
        exports_openssl_component_x509_borrow_csr_t self,
        exports_openssl_component_x509_csr_info_t *ret) {
    X509_REQ *r = as_csr(self);
    memset(ret, 0, sizeof(*ret));
    name_to_list(X509_REQ_get_subject_name(r), &ret->subject);

    // SANs may live in a CSR attribute (NID_ext_req).
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(r);
    GENERAL_NAMES *gens = exts
        ? X509V3_get_d2i(exts, NID_subject_alt_name, NULL, NULL)
        : NULL;
    if (gens) {
        int n = sk_GENERAL_NAME_num(gens);
        ret->subject_alt_names.ptr = n > 0
            ? xmalloc(n * sizeof(*ret->subject_alt_names.ptr))
            : xmalloc(sizeof(*ret->subject_alt_names.ptr));
        ret->subject_alt_names.len = 0;
        for (int i = 0; i < n; i++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);
            int type = 0;
            void *p = GENERAL_NAME_get0_value(gn, &type);
            exports_openssl_component_x509_general_name_t *slot =
                &ret->subject_alt_names.ptr[ret->subject_alt_names.len++];
            memset(slot, 0, sizeof(*slot));
            if (type == GEN_DNS) {
                ASN1_IA5STRING *s = p;
                slot->tag = 0;
                string_take(&slot->val.dns,
                            (char *)ASN1_STRING_get0_data(s),
                            ASN1_STRING_length(s));
            } else {
                slot->tag = 4;
                unsigned char *der = NULL;
                int dlen = i2d_GENERAL_NAME(gn, &der);
                list_u8_take(&slot->val.other, der, dlen > 0 ? dlen : 0);
                if (der) OPENSSL_free(der);
            }
        }
        GENERAL_NAMES_free(gens);
    } else {
        ret->subject_alt_names.ptr = xmalloc(1);
        ret->subject_alt_names.len = 0;
    }
    if (exts) sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
}

exports_openssl_component_x509_own_pkey_t
exports_openssl_component_x509_method_csr_public_key(
        exports_openssl_component_x509_borrow_csr_t self) {
    EVP_PKEY *p = X509_REQ_get_pubkey(as_csr(self));
    if (!p) abort();
    return pkey_handle(p);
}

bool exports_openssl_component_x509_method_csr_verify_signature(
        exports_openssl_component_x509_borrow_csr_t self, bool *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    EVP_PKEY *pk = X509_REQ_get_pubkey(as_csr(self));
    if (!pk) { err->tag = XE_VERIFY; return false; }
    int rc = X509_REQ_verify(as_csr(self), pk);
    EVP_PKEY_free(pk);
    if (rc < 0) { err->tag = XE_VERIFY; err->val.internal = ERR_peek_last_error(); return false; }
    *ret = (rc == 1);
    return true;
}

void exports_openssl_component_x509_csr_destructor(
        exports_openssl_component_x509_csr_t *rep) {
    if (rep) X509_REQ_free((X509_REQ *)rep);
}

// --- CRL ------------------------------------------------------------------

bool exports_openssl_component_x509_static_crl_parse(
        openssl_list_u8_t *bytes, exports_openssl_component_x509_encoding_t enc,
        exports_openssl_component_x509_own_crl_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *b = BIO_new_mem_buf(bytes->ptr, (int)bytes->len);
    X509_CRL *c = enc == 0
        ? PEM_read_bio_X509_CRL(b, NULL, NULL, NULL)
        : d2i_X509_CRL_bio(b, NULL);
    BIO_free(b);
    if (!c) { err->tag = XE_PARSE; err->val.internal = ERR_peek_last_error(); return false; }
    *ret = crl_handle(c);
    return true;
}

bool exports_openssl_component_x509_method_crl_encode(
        exports_openssl_component_x509_borrow_crl_t self,
        exports_openssl_component_x509_encoding_t enc,
        openssl_list_u8_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *b = BIO_new(BIO_s_mem());
    int ok = enc == 0 ? PEM_write_bio_X509_CRL(b, as_crl(self))
                      : i2d_X509_CRL_bio(b, as_crl(self));
    if (!ok) { BIO_free(b); err->tag = XE_ENCODING; return false; }
    const unsigned char *buf = NULL;
    long n = BIO_get_mem_data(b, &buf);
    ret->ptr = xmalloc(n > 0 ? (size_t)n : 1);
    memcpy(ret->ptr, buf, n);
    ret->len = (size_t)n;
    BIO_free(b);
    return true;
}

void exports_openssl_component_x509_method_crl_info(
        exports_openssl_component_x509_borrow_crl_t self,
        exports_openssl_component_x509_crl_info_t *ret) {
    X509_CRL *c = as_crl(self);
    memset(ret, 0, sizeof(*ret));
    name_to_list(X509_CRL_get_issuer(c), &ret->issuer);
    asn1_time_to_iso(X509_CRL_get0_lastUpdate(c), &ret->this_update);
    const ASN1_TIME *nu = X509_CRL_get0_nextUpdate(c);
    if (nu) {
        ret->next_update.is_some = true;
        asn1_time_to_iso(nu, &ret->next_update.val);
    }
    STACK_OF(X509_REVOKED) *revs = X509_CRL_get_REVOKED(c);
    int n = revs ? sk_X509_REVOKED_num(revs) : 0;
    ret->revoked.ptr = n > 0
        ? xmalloc(n * sizeof(*ret->revoked.ptr))
        : xmalloc(sizeof(*ret->revoked.ptr));
    ret->revoked.len = n > 0 ? (size_t)n : 0;
    for (int i = 0; i < n; i++) {
        X509_REVOKED *r = sk_X509_REVOKED_value(revs, i);
        BIGNUM *bn = ASN1_INTEGER_to_BN(X509_REVOKED_get0_serialNumber(r), NULL);
        char *hx = bn ? BN_bn2hex(bn) : NULL;
        string_take(&ret->revoked.ptr[i].serial_hex,
                    hx ? hx : "", hx ? strlen(hx) : 0);
        if (hx) OPENSSL_free(hx);
        if (bn) BN_free(bn);
        asn1_time_to_iso(X509_REVOKED_get0_revocationDate(r),
                         &ret->revoked.ptr[i].revocation_date);
        ret->revoked.ptr[i].reason.is_some = false;
    }
}

bool exports_openssl_component_x509_method_crl_verify_signature(
        exports_openssl_component_x509_borrow_crl_t self,
        exports_openssl_component_x509_borrow_pkey_t issuer, bool *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    int rc = X509_CRL_verify(as_crl(self), as_pkey(issuer));
    if (rc < 0) { err->tag = XE_VERIFY; err->val.internal = ERR_peek_last_error(); return false; }
    *ret = (rc == 1);
    return true;
}

bool exports_openssl_component_x509_method_crl_is_revoked(
        exports_openssl_component_x509_borrow_crl_t self,
        openssl_string_t *serial_hex) {
    BIGNUM *bn = NULL;
    char *nul = xmalloc(serial_hex->len + 1);
    memcpy(nul, serial_hex->ptr, serial_hex->len);
    nul[serial_hex->len] = 0;
    int ok = BN_hex2bn(&bn, nul);
    free(nul);
    if (!ok || !bn) { if (bn) BN_free(bn); return false; }
    ASN1_INTEGER *ai = BN_to_ASN1_INTEGER(bn, NULL);
    BN_free(bn);
    STACK_OF(X509_REVOKED) *revs = X509_CRL_get_REVOKED(as_crl(self));
    int n = revs ? sk_X509_REVOKED_num(revs) : 0;
    bool found = false;
    for (int i = 0; i < n; i++) {
        X509_REVOKED *r = sk_X509_REVOKED_value(revs, i);
        if (ASN1_INTEGER_cmp(X509_REVOKED_get0_serialNumber(r), ai) == 0) {
            found = true; break;
        }
    }
    ASN1_INTEGER_free(ai);
    return found;
}

void exports_openssl_component_x509_crl_destructor(
        exports_openssl_component_x509_crl_t *rep) {
    if (rep) X509_CRL_free((X509_CRL *)rep);
}

// --- Store ----------------------------------------------------------------

exports_openssl_component_x509_own_store_t
exports_openssl_component_x509_constructor_store(void) {
    X509_STORE *s = X509_STORE_new();
    if (!s) abort();
    return store_handle(s);
}

bool exports_openssl_component_x509_method_store_add_trusted(
        exports_openssl_component_x509_borrow_store_t self,
        exports_openssl_component_x509_borrow_certificate_t cert,
        exports_openssl_component_x509_x509_error_t *err) {
    if (X509_STORE_add_cert(as_store(self), as_cert(cert)) != 1) {
        err->tag = XE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

// "Untrusted" certs are stored in the verification CTX when verifying,
// not in the store. We stash them in a per-store STACK via ex_data.
static int untrusted_idx(void) {
    static int idx = -1;
    if (idx == -1) {
        idx = X509_STORE_get_ex_new_index(
            0, (void *)"untrusted", NULL, NULL, NULL);
    }
    return idx;
}

static STACK_OF(X509) *store_get_untrusted(X509_STORE *s) {
    STACK_OF(X509) *stk = X509_STORE_get_ex_data(s, untrusted_idx());
    if (!stk) {
        stk = sk_X509_new_null();
        X509_STORE_set_ex_data(s, untrusted_idx(), stk);
    }
    return stk;
}

bool exports_openssl_component_x509_method_store_add_untrusted(
        exports_openssl_component_x509_borrow_store_t self,
        exports_openssl_component_x509_borrow_certificate_t cert,
        exports_openssl_component_x509_x509_error_t *err) {
    STACK_OF(X509) *stk = store_get_untrusted(as_store(self));
    if (!stk) { err->tag = XE_INTERNAL; err->val.internal = 0; return false; }
    X509_up_ref(as_cert(cert));
    sk_X509_push(stk, as_cert(cert));
    return true;
}

bool exports_openssl_component_x509_method_store_load_defaults(
        exports_openssl_component_x509_borrow_store_t self,
        exports_openssl_component_x509_x509_error_t *err) {
    (void)self;
    // wasi has no system trust store; return OK as a no-op so callers can
    // compose this with add-trusted/load-from-file.
    (void)err;
    return true;
}

bool exports_openssl_component_x509_method_store_load_from_file(
        exports_openssl_component_x509_borrow_store_t self,
        openssl_string_t *path,
        exports_openssl_component_x509_x509_error_t *err) {
    char *nul = xmalloc(path->len + 1);
    memcpy(nul, path->ptr, path->len);
    nul[path->len] = 0;
    int rc = X509_STORE_load_file(as_store(self), nul);
    free(nul);
    if (rc != 1) { err->tag = XE_INTERNAL; err->val.internal = ERR_peek_last_error(); return false; }
    return true;
}

bool exports_openssl_component_x509_method_store_add_crl(
        exports_openssl_component_x509_borrow_store_t self,
        exports_openssl_component_x509_borrow_crl_t crl,
        exports_openssl_component_x509_x509_error_t *err) {
    if (X509_STORE_add_crl(as_store(self), as_crl(crl)) != 1) {
        err->tag = XE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

void exports_openssl_component_x509_store_destructor(
        exports_openssl_component_x509_store_t *rep) {
    if (!rep) return;
    X509_STORE *s = (X509_STORE *)rep;
    STACK_OF(X509) *stk = X509_STORE_get_ex_data(s, untrusted_idx());
    if (stk) sk_X509_pop_free(stk, X509_free);
    X509_STORE_free(s);
}

// Chain verification ------------------------------------------------------

bool exports_openssl_component_x509_verify_chain(
        exports_openssl_component_x509_borrow_store_t store,
        exports_openssl_component_x509_borrow_certificate_t leaf,
        exports_openssl_component_x509_list_borrow_certificate_t *extra,
        exports_openssl_component_x509_verify_options_t *opts,
        exports_openssl_component_x509_list_own_certificate_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    STACK_OF(X509) *stash = store_get_untrusted(as_store(store));
    for (int i = 0; i < sk_X509_num(stash); i++) {
        sk_X509_push(untrusted, sk_X509_value(stash, i));
    }
    for (size_t i = 0; i < extra->len; i++) {
        sk_X509_push(untrusted, (X509 *)extra->ptr[i]);
    }
    if (X509_STORE_CTX_init(ctx, as_store(store), as_cert(leaf), untrusted) != 1) {
        X509_STORE_CTX_free(ctx); sk_X509_free(untrusted);
        err->tag = XE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }

    X509_VERIFY_PARAM *vp = X509_STORE_CTX_get0_param(ctx);
    if (opts->hostname.is_some) {
        X509_VERIFY_PARAM_set1_host(vp, (char *)opts->hostname.val.ptr,
                                    opts->hostname.val.len);
    }
    if (opts->ip.is_some) {
        char *ips = xmalloc(opts->ip.val.len + 1);
        memcpy(ips, opts->ip.val.ptr, opts->ip.val.len);
        ips[opts->ip.val.len] = 0;
        X509_VERIFY_PARAM_set1_ip_asc(vp, ips);
        free(ips);
    }
    if (opts->purpose.is_some) {
        static const int purpose_map[7] = {
            X509_PURPOSE_SSL_SERVER, X509_PURPOSE_SSL_CLIENT,
            X509_PURPOSE_CODE_SIGN, X509_PURPOSE_SMIME_SIGN,
            X509_PURPOSE_TIMESTAMP_SIGN, X509_PURPOSE_OCSP_HELPER,
            X509_PURPOSE_ANY
        };
        X509_VERIFY_PARAM_set_purpose(vp, purpose_map[opts->purpose.val]);
    }
    unsigned long flags = 0;
    if (opts->partial_chain) flags |= X509_V_FLAG_PARTIAL_CHAIN;
    if (opts->crl_check)     flags |= X509_V_FLAG_CRL_CHECK;
    if (opts->crl_check_all) flags |= X509_V_FLAG_CRL_CHECK_ALL;
    if (flags) X509_VERIFY_PARAM_set_flags(vp, flags);

    int rc = X509_verify_cert(ctx);
    if (rc != 1) {
        int e = X509_STORE_CTX_get_error(ctx);
        X509_STORE_CTX_free(ctx); sk_X509_free(untrusted);
        switch (e) {
        case X509_V_ERR_CERT_HAS_EXPIRED:      err->tag = XE_EXPIRED; break;
        case X509_V_ERR_CERT_NOT_YET_VALID:    err->tag = XE_NOT_YET_VALID; break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                                               err->tag = XE_UNKNOWN_ISSUER; break;
        case X509_V_ERR_CERT_REVOKED:          err->tag = XE_REVOKED; break;
        case X509_V_ERR_HOSTNAME_MISMATCH:     err->tag = XE_HOSTNAME; break;
        default:                                err->tag = XE_UNTRUSTED; break;
        }
        err->val.internal = (uint64_t)e;
        return false;
    }
    STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
    int n = sk_X509_num(chain);
    ret->ptr = xmalloc(n > 0 ? n * sizeof(*ret->ptr) : sizeof(*ret->ptr));
    ret->len = (size_t)(n > 0 ? n : 0);
    for (int i = 0; i < n; i++) {
        X509 *c = sk_X509_value(chain, i);
        X509_up_ref(c);
        ret->ptr[i] = cert_handle(c);
    }
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_CTX_free(ctx);
    sk_X509_free(untrusted);
    return true;
}

// --- PKCS#12 --------------------------------------------------------------

bool exports_openssl_component_x509_pkcs12_parse(
        openssl_list_u8_t *bytes, openssl_list_u8_t *passphrase,
        exports_openssl_component_x509_pkcs12_contents_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *b = BIO_new_mem_buf(bytes->ptr, (int)bytes->len);
    PKCS12 *p12 = d2i_PKCS12_bio(b, NULL);
    BIO_free(b);
    if (!p12) { err->tag = XE_PARSE; err->val.internal = ERR_peek_last_error(); return false; }

    char *pass = xmalloc(passphrase->len + 1);
    memcpy(pass, passphrase->ptr, passphrase->len);
    pass[passphrase->len] = 0;

    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int ok = PKCS12_parse(p12, pass, &pkey, &cert, &ca);
    PKCS12_free(p12);
    free(pass);
    if (!ok) { err->tag = XE_PARSE; err->val.internal = ERR_peek_last_error(); return false; }

    memset(ret, 0, sizeof(*ret));
    if (pkey) {
        ret->key.is_some = true;
        ret->key.val = pkey_handle(pkey);
    }
    if (cert) {
        ret->cert.is_some = true;
        ret->cert.val = cert_handle(cert);
    }
    int n = ca ? sk_X509_num(ca) : 0;
    ret->extra_certs.ptr = xmalloc(n > 0 ? n * sizeof(*ret->extra_certs.ptr) : sizeof(*ret->extra_certs.ptr));
    ret->extra_certs.len = (size_t)(n > 0 ? n : 0);
    for (int i = 0; i < n; i++) {
        X509 *c = sk_X509_value(ca, i);
        X509_up_ref(c);
        ret->extra_certs.ptr[i] = cert_handle(c);
    }
    if (ca) sk_X509_pop_free(ca, X509_free);
    return true;
}

// --- CMS sign/verify ------------------------------------------------------

bool exports_openssl_component_x509_cms_sign(
        openssl_list_u8_t *content,
        exports_openssl_component_x509_borrow_pkey_t signer,
        exports_openssl_component_x509_borrow_certificate_t cert,
        exports_openssl_component_x509_list_borrow_certificate_t *intermediates,
        bool detached, exports_openssl_component_x509_encoding_t enc,
        openssl_list_u8_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    STACK_OF(X509) *certs = sk_X509_new_null();
    for (size_t i = 0; i < intermediates->len; i++) {
        sk_X509_push(certs, (X509 *)intermediates->ptr[i]);
    }
    BIO *data = BIO_new_mem_buf(content->ptr, (int)content->len);
    unsigned int flags = CMS_BINARY;
    if (detached) flags |= CMS_DETACHED;

    CMS_ContentInfo *cms = CMS_sign(as_cert(cert), as_pkey(signer),
                                    certs, data, flags);
    sk_X509_free(certs);
    BIO_free(data);
    if (!cms) { err->tag = XE_SIGN; err->val.internal = ERR_peek_last_error(); return false; }

    BIO *out = BIO_new(BIO_s_mem());
    int ok = enc == 0 ? PEM_write_bio_CMS(out, cms)
                      : i2d_CMS_bio(out, cms);
    CMS_ContentInfo_free(cms);
    if (!ok) { BIO_free(out); err->tag = XE_ENCODING; return false; }

    const unsigned char *buf = NULL;
    long n = BIO_get_mem_data(out, &buf);
    ret->ptr = xmalloc(n > 0 ? n : 1);
    memcpy(ret->ptr, buf, n);
    ret->len = (size_t)n;
    BIO_free(out);
    return true;
}

bool exports_openssl_component_x509_cms_verify(
        openssl_list_u8_t *cms_bytes,
        exports_openssl_component_x509_borrow_store_t store,
        openssl_list_u8_t *maybe_detached,
        exports_openssl_component_x509_encoding_t enc,
        openssl_option_list_u8_t *ret,
        exports_openssl_component_x509_x509_error_t *err) {
    BIO *in = BIO_new_mem_buf(cms_bytes->ptr, (int)cms_bytes->len);
    CMS_ContentInfo *cms = enc == 0
        ? PEM_read_bio_CMS(in, NULL, NULL, NULL)
        : d2i_CMS_bio(in, NULL);
    BIO_free(in);
    if (!cms) { err->tag = XE_PARSE; err->val.internal = ERR_peek_last_error(); return false; }

    BIO *det = maybe_detached
        ? BIO_new_mem_buf(maybe_detached->ptr, (int)maybe_detached->len)
        : NULL;
    BIO *out = BIO_new(BIO_s_mem());
    int ok = CMS_verify(cms, NULL, as_store(store), det, out, CMS_BINARY);
    if (det) BIO_free(det);
    CMS_ContentInfo_free(cms);
    if (!ok) {
        BIO_free(out);
        err->tag = XE_VERIFY; err->val.internal = ERR_peek_last_error();
        return false;
    }

    const unsigned char *buf = NULL;
    long n = BIO_get_mem_data(out, &buf);
    if (maybe_detached) {
        ret->is_some = false;
    } else {
        ret->is_some = true;
        ret->val.ptr = xmalloc(n > 0 ? n : 1);
        memcpy(ret->val.ptr, buf, n);
        ret->val.len = (size_t)n;
    }
    BIO_free(out);
    return true;
}

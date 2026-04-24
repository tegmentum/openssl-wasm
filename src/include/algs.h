#ifndef OPENSSL_WASM_ALGS_H
#define OPENSSL_WASM_ALGS_H

#include "bindings/openssl.h"
#include <openssl/evp.h>

// Map WIT digest::algorithm → OpenSSL EVP_MD*. Returns NULL on unknown.
static inline const EVP_MD *wit_digest_md(
        exports_openssl_component_digest_algorithm_t a) {
    switch (a) {
    case 0:  return EVP_md5();
    case 1:  return EVP_sha1();
    case 2:  return EVP_sha224();
    case 3:  return EVP_sha256();
    case 4:  return EVP_sha384();
    case 5:  return EVP_sha512();
    case 6:  return EVP_sha512_224();
    case 7:  return EVP_sha512_256();
    case 8:  return EVP_sha3_224();
    case 9:  return EVP_sha3_256();
    case 10: return EVP_sha3_384();
    case 11: return EVP_sha3_512();
    case 12: return EVP_shake128();
    case 13: return EVP_shake256();
#ifndef OPENSSL_NO_BLAKE2
    case 14: return EVP_blake2s256();
    case 15: return EVP_blake2b512();
#endif
#ifndef OPENSSL_NO_RMD160
    case 16: return EVP_ripemd160();
#endif
#ifndef OPENSSL_NO_SM3
    case 17: return EVP_sm3();
#endif
    default: return NULL;
    }
}

// Short name for digest — usable as an OSSL_PARAM value.
static inline const char *wit_digest_name(
        exports_openssl_component_digest_algorithm_t a) {
    switch (a) {
    case 0:  return "MD5";
    case 1:  return "SHA1";
    case 2:  return "SHA2-224";
    case 3:  return "SHA2-256";
    case 4:  return "SHA2-384";
    case 5:  return "SHA2-512";
    case 6:  return "SHA2-512/224";
    case 7:  return "SHA2-512/256";
    case 8:  return "SHA3-224";
    case 9:  return "SHA3-256";
    case 10: return "SHA3-384";
    case 11: return "SHA3-512";
    case 12: return "SHAKE-128";
    case 13: return "SHAKE-256";
    case 14: return "BLAKE2S-256";
    case 15: return "BLAKE2B-512";
    case 16: return "RIPEMD-160";
    case 17: return "SM3";
    default: return NULL;
    }
}

#endif

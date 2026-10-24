/* An in-memory certificate authority (section 5, TLS): EC P-256 CA and leaf certificates issued as the Python
 * reference issues them (366 days from 5 minutes ago, CA path length 0, leaves with server and client EKU and the
 * common name as a DNS SAN), through OpenSSL's X509 API. */
#include "internal.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>

#define LIFETIME_SECONDS (366L * 24 * 3600)
#define BACKDATE_SECONDS (5L * 60)

struct ppc_authority {
    EVP_PKEY *key;
    X509 *cert;
    char *ca_pem;
};

static void openssl_error(char *err, size_t err_len, const char *what) {
    if (err && err_len) {
        char buf[256] = "";
        unsigned long code = ERR_get_error();
        if (code) ERR_error_string_n(code, buf, sizeof buf);
        snprintf(err, err_len, "%s: %s", what, buf[0] ? buf : "OpenSSL error");
    }
    ERR_clear_error();
}

static char *pem_of(int (*writer)(BIO *, void *), void *object) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) return NULL;
    char *out = NULL;
    if (writer(bio, object) == 1) {
        char *data = NULL;
        long n = BIO_get_mem_data(bio, &data);
        if (n > 0 && (out = malloc((size_t)n + 1)) != NULL) { memcpy(out, data, (size_t)n); out[n] = '\0'; }
    }
    BIO_free(bio);
    return out;
}

static int write_cert(BIO *bio, void *x) { return PEM_write_bio_X509(bio, x); }
static int write_key(BIO *bio, void *k) { return PEM_write_bio_PKCS8PrivateKey(bio, k, NULL, NULL, 0, NULL, NULL); }

static bool random_serial(X509 *cert) {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof bytes) != 1) return false;
    bytes[0] &= 0x7f;       /* positive, below 2^127 as the reference's random_serial_number */
    BIGNUM *bn = BN_bin2bn(bytes, sizeof bytes, NULL);
    if (bn == NULL) return false;
    ASN1_INTEGER *serial = BN_to_ASN1_INTEGER(bn, NULL);
    BN_free(bn);
    if (serial == NULL) return false;
    int ok = X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);
    return ok == 1;
}

static bool add_extension(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ext == NULL) return false;
    int ok = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return ok == 1;
}

static X509 *new_cert(EVP_PKEY *key, const char *common_name) {
    X509 *cert = X509_new();
    if (cert == NULL) return NULL;
    bool ok = X509_set_version(cert, 2) == 1 && random_serial(cert) && X509_set_pubkey(cert, key) == 1;
    X509_NAME *name = X509_get_subject_name(cert);
    ok = ok && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (const unsigned char *)common_name, -1, -1, 0) == 1;
    ok = ok && X509_gmtime_adj(X509_getm_notBefore(cert), -BACKDATE_SECONDS) != NULL
         && X509_gmtime_adj(X509_getm_notAfter(cert), LIFETIME_SECONDS) != NULL;
    if (!ok) { X509_free(cert); return NULL; }
    return cert;
}

ppc_authority *ppc_authority_new(const char *name, char *err, size_t err_len) {
    if (err && err_len) err[0] = '\0';
    ppc_authority *a = calloc(1, sizeof *a);
    if (a == NULL) return NULL;
    a->key = EVP_EC_gen("P-256");
    if (a->key == NULL) { openssl_error(err, err_len, "CA key"); ppc_authority_free(a); return NULL; }
    a->cert = new_cert(a->key, name ? name : "protocol-proxy manager");
    if (a->cert == NULL || X509_set_issuer_name(a->cert, X509_get_subject_name(a->cert)) != 1
        || !add_extension(a->cert, a->cert, NID_basic_constraints, "critical,CA:TRUE,pathlen:0")
        || !add_extension(a->cert, a->cert, NID_key_usage, "critical,digitalSignature,keyCertSign,cRLSign")
        || !add_extension(a->cert, a->cert, NID_subject_key_identifier, "hash")
        || X509_sign(a->cert, a->key, EVP_sha256()) == 0) {
        openssl_error(err, err_len, "CA certificate");
        ppc_authority_free(a);
        return NULL;
    }
    a->ca_pem = pem_of(write_cert, a->cert);
    if (a->ca_pem == NULL) { ppc_authority_free(a); return NULL; }
    return a;
}

void ppc_authority_free(ppc_authority *a) {
    if (a == NULL) return;
    EVP_PKEY_free(a->key);
    X509_free(a->cert);
    free(a->ca_pem);
    free(a);
}

const char *ppc_authority_ca_pem(const ppc_authority *a) { return a->ca_pem; }

static bool looks_like_ip(const char *s) {
    ASN1_OCTET_STRING *ip = a2i_IPADDRESS(s);
    if (ip == NULL) { ERR_clear_error(); return false; }
    ASN1_OCTET_STRING_free(ip);
    return true;
}

ppc_tls_material *ppc_authority_issue(const ppc_authority *a, const char *common_name,
                                      const char *const *ip_addresses, size_t n_addresses, char *err, size_t err_len) {
    if (a == NULL || common_name == NULL) return NULL;
    if (err && err_len) err[0] = '\0';
    EVP_PKEY *key = EVP_EC_gen("P-256");
    if (key == NULL) { openssl_error(err, err_len, "leaf key"); return NULL; }
    X509 *cert = new_cert(key, common_name);
    ppc_buf san = {0};
    ppc_buf_append(&san, "DNS:", 4);
    ppc_buf_append(&san, common_name, strlen(common_name));
    for (size_t i = 0; i < n_addresses; i++) {
        if (ip_addresses[i] == NULL || ip_addresses[i][0] == '\0') continue;
        const char *kind = looks_like_ip(ip_addresses[i]) ? ",IP:" : ",DNS:";
        ppc_buf_append(&san, kind, strlen(kind));
        ppc_buf_append(&san, ip_addresses[i], strlen(ip_addresses[i]));
    }
    ppc_buf_append(&san, "", 1);
    bool ok = cert != NULL && X509_set_issuer_name(cert, X509_get_subject_name(a->cert)) == 1
              && add_extension(cert, a->cert, NID_basic_constraints, "critical,CA:FALSE")
              && add_extension(cert, a->cert, NID_ext_key_usage, "serverAuth,clientAuth")
              && add_extension(cert, a->cert, NID_subject_alt_name, (const char *)san.data)
              && add_extension(cert, a->cert, NID_authority_key_identifier, "keyid")
              && X509_sign(cert, a->key, EVP_sha256()) != 0;
    ppc_buf_free(&san);
    ppc_tls_material *m = NULL;
    if (ok) {
        m = calloc(1, sizeof *m);
        if (m) {
            m->ca = ppc_strdup(a->ca_pem);
            m->cert = pem_of(write_cert, cert);
            m->key = pem_of(write_key, key);
            if (m->ca == NULL || m->cert == NULL || m->key == NULL) { ppc_tls_material_free(m); m = NULL; }
        }
    } else {
        openssl_error(err, err_len, "leaf certificate");
    }
    X509_free(cert);
    EVP_PKEY_free(key);
    return m;
}

char *ppc_tls_material_line(const ppc_tls_material *m) {
    if (m == NULL) return NULL;
    ppc_json *o = ppc_json_new_object();
    if (o == NULL) return NULL;
    ppc_json_object_set(o, "ca", ppc_json_new_string(m->ca));
    ppc_json_object_set(o, "cert", ppc_json_new_string(m->cert));
    ppc_json_object_set(o, "key", ppc_json_new_string(m->key));
    char *text = ppc_json_dump(o);
    ppc_json_free(o);
    if (text == NULL) return NULL;
    size_t n = strlen(text);
    char *line = realloc(text, n + 2);
    if (line == NULL) { free(text); return NULL; }
    line[n] = '\n';
    line[n + 1] = '\0';
    return line;
}

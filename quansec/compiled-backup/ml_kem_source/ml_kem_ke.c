#include "ml_kem_ke.h"
#include <oqs/oqs.h>
#include <utils/debug.h>

#define ML_KEM_768  1050
#define ML_KEM_1024 1051

typedef struct private_ml_kem_ke_t private_ml_kem_ke_t;

struct private_ml_kem_ke_t {
    key_exchange_t public;
    key_exchange_method_t method;
    OQS_KEM *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
    bool initiator;
};

static bool get_public_key(private_ml_kem_ke_t *this, chunk_t *value) {
    if (!this->public_key) {
        this->public_key = malloc(this->kem->length_public_key);
        this->secret_key = malloc(this->kem->length_secret_key);
        if (OQS_KEM_keypair(this->kem, this->public_key, this->secret_key) != OQS_SUCCESS) {
            return FALSE;
        }
        this->initiator = TRUE;
    }
    *value = chunk_clone(chunk_create(this->public_key, this->kem->length_public_key));
    return TRUE;
}

static bool set_public_key(private_ml_kem_ke_t *this, chunk_t value) {
    if (this->initiator) {
        if (value.len != this->kem->length_ciphertext) return FALSE;
        this->shared_secret = malloc(this->kem->length_shared_secret);
        return OQS_KEM_decaps(this->kem, this->shared_secret,
                              value.ptr, this->secret_key) == OQS_SUCCESS;
    } else {
        if (value.len != this->kem->length_public_key) return FALSE;
        this->ciphertext    = malloc(this->kem->length_ciphertext);
        this->shared_secret = malloc(this->kem->length_shared_secret);
        this->public_key    = malloc(this->kem->length_ciphertext);
        if (OQS_KEM_encaps(this->kem, this->ciphertext,
                           this->shared_secret, value.ptr) != OQS_SUCCESS) {
            return FALSE;
        }
        memcpy(this->public_key, this->ciphertext, this->kem->length_ciphertext);
        return TRUE;
    }
}

static bool get_shared_secret(private_ml_kem_ke_t *this, chunk_t *secret) {
    if (!this->shared_secret) return FALSE;
    *secret = chunk_clone(chunk_create(this->shared_secret,
                                       this->kem->length_shared_secret));
    return TRUE;
}

static key_exchange_method_t get_method(private_ml_kem_ke_t *this) {
    return this->method;
}

static void destroy(private_ml_kem_ke_t *this) {
    OQS_KEM_free(this->kem);
    free(this->public_key);
    free(this->secret_key);
    free(this->ciphertext);
    free(this->shared_secret);
    free(this);
}

key_exchange_t *ml_kem_ke_create(key_exchange_method_t method) {
    private_ml_kem_ke_t *this;
    const char *alg;
    switch (method) {
        case ML_KEM_768:  alg = "ML-KEM-768";  break;
        case ML_KEM_1024: alg = "ML-KEM-1024"; break;
        default: return NULL;
    }
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        DBG1(DBG_LIB, "ml-kem: OQS_KEM_new(%s) failed", alg);
        return NULL;
    }
    INIT(this,
        .public = {
            .get_method        = (void*)get_method,
            .get_public_key    = (void*)get_public_key,
            .set_public_key    = (void*)set_public_key,
            .get_shared_secret = (void*)get_shared_secret,
            .destroy           = (void*)destroy,
        },
        .method = method,
        .kem    = kem,
    );
    return &this->public;
}

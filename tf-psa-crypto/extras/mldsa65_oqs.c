/*
 *  ML-DSA-65 (pure) signature verification using liboqs.
 *
 *  SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

/* Requires the ML-DSA-65 integration to be enabled — this TU depends on
 * liboqs headers, which are absent when CONFIG_LIBOQS_ENABLED=n (e.g. the
 * classical-TLS baseline build). */
#if defined(MBEDTLS_SSL_TLS1_3_SIG_MLDSA65) && \
    (defined(MBEDTLS_X509_USE_C) || defined(MBEDTLS_SSL_PROTO_TLS1_3))

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/pk.h"
#include "pk_internal.h"

#include "mbedtls/mldsa65_oqs.h"

#include "mbedtls/private/error_common.h"
#include "mbedtls/platform.h"

#include <string.h>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtypedef-redefinition"
#endif
#include <oqs/sig.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include "psa/crypto.h"

int mbedtls_pk_mldsa65_oqs_verify(mbedtls_pk_context *pk,
                                  const unsigned char *msg, size_t msg_len,
                                  const unsigned char *sig, size_t sig_len)
{
    OQS_SIG *mldsa;
    OQS_STATUS status;

    if (pk == NULL || (msg == NULL && msg_len != 0) || sig == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (pk->pub_raw_len != MBEDTLS_MLDSA65_PUBLIC_KEY_LEN) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (sig_len != MBEDTLS_MLDSA65_SIGNATURE_LEN) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }


    mldsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (mldsa == NULL) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    status = OQS_SIG_verify(mldsa, msg, msg_len, sig, sig_len, pk->pub_raw);
    OQS_SIG_free(mldsa);

    if (status != OQS_SUCCESS) {
        mbedtls_printf("mldsa65_oqs: OQS_SIG_verify failed\n");
    }

    return (status == OQS_SUCCESS) ? 0 : MBEDTLS_ERR_PK_INVALID_ALG;
}

#else /* MBEDTLS_SSL_TLS1_3_SIG_MLDSA65 && (MBEDTLS_X509_USE_C || MBEDTLS_SSL_PROTO_TLS1_3) */

#include "mbedtls/pk.h"
#include "mbedtls/private/error_common.h"
#include "mbedtls/mldsa65_oqs.h"

int mbedtls_pk_mldsa65_oqs_verify(mbedtls_pk_context *pk,
                                  const unsigned char *msg, size_t msg_len,
                                  const unsigned char *sig, size_t sig_len)
{
    (void) pk;
    (void) msg;
    (void) msg_len;
    (void) sig;
    (void) sig_len;
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}

#endif /* MBEDTLS_SSL_TLS1_3_SIG_MLDSA65 && (MBEDTLS_X509_USE_C || MBEDTLS_SSL_PROTO_TLS1_3) */

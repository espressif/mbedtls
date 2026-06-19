/*
 *  SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_MLDSA65_OQS_H
#define MBEDTLS_MLDSA65_OQS_H

#include "tf-psa-crypto/build_info.h"

#include "mbedtls/pk.h"

#include <stddef.h>

/** ML-DSA-65 raw public key size in bytes (FIPS 204, RFC 9881). */
#define MBEDTLS_MLDSA65_PUBLIC_KEY_LEN  1952

/** ML-DSA-65 signature size in bytes (FIPS 204, RFC 9881). */
#define MBEDTLS_MLDSA65_SIGNATURE_LEN   3309

/**
 * \brief Verify a pure ML-DSA-65 signature (liboqs).
 *
 * \param msg        Message that was signed (e.g. TLS 1.3 verify structure, or
 *                   digest for X.509 depending on the caller).
 * \param msg_len    Length of \p msg.
 */
int mbedtls_pk_mldsa65_oqs_verify(mbedtls_pk_context *pk,
                                  const unsigned char *msg, size_t msg_len,
                                  const unsigned char *sig, size_t sig_len);

#endif /* MBEDTLS_MLDSA65_OQS_H */

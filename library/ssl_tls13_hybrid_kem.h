/*
 *  TLS 1.3 hybrid post-quantum key exchange: X25519MLKEM768 sizes and helpers.
 *
 *  SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SSL_TLS13_HYBRID_KEM_H
#define MBEDTLS_SSL_TLS13_HYBRID_KEM_H
#include "mbedtls/ssl.h"
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768)

/* Key and secret sizes for the X25519MLKEM768 hybrid group
 * (draft-ietf-tls-ecdhe-mlkem-04, IANA codepoint 0x11EC). */
#define MBEDTLS_X25519_KEY_BITS                 255
#define MBEDTLS_X25519_PUBLIC_KEY_LEN            32
#define MBEDTLS_X25519_SHARED_SECRET_LEN         32
#define MBEDTLS_MLKEM768_PUBLIC_KEY_LEN        1184   /* ek */
#define MBEDTLS_MLKEM768_SECRET_KEY_LEN        2400   /* dk */
#define MBEDTLS_MLKEM768_CIPHERTEXT_LEN        1088
#define MBEDTLS_MLKEM768_SHARED_SECRET_LEN       32

/* Client key share: ML-KEM-768 ek || X25519 public key (1216 bytes). */
#define MBEDTLS_X25519MLKEM768_CLIENT_SHARE_LEN \
    (MBEDTLS_MLKEM768_PUBLIC_KEY_LEN + MBEDTLS_X25519_PUBLIC_KEY_LEN)

/* Server key share: ML-KEM-768 ciphertext || X25519 public key (1120 bytes). */
#define MBEDTLS_X25519MLKEM768_SERVER_SHARE_LEN \
    (MBEDTLS_MLKEM768_CIPHERTEXT_LEN + MBEDTLS_X25519_PUBLIC_KEY_LEN)

/* IKM for the TLS 1.3 key schedule: ML-KEM ss || X25519 ss (64 bytes). */
#define MBEDTLS_X25519MLKEM768_SHARED_SECRET_LEN \
    (MBEDTLS_MLKEM768_SHARED_SECRET_LEN + MBEDTLS_X25519_SHARED_SECRET_LEN)

/* RFC 8446 KeyShareEntry: uint16 length prefix ahead of opaque key_exchange. */
#define MBEDTLS_SSL_KEY_SHARE_ENTRY_LEN_SIZE      2

int mbedtls_ssl_tls13_hybrid_x25519mlkem768_write_client_share(
    mbedtls_ssl_context *ssl, unsigned char *buf, unsigned char *end,
    size_t *out_len);
int mbedtls_ssl_tls13_hybrid_x25519mlkem768_read_server_share(
    mbedtls_ssl_context *ssl, const unsigned char *buf, size_t buf_len);
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768 */
#endif /* MBEDTLS_SSL_TLS13_HYBRID_KEM_H */

/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * TLS 1.3 hybrid post-quantum key exchange: X25519 + ML-KEM-768
 *
 * Wire format (client key share, 1216 bytes total):
 *   ML-KEM-768 ek      : 1184 bytes
 *   X25519 public key  : 32 bytes
 *
 * Wire format (server key share, 1120 bytes total):
 *   ML-KEM-768 ciphertext : 1088 bytes
 *   X25519 public key  : 32 bytes
 *
 * Combined shared secret (64 bytes) fed into TLS key schedule:
 *   ML-KEM shared secret (32) || X25519 shared secret (32)
 *
 * Reference: draft-ietf-tls-ecdhe-mlkem-04
 * IANA codepoint: 0x11EC
 */

#include "ssl_misc.h"

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768)

#include <string.h>
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/psa_util.h"
#include "debug_internal.h"
#include "psa/crypto.h"
#include "ssl_tls13_hybrid_kem.h"

/* Suppress typedef-redefinition warnings from liboqs headers (Clang only). */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtypedef-redefinition"
#endif
#include <oqs/oqsconfig.h>
#include <oqs/kem_ml_kem.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

/* Local PSA→mbedtls error translation, same pattern as ssl_tls13_generic.c */
static int local_err_translation(psa_status_t status)
{
    return psa_status_to_mbedtls(status, psa_to_ssl_errors,
                                 ARRAY_LENGTH(psa_to_ssl_errors),
                                 psa_generic_status_to_mbedtls);
}
#define PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)

/*
 * Client side: generate X25519 + ML-KEM-768 keypair, write key share.
 *
 * Writes MLKEM768_ek (1184) || X25519_pub (32) = 1216 bytes into buf
 * (caller wraps this in KeyShareEntry with length prefix).
 * Stores X25519 private key handle in handshake->xxdh_psa_privkey (PSA).
 * Stores ML-KEM-768 secret key in handshake->mlkem_sk until decapsulation.
 */
int mbedtls_ssl_tls13_hybrid_x25519mlkem768_write_client_share(
    mbedtls_ssl_context *ssl,
    unsigned char *buf,
    unsigned char *end,
    size_t *out_len)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t x25519_pub_len = 0;
    OQS_STATUS oqs_ret;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    *out_len = 0;

    MBEDTLS_SSL_CHK_BUF_PTR(buf, end, MBEDTLS_X25519MLKEM768_CLIENT_SHARE_LEN);

    /* --- Part 1: ML-KEM-768 keypair via liboqs --- */
    /* Wire format: MLKEM ek (1184) || X25519 pub (32) per draft-ietf-tls-ecdhe-mlkem-04 */
    /* ek (public key) goes into first 1184 bytes of buf                  */
    /* dk (secret key) is stored in handshake struct for later decaps     */
    oqs_ret = OQS_KEM_ml_kem_768_keypair(
        buf,
        handshake->mlkem_sk);

    if (oqs_ret != OQS_SUCCESS) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("OQS_KEM_ml_kem_768_keypair failed"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    MBEDTLS_SSL_DEBUG_BUF(4, "ML-KEM-768 ek", buf, MBEDTLS_MLKEM768_PUBLIC_KEY_LEN);

    /* --- Part 2: X25519 keypair via PSA --- */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
    psa_set_key_type(&key_attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&key_attributes, MBEDTLS_X25519_KEY_BITS);

    status = psa_generate_key(&key_attributes, &handshake->xxdh_psa_privkey);
    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        MBEDTLS_SSL_DEBUG_RET(1, "psa_generate_key (X25519)", ret);
        return ret;
    }

    /* Export X25519 public key into last 32 bytes of buf (after ML-KEM ek) */
    status = psa_export_public_key(handshake->xxdh_psa_privkey,
                                   buf + MBEDTLS_MLKEM768_PUBLIC_KEY_LEN,
                                   MBEDTLS_X25519_PUBLIC_KEY_LEN,
                                   &x25519_pub_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        MBEDTLS_SSL_DEBUG_RET(1, "psa_export_public_key (X25519)", ret);
        return ret;
    }

    if (x25519_pub_len != MBEDTLS_X25519_PUBLIC_KEY_LEN) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    MBEDTLS_SSL_DEBUG_BUF(4, "X25519 public key",
                          buf + MBEDTLS_MLKEM768_PUBLIC_KEY_LEN,
                          MBEDTLS_X25519_PUBLIC_KEY_LEN);

    *out_len = MBEDTLS_X25519MLKEM768_CLIENT_SHARE_LEN;
    return 0;
}

/*
 * Client side: process server key share, produce combined shared secret.
 *
 * Server KeyShareEntry: opaque key_exchange<1..2^16-1> =
 *   uint16 length (1120) || MLKEM768_ct (1088) || X25519_pub (32)
 *   (buf points at the start of key_exchange, i.e. length || payload).
 *
 * Produces combined_secret = MLKEM_ss (32) || X25519_ss (32) = 64 bytes
 * stored in handshake->xxdh_psa_peerkey for the TLS 1.3 key schedule.
 * Order per draft-ietf-tls-ecdhe-mlkem-04 Section 4.3.
 *
 * The X25519 private key (xxdh_psa_privkey) is destroyed here after use.
 * The ML-KEM secret key (mlkem_sk) is wiped here after decapsulation.
 * ssl_tls13_keys.c detects xxdh_psa_privkey == INIT and uses peerkey
 * directly as the pre-computed shared secret input to HKDF.
 */
int mbedtls_ssl_tls13_hybrid_x25519mlkem768_read_server_share(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf,
    size_t buf_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status;
    OQS_STATUS oqs_ret;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    uint8_t x25519_ss[MBEDTLS_X25519_SHARED_SECRET_LEN];
    uint8_t mlkem_ss[MBEDTLS_MLKEM768_SHARED_SECRET_LEN];
    size_t x25519_ss_len = 0;

    uint16_t ke_payload_len;
    const unsigned char *payload;

    /* RFC 8446 KeyShareEntry: NamedGroup || opaque key_exchange<1..2^16-1> */
    if (buf_len < MBEDTLS_SSL_KEY_SHARE_ENTRY_LEN_SIZE + MBEDTLS_X25519MLKEM768_SERVER_SHARE_LEN) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("server key share too short: %u < %u",
                                  (unsigned) buf_len,
                                  (unsigned) (MBEDTLS_SSL_KEY_SHARE_ENTRY_LEN_SIZE + MBEDTLS_X25519MLKEM768_SERVER_SHARE_LEN)));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                     MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

    ke_payload_len = MBEDTLS_GET_UINT16_BE(buf, 0);
    if (ke_payload_len != MBEDTLS_X25519MLKEM768_SERVER_SHARE_LEN) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad hybrid server key_exchange length: %u != %u",
                                  (unsigned) ke_payload_len,
                                  (unsigned) MBEDTLS_X25519MLKEM768_SERVER_SHARE_LEN));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                     MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    payload = buf + MBEDTLS_SSL_KEY_SHARE_ENTRY_LEN_SIZE;
    /*
     * draft-ietf-tls-ecdhe-mlkem-04 §4.2: server share is
     * ML-KEM ciphertext (1088) || X25519 server public key (32).
     */
    MBEDTLS_SSL_DEBUG_BUF(4, "Server KeyShareEntry payload (MLKEM768_ct || X25519_pub)",
                          payload, MBEDTLS_X25519MLKEM768_SERVER_SHARE_LEN);

    const unsigned char *mlkem_ct = payload;
    const unsigned char *x25519_peer_pub = payload + MBEDTLS_MLKEM768_CIPHERTEXT_LEN;

    MBEDTLS_SSL_DEBUG_BUF(4, "Server X25519 public key (from payload)",
                          x25519_peer_pub, MBEDTLS_X25519_PUBLIC_KEY_LEN);

    /* --- Part 1: ML-KEM-768 decapsulation --- */
    oqs_ret = OQS_KEM_ml_kem_768_decaps(
        mlkem_ss,
        mlkem_ct,
        handshake->mlkem_sk);

    /* Wipe the ML-KEM secret key from the handshake struct immediately */
    mbedtls_platform_zeroize(handshake->mlkem_sk, sizeof(handshake->mlkem_sk));

    if (oqs_ret != OQS_SUCCESS) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("OQS_KEM_ml_kem_768_decaps failed"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    MBEDTLS_SSL_DEBUG_BUF(4, "ML-KEM-768 shared secret",
                          mlkem_ss, MBEDTLS_MLKEM768_SHARED_SECRET_LEN);

    /* --- Part 2: X25519 key agreement --- */
    status = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        handshake->xxdh_psa_privkey,    /* our X25519 private key (PSA handle) */
        x25519_peer_pub,                /* server's X25519 public key (32 bytes) */
        MBEDTLS_X25519_PUBLIC_KEY_LEN,
        x25519_ss,
        sizeof(x25519_ss),
        &x25519_ss_len);

    /* Destroy the ephemeral X25519 private key immediately after use */
    psa_destroy_key(handshake->xxdh_psa_privkey);
    handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;

    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        MBEDTLS_SSL_DEBUG_RET(1, "psa_raw_key_agreement (X25519)", ret);
        return ret;
    }

    MBEDTLS_SSL_DEBUG_BUF(4, "X25519 shared secret", x25519_ss, x25519_ss_len);

    /* --- Part 3: concatenate for TLS 1.3 key schedule (IKM to HKDF-Extract) --- */
    if (sizeof(handshake->xxdh_psa_peerkey) < MBEDTLS_X25519MLKEM768_SHARED_SECRET_LEN) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* IKM for HKDF: ML-KEM SS || X25519 SS (draft-ietf-tls-ecdhe-mlkem-04 §4.3) */
    memcpy(handshake->xxdh_psa_peerkey,
           mlkem_ss, MBEDTLS_MLKEM768_SHARED_SECRET_LEN);
    memcpy(handshake->xxdh_psa_peerkey + MBEDTLS_MLKEM768_SHARED_SECRET_LEN,
           x25519_ss, MBEDTLS_X25519_SHARED_SECRET_LEN);
    handshake->xxdh_psa_peerkey_len = MBEDTLS_X25519MLKEM768_SHARED_SECRET_LEN;

    /* Wipe local copies of both secrets */
    mbedtls_platform_zeroize(x25519_ss, sizeof(x25519_ss));
    mbedtls_platform_zeroize(mlkem_ss, sizeof(mlkem_ss));

    MBEDTLS_SSL_DEBUG_BUF(4, "Combined shared secret (MLKEM||X25519)",
                          handshake->xxdh_psa_peerkey,
                          handshake->xxdh_psa_peerkey_len);

    return 0;
}

#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768 */

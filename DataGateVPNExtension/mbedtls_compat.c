/*
 * Compatibility layer for mbedTLS 4.0 functions that were removed or renamed
 * This file provides stub implementations for functions used by OpenVPN3
 * that are no longer available in mbedTLS 4.0
 */

#include "mbedtls_compat.h"
#include <mbedtls/version.h>
#include <mbedtls/ssl.h>
#include <mbedtls/platform.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha1.h>
#include <mbedtls/error.h>
#include <mbedtls/ecp.h>
#include <mbedtls/asn1.h>
#include <mbedtls/entropy.h>
#include <mbedtls/dhm.h>
#include <stdlib.h>
#include <string.h>

// iOS Security framework for SecRandomCopyBytes
#if defined(__APPLE__) && defined(__MACH__)
#include <Security/Security.h>
#endif

/* mbedtls_sha1_ret - wrapper using standard functions (mbedTLS 3.x) */
int mbedtls_sha1_ret(const unsigned char *input, size_t ilen, unsigned char output[20])
{
    mbedtls_sha1_context ctx;
    int ret;
    
    mbedtls_sha1_init(&ctx);
    ret = mbedtls_sha1_starts(&ctx);
    if (ret == 0) ret = mbedtls_sha1_update(&ctx, input, ilen);
    if (ret == 0) ret = mbedtls_sha1_finish(&ctx, output);
    mbedtls_sha1_free(&ctx);
    return ret;
}

/* These functions are aliases for mbedTLS 3.x compatibility */
int mbedtls_sha1_starts_ret(mbedtls_sha1_context *ctx)
{
    return mbedtls_sha1_starts(ctx);
}

int mbedtls_sha1_update_ret(mbedtls_sha1_context *ctx, const unsigned char *input, size_t ilen)
{
    return mbedtls_sha1_update(ctx, input, ilen);
}

int mbedtls_sha1_finish_ret(mbedtls_sha1_context *ctx, unsigned char output[20])
{
    return mbedtls_sha1_finish(ctx, output);
}

/* mbedtls_ssl_conf_rng - compatibility wrapper for mbedTLS 3.x */
/* Note: This function exists in mbedTLS 3.x, so this is only needed for 2.x compatibility */
#if MBEDTLS_VERSION_NUMBER < 0x03000000
void mbedtls_ssl_conf_rng(mbedtls_ssl_config *conf,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng)
{
    /* mbedTLS 2.x - direct access to structure fields */
    if (conf && f_rng) {
        conf->p_rng = p_rng;
        conf->f_rng = f_rng;
    }
}
#endif

/* NOTE: The following functions are already defined in mbedTLS libraries:
 * - mbedtls_ssl_conf_curves (in libmbedtls.a)
 * - mbedtls_ssl_conf_dh_param_ctx (in libmbedtls.a)
 * - mbedtls_ssl_conf_min_version (in libmbedtls.a)
 * They are removed from this file to avoid duplicate symbol errors.
 */

/* mbedtls_ssl_conf_cbc_record_splitting - removed in mbedTLS 4.0 */
void mbedtls_ssl_conf_cbc_record_splitting(mbedtls_ssl_config *conf, char split)
{
    /* This feature was removed - do nothing */
    (void)conf;
    (void)split;
}

/* mbedtls_platform_entropy_poll - removed in mbedTLS 4.0 */
/* Re-implemented using iOS SecRandomCopyBytes for Network Extension */
/* IMPORTANT: This function must be visible from C++ code (OpenVPN3) */
int mbedtls_platform_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    (void)data; // Not used
    
#if defined(__APPLE__) && defined(__MACH__)
    // Use iOS Security framework's SecRandomCopyBytes for entropy
    // This is the recommended way to get cryptographic random data on iOS
    // and works in Network Extensions (sandboxed environment)
    
    // Log for debugging (only in debug builds to avoid performance impact)
    #ifdef DEBUG
    printf("[mbedtls_compat] mbedtls_platform_entropy_poll called: len=%zu\n", len);
    #endif
    
    if (output == NULL || len == 0) {
        #ifdef DEBUG
        printf("[mbedtls_compat] ERROR: Invalid parameters\n");
        #endif
        if (olen) *olen = 0;
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    
    // SecRandomCopyBytes returns errSecSuccess (0) on success
    int result = SecRandomCopyBytes(kSecRandomDefault, len, output);
    
    if (result == errSecSuccess) {
        if (olen) *olen = len;
        #ifdef DEBUG
        printf("[mbedtls_compat] Success: Generated %zu bytes of entropy\n", len);
        #endif
        return 0; // Success
    } else {
        // Failed to get random bytes
        #ifdef DEBUG
        printf("[mbedtls_compat] ERROR: SecRandomCopyBytes failed with code %d\n", result);
        #endif
        if (olen) *olen = 0;
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
#else
    // For non-Apple platforms, return error (should not happen on iOS)
    #ifdef DEBUG
    printf("[mbedtls_compat] ERROR: Not on Apple platform\n");
    #endif
    (void)output;
    (void)len;
    if (olen) *olen = 0;
    return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
#endif
}

/* NOTE: The following functions are already defined in mbedTLS libraries:
 * - mbedtls_oid_get_extended_key_usage (in libmbedx509.a or libmbedtls.a)
 * - mbedtls_pk_setup_rsa_alt (in libmbedx509.a or libmbedtls.a)
 * They are removed from this file to avoid duplicate symbol errors.
 */

/* NOTE: The following functions are already defined in mbedTLS libraries:
 * - mbedtls_dhm_init (in libmbedcrypto.a)
 * - mbedtls_dhm_free (in libmbedcrypto.a)
 * - mbedtls_dhm_parse_dhm (in libmbedcrypto.a)
 * They are removed from this file to avoid duplicate symbol errors.
 */

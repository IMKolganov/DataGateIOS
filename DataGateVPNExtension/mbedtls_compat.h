/*
 * Compatibility layer header for mbedTLS 4.0 functions
 * This header provides declarations for functions that were removed in mbedTLS 4.0
 * but are still needed by OpenVPN3
 */

#ifndef MBEDTLS_COMPAT_H
#define MBEDTLS_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// mbedTLS error codes
#define MBEDTLS_ERR_ENTROPY_SOURCE_FAILED        -0x003C

/**
 * Platform entropy poll function - removed in mbedTLS 4.0
 * Re-implemented using iOS SecRandomCopyBytes for Network Extension
 * 
 * IMPORTANT: This function MUST be visible from C++ code (OpenVPN3)
 * Make sure it's properly exported and linked
 * 
 * @param data      Not used (can be NULL)
 * @param output    Buffer to fill with random data
 * @param len       Number of bytes to generate
 * @param olen      Output: number of bytes actually generated
 * @return          0 on success, MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on failure
 */
int mbedtls_platform_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_COMPAT_H */

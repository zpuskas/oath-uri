/*
 * oathrui.h - header file for liboathuri
 * Copyright (C) 2017 Zoltan Puskas <zoltan@sinustrom.info>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef OATHURI_H
#define OATHURI_H

#include <stdint.h>

# ifdef __cplusplus
extern "C"
{
# endif

/**
 * OATHURI_MAX_LEN
 *
 * Preprocessor symbol with an integer value. Defines the maximum allowed
 * lenght for the resulting URI, including the terminating zero. The value
 * is the maximum number of bytes in an binary/byte QR code + 1.
 */
#define OATHURI_MAX_LEN 2954

/**
 * oathuri_rc:
 * @OATHURI_OK: Successful return
 * @OATHURI_NULL_PARAMETER: Empty parameter was passed to a function
 * @OATHURI_INVALID_DIGITS: Unsupported number of OTP digits
 */
typedef enum
{
    OATHURI_OK = 0,
    OATHURI_NULL_PARAMETER = -1,
    OATHURI_INVALID_DIGITS = -2,
    OATHURI_CURL_FAILURE = -3,
    OATHURI_URI_TOO_LONG = -4,
} oathuri_rc;

/**
 * oathuri_hash:
 * @OATHURI_SHA1: Use the SHA1 algorithm for OTP generation (default).
 * @OATHURI_SHA256: Use the SHA256 algorithm for OTP generation.
 * @OATHURI_SHA512: Use the SHA512 algorithm for OTP generation.
 */
typedef enum
{
    OATHURI_SHA1 = 0,
    OATHURI_SHA256 = 1,
    OATHURI_SHA512 = 2,
} oathuri_hash;

extern int
oathuri_totp_generate(const char* secret,
            const char* account_name,
            const char* issuer,
            unsigned digits,
            unsigned period,
            oathuri_hash algorithm,
            char* key_uri);

extern int
oathuri_hotp_generate(const char* secret,
            const char* account_name,
            const char* issuer,
            unsigned digits,
            uint64_t counter,
            oathuri_hash algorithm,
            char* key_uri);

# ifdef __cplusplus
}
# endif

#endif /* OATHURI_H */

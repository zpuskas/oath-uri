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
} oathuri_rc;

extern int
oathuri_totp_generate(const char* secret,
            const char* account_name,
            const char* issuer,
            unsigned digits,
            unsigned period,
            char* key_uri);

extern int
oathuri_hotp_generate(const char* secret,
            const char* account_name,
            const char* issuer,
            unsigned digits,
            uint64_t counter,
            char* key_uri);

# ifdef __cplusplus
}
# endif

#endif /* OATHURI_H */

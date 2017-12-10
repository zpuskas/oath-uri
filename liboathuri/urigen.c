/*
 * urigen.c - implementation of OATH Key URI format composition
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

#include "oathuri.h"

/**
 * oathuri_totp_generate:
 * @secret: the shared secret string, NULL terminated
 * @account_name: name of the account string, NULL terminated
 * @digits: number of requested digits in the OTP
 * @period: time step system parameter (typically 30)
 * @key_uri: output buffer, must have room for the entire URI plus zero, but
 *           maximum 4000 characters so it can fit into a QR code
 *
 * Generate a otpauth:// URI to be used with soft OTP authenticator
 * initialization (typically smart phone applications via QR code). Key URI
 * strucutre corresponds to the most widely format used by Goole Authenticator,
 * as documented on their github page:
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *
 * The system parameter @digits tells how many digits the OTP will consits of.
 * Currently accepted values are 6, 7, and 8.
 *
 * The system parameter @period corresponds to the time period setting in
 * oath-toolkit and describes the time window in seconds for each OTP.
 * Recommended value is 30, and 0 can be used to indicate this as default too.
 *
 * Returns: On success, %OATHURI_OK (zero) is returned, otherwise an error
 *          code is returned
 *
 * Since: 1.0.0
 */
int
oathuri_totp_generate(const char* secret,
            const char* account_name,
            const char* issuer,
            unsigned digits,
            unsigned period,
            char* key_uri)
{
    return 0;
}

/**
 * oathuri_hotp_generate:
 * @secret: the shared secret string, NULL terminated
 * @account_name: name of the account string, NULL terminated
 * @digits: number of requested digits in the OTP
 * @counter: counter to indicate the next OTP to generate
 * @key_uri: output buffer, must have room for the entire URI plus zero, but
 *           maximum 4000 characters so it can fit into a QR code
 *
 * Generate a otpauth:// URI to be used with soft OTP authenticator
 * initialization (typically smart phone applications via QR code). Key URI
 * strucutre corresponds to the most widely format used by Goole Authenticator,
 * as documented on their github page:
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *
 * The system parameter @digits tells how many digits the OTP will consits of.
 * Currently accepted values are 6, 7, and 8.
 *
 * Returns: On success, %OATHURI_OK (zero) is returned, otherwise an error
 *          code is returned
 *
 * Since: 1.0.0
 */
int
oathuri_hotp_generate(const char* secret,
            const char* account_name,
            const char* issuer,
            unsigned digits,
            uint64_t counter,
            char* key_uri)
{
    return 0;
}

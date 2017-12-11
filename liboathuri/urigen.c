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

/*
 * # OATH Key URI format
 *
 * As per: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *
 * otpauth://TYPE/LABEL?PARAMETERS
 *
 * Example:
 * otpauth://totp/webprovider:alice@provider.com?secret=JBSWY3DPEHPK3PXP&issuer=webprovider
 *
 * # Fields
 *
 * ## TYPE
 *
 * Used to distinguish key types. Valid values are `hotp` for counter based
 * HOTP and `totp` for time based TOTP.
 *
 * ## LABEL
 *
 * The label is used to identify which account a key is associated with. It
 * contains an account name, which is a URI-encoded string, optionally
 * prefixed by an issuer string identifying the provider or service managing
 * that account.
 *
 * This issuer prefix can be used to prevent collisions between different
 * accounts with different providers that might be identified using the same
 * account name, e.g. the user's email address.
 *
 * label = accountname / issuer (“:” / “%3A”) *”%20” accountname
 *
 * ## PARAMETERS
 *
 * Ampersand separated key=value pairs describing the secret key.
 *
 * ### Secret
 *
 * REQUIRED: secret=<secret string>
 *
 * Secret string to be used for key generation, typically base32 encoded.
 *
 * ### Issuer
 *
 * RECOMMENDED: issuer=<issuer/provider string>
 *
 * Identifies the issuer or service provider the secret belongs to.
 *
 * ### Algorithm
 *
 * OPTIONAL: algorithm=<SHA1|SHA256|SHA512>
 *
 * Defines the hash algorithm to use to generate OTP keys. Default is SHA1.
 *
 * ### Digits
 *
 * OPTIONAL: digits=<6|7|8>
 *
 * Determines the length of the OTP to be generated. Default is 6.
 *
 * ### Counter
 *
 * REQUIRED if `type` is `hotp`: counter=<uint64_t>
 *
 * Counter used for the HOTP key generation, indicates the next OTP.
 *
 * ### Period
 *
 * OPTIONAL if `type` is `totp`: period=<int>
 *
 * Tells how long an OTP is valid in seconds. Default is 30.
 *
 */

/* URI protocol prefix */
static const char OATHURI_PROTOCOL[] = "otpauth://";

/* Type definitions for different OPT key types */
static const char OATHURI_TYPE_TOTP[] = "totp";
static const char OATHURI_TYPE_HOTP[] = "hotp";

/**
 * oathuri_totp_generate:
 * @secret: the shared secret string, NULL terminated
 * @account_name: name of the account string, NULL terminated
 * @digits: number of requested digits in the OTP
 * @period: time step system parameter (typically 30)
 * @algorithm: Type of algorithm used to produce OTP keys.
 * @key_uri: output buffer, must have room for the entire URI plus zero, but
 *           maximum 4000 characters so it can fit into a QR code
 *
 * Generate a TOTP type otpauth:// URI to be used with soft OTP authenticator
 * initialization (typically smart phone applications via QR code). Key URI's
 * structure corresponds to the most widely format introduced by
 * google-authenticator.
 *
 * The system parameter @digits tells how many digits the OTP will consists of.
 * Currently accepted values are 6, 7, and 8
 *
 * The system parameter @period corresponds to the time period setting in
 * oath-toolkit and describes the time window in seconds for each OTP.
 * Recommended value is 30, and 0 can be used to indicate this as default too.
 *
 * The system parameter @algorithm determined the way OTP keys are generated.
 * Accepted values are SHA1, SHA256, and SHA512.
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
            oathuri_hash algorithm,
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
 * @algorithm: Type of algorithm used to produce OTP keys.
 * @key_uri: output buffer, must have room for the entire URI plus zero, but
 *           maximum 4000 characters so it can fit into a QR code
 *
 * Generate a HOTP type otpauth:// URI to be used with soft OTP authenticator
 * initialization (typically smart phone applications via QR code). Key URI's
 * structure corresponds to the most widely format introduced by
 * google-authenticator.
 *
 * The system parameter @digits tells how many digits the OTP will consists of.
 * Currently accepted values are 6, 7, and 8.
 *
 * The system parameter @algorithm determined the way OTP keys are generated.
 * Accepted values are SHA1, SHA256, and SHA512.
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
            oathuri_hash algorithm,
            char* key_uri)
{
    return 0;
}

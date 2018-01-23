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
#define _POSIX_C_SOURCE 200809L

#include "oathuri.h"

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

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
 * OPTIONAL if `type` is `totp`: period=<unit64_t>
 *
 * Tells how long an OTP is valid in seconds. Default is 30.
 *
 */

/* URI protocol prefix */
static const char OATHURI_PROTOCOL[] = "otpauth://";

/* Key parameter string definitions */
static const char OATHURI_PARAM_SECRET[] = "secret=";
static const char OATHURI_PARAM_ISSUER[] = "issuer=";
static const char OATHURI_PARAM_ALGO[] = "algorithm=";
static const char OATHURI_PARAM_DIGITS[] = "digits=";
static const char OATHURI_PARAM_COUNTER[] = "counter=";
static const char OATHURI_PARAM_PERIOD[] = "period=";

/* Local function to actually build different URIs */
static int
oathuri_construct(oathuri_otp_type type,
            const char* secret,
            const char* account_name,
            const char* issuer,
            unsigned digits,
            uint64_t moving_factor,
            oathuri_hash algorithm,
            char* key_uri);

/**
 * oathuri_totp_generate:
 * @secret: the shared secret string, NULL terminated
 * @account_name: name of the account string, NULL terminated
 * @digits: number of requested digits in the OTP
 * @period: time step system parameter (typically 30)
 * @algorithm: Type of algorithm used to produce OTP keys.
 * @key_uri: output buffer, must have room for the entire URI plus zero, but
 *           maximum OATHURI_MAX_LEN characters so it can fit into a QR code
 *
 * Generate a TOTP type otpauth:// URI to be used with soft OTP authenticator
 * initialization (typically smart phone applications via QR code). Key URI's
 * structure corresponds to the most widely format introduced by
 * google-authenticator.
 *
 * The system parameter @digits tells how many digits the OTP will consists of.
 * Currently accepted values are 6, 7, and 8. If 0 is specified
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
            uint64_t period,
            oathuri_hash algorithm,
            char* key_uri)
{
    return oathuri_construct(OATHURI_TYPE_TOTP,
                             secret,
                             account_name,
                             issuer,
                             digits,
                             period,
                             algorithm,
                             key_uri);
}

/**
 * oathuri_hotp_generate:
 * @secret: the shared secret string, NULL terminated
 * @account_name: name of the account string, NULL terminated
 * @digits: number of requested digits in the OTP
 * @counter: counter to indicate the next OTP to generate
 * @algorithm: Type of algorithm used to produce OTP keys.
 * @key_uri: output buffer, must have room for the entire URI plus zero, but
 *           maximum OATHURI_MAX_LEN characters so it can fit into a QR code
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
    return oathuri_construct(OATHURI_TYPE_HOTP,
                             secret,
                             account_name,
                             issuer,
                             digits,
                             counter,
                             algorithm,
                             key_uri);
}


/**
 * oathuri_construct:
 * @moving_factor is either counter or period, depending on the URI type
 */
static int
oathuri_construct(oathuri_otp_type type,
            const char* secret,
            const char* account_name,
            const char* issuer,
            unsigned digits,
            uint64_t moving_factor,
            oathuri_hash algorithm,
            char* key_uri)
{
    /* Construction buffer. Make sure we have space even if all chars are URL
       encoded to some %XX value */
    char buffer[OATHURI_MAX_LEN * 3] = {0};
    char *pos = NULL;  /* position in the buffer to insert next param into */
    CURL *curl = NULL;
    char *encoded_data = NULL;
    int exit_code = OATHURI_OK;

    /* Account name, issuer and URI buffers are required to be non zero */
    if (NULL == account_name || NULL == issuer || NULL == key_uri) {
        return OATHURI_NULL_PARAMETER;
    }

    /* Account name ans issuer cannot contain colon (:) in them */
    if (NULL != strchr(account_name, ':') || NULL != strchr(issuer, ':')) {
        return OATHURI_INVALID_INPUT;
    }

    /* Unless zero is specified for the default 6 digits, check the value */
    if (digits != 0 && (digits < 6 || digits > 8)) {
        return OATHURI_INVALID_DIGITS;
    }

    /* We need curl to perform URI string encoding */
    if (curl_global_init(CURL_GLOBAL_ALL)) {
        return OATHURI_CURL_FAILURE;
    }
    curl = curl_easy_init();
    if(!curl) {
        return OATHURI_CURL_FAILURE;
    }

    /* Start URI construction */
    pos = buffer;
    /* First create the protocol header */
    pos = stpncpy(pos, OATHURI_PROTOCOL, sizeof(OATHURI_PROTOCOL));
    pos = stpncpy(pos, OATHURI_TYPE_STR[type], sizeof(OATHURI_TYPE_STR[type]));
    *pos++ = '/';

    /* Add LABEL with issuer for backward compatibility */
    encoded_data = curl_easy_escape(curl, issuer, 0);
    if(!encoded_data) {
        exit_code = OATHURI_CURL_FAILURE;
        goto exit;
    }
    pos = stpncpy(pos, encoded_data, strlen(encoded_data) + 1);
    curl_free(encoded_data);
    *pos++ = ':';  /* issuer/account separator */
    encoded_data = curl_easy_escape(curl, account_name, 0);
    if(!encoded_data) {
        exit_code = OATHURI_CURL_FAILURE;
        goto exit;
    }
    pos = stpncpy(pos, encoded_data, strlen(encoded_data) + 1);
    curl_free(encoded_data);

    /* Add secret */
    *pos++ = '?';
    pos = stpncpy(pos, OATHURI_PARAM_SECRET, sizeof(OATHURI_PARAM_SECRET));
    pos = stpncpy(pos, secret, strlen(secret) + 1);

    /* Add issuer as it's recommended for newer applications */
    *pos++ = '&';
    pos = stpncpy(pos, OATHURI_PARAM_ISSUER, sizeof(OATHURI_PARAM_SECRET));
    encoded_data = curl_easy_escape(curl, issuer, 0);
    if(!encoded_data) {
        exit_code = OATHURI_CURL_FAILURE;
        goto exit;
    }
    pos = stpncpy(pos, encoded_data, strlen(encoded_data) + 1);
    curl_free(encoded_data);

    /* The moving factor is dependent on the type of the OTP  */
    if (type == OATHURI_TYPE_HOTP) {
        char factor_string[32] = {0};
        *pos++ = '&';
        pos = stpncpy(pos, OATHURI_PARAM_COUNTER, sizeof(OATHURI_PARAM_COUNTER));
        snprintf(factor_string, sizeof(factor_string), "%ld", moving_factor);
        pos = stpncpy(pos, factor_string, strlen(factor_string) + 1);
    } else if (type == OATHURI_TYPE_TOTP && moving_factor != 0) {
        char factor_string[32] = {0};
        *pos++ = '&';
        pos = stpncpy(pos, OATHURI_PARAM_PERIOD, sizeof(OATHURI_PARAM_PERIOD));
        snprintf(factor_string, sizeof(factor_string), "%ld", moving_factor);
        pos = stpncpy(pos, factor_string, strlen(factor_string) + 1);
    }

    if (algorithm) {
        *pos++ = '&';
        pos = stpncpy(pos, OATHURI_PARAM_ALGO, sizeof(OATHURI_PARAM_ALGO));
        pos = stpncpy(
            pos,
            OATHURI_HASH[algorithm],
            strlen(OATHURI_HASH[algorithm]) + 1
        );
    }

    if (digits) {
        char digit_string[2] = {0};
        snprintf(digit_string, sizeof(digit_string), "%u", digits);
        *pos++ = '&';
        pos = stpncpy(pos, OATHURI_PARAM_DIGITS, sizeof(OATHURI_PARAM_DIGITS));
        pos = stpncpy(pos, digit_string, sizeof(digit_string));
    }
    *pos++ = '\0';

    if (strlen(buffer) > OATHURI_MAX_LEN) {
        exit_code = OATHURI_URI_TOO_LONG;
        goto exit;
    }
    strcpy(key_uri, buffer);

exit:
    curl_easy_cleanup(curl);
    return exit_code;
}

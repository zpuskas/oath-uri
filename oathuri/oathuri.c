/**
 *  oathuri.c - command line tool for OATH one-time password key URI generation
 *  Copyright (C) 2017 Zoltan Puskas <zoltan@sinustrom.info>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#define _POSIX_C_SOURCE 200809L

#include <argp.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <oathuri.h>

#define MANDATORY_ARGS 3

/* CLI argument parsing constants and settings for argp library */
const char* argp_program_version = "oathuri 1.0.0";
const char* argp_program_bug_address = \
    "<bugs@sinustrom.info> by email or " \
    "via web at <https://github.com/zpuskas/oath-uri/issues>";
static char doc[] = "oathuri -- Generate OATH OTP key URI for soft tokens";
static struct argp_option options[] = {
    { "mode", 'm', "MODE", 0,
      "Type of the OATH token: TOTP (default), HOTP", 0 },
    { "digits", 'd', "DIGITS", 0,
      "Number of digits for the OTP: 6 (default), 7, 8", 1 },
    { "counter", 'c', "COUNTER", 0,
      "In HOTP mode the state of the moving factor (default: 0)", 2 },
    { "period", 'p', "PERIOD", 0,
      "In TOTP mode the window of an OTP in seconds (default: 30)", 2 },
    { "hash", 'h', "HASH", 0,
      "Hash algorithm used for the OTP: SHA1 (default), SHA256, SHA512", 3 },
    { "null", '0', 0, 0,
      "Output URI is terminated by a null character instead of a newline. "\
      "Useful when piping into qrencode.", 4 },
    { 0 }
};
static char args_doc[] = "SECRET ACCOUNT ISSUER";

/* Structure containing parsed parameters */
struct arguments
{
   char *args[MANDATORY_ARGS];
   unsigned digits;
   uint64_t moving_factor;
   oathuri_hash hash;
   oathuri_otp_type type;
   bool null_terminated;
};

/* Function called by argp to parse a single option */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    char *end = NULL;
    switch (key)
    {
        case 'm':
            /* Mode can only be one of: [HTOP, TOTP].
               Input is case insensitive. */
            if (!strcasecmp(arg, OATHURI_TYPE_STR[OATHURI_TYPE_TOTP])) {
                arguments->type = OATHURI_TYPE_TOTP;
            } else if (!strcasecmp(arg, OATHURI_TYPE_STR[OATHURI_TYPE_HOTP])) {
                arguments->type = OATHURI_TYPE_HOTP;
            } else {
                error(0, 0, "Invalid OATH mode!");
                argp_usage(state);
                return EINVAL;
            }
            break;
        case 'd':
            arguments->digits = strtoul(arg, &end, 10);
            if (arg == end) {
                error(0, 0, "Digits parameter must be a number!");
                argp_usage(state);
                return EINVAL;
            }
            break;
        case 'c':
            arguments->moving_factor = strtoull(arg, &end, 10);
            if (arg == end) {
                error(0, 0, "Counter parameter must be number!");
                argp_usage(state);
                return EINVAL;
            }
            break;
        case 'p':
            arguments->moving_factor = strtoull(arg, &end, 10);
            if (arg == end) {
                error(0, 0, "Period parameter must be number!");
                argp_usage(state);
                return EINVAL;
            }
            break;
        case 'h':
            /* Hash algorithm can be only one of: [SHA1, SHA256, SHA512].
               Input is case insensitive */
            if (!strcasecmp(arg, OATHURI_HASH[OATHURI_SHA1])) {
                arguments->hash = OATHURI_SHA1;
            } else if (!strcasecmp(arg, OATHURI_HASH[OATHURI_SHA256])) {
                arguments->hash = OATHURI_SHA256;
            } else if (!strcasecmp(arg, OATHURI_HASH[OATHURI_SHA512])) {
                arguments->hash = OATHURI_SHA512;
            } else {
                error(0, 0, "Invalid hash type!");
                argp_usage(state);
                return EINVAL;
            }
            break;
        case '0':
            arguments->null_terminated = true;
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= MANDATORY_ARGS) {
                argp_usage(state);
            }
            arguments->args[state->arg_num] = arg;
            break;
        case ARGP_KEY_END:
            if (state->arg_num < MANDATORY_ARGS) {
                argp_usage(state);
            }
            break;
        case ARGP_KEY_NO_ARGS:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

int
main(int argc, char** argv)
{
    struct arguments arguments;
    struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };
    char buffer[OATHURI_MAX_LEN] = {0};
    int ret = 0;

    /* Zeroing out arguments also sets the accepted default values */
    memset((void*)&arguments, 0, sizeof(struct arguments));
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    /* Call into URI generation library */
    switch (arguments.type) {
        case OATHURI_TYPE_TOTP:
            ret = oathuri_totp_generate(
                arguments.args[0],
                arguments.args[1],
                arguments.args[2],
                arguments.digits,
                arguments.moving_factor,
                arguments.hash,
                buffer
             );
            break;
        case OATHURI_TYPE_HOTP:
            ret = oathuri_hotp_generate(
                arguments.args[0],
                arguments.args[1],
                arguments.args[2],
                arguments.digits,
                arguments.moving_factor,
                arguments.hash,
                buffer
             );
            break;
        default:
            /* We never enter here */
            break;
    }

    /* Inputs are only partially sanitized, so check result from generator */
    if (ret) {
        error(ret, 0, "Failed to generate OATH URI");
    }

    /* Print generated URI */
    printf("%s", buffer);
    if(!arguments.null_terminated) {
        printf("%s", "\n");
    }

    return ret;
}

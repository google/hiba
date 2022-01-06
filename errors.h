/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#ifndef _ERRORS_H
#define _ERRORS_H

#define TO_HIBA_CODE(a) ((a) << 16)

#define HIBA_OK 0

// Generic error codes
#define HIBA_INVALID_EXT -1
#define HIBA_BAD_VERSION -2
#define HIBA_BAD_PARAMS -3
#define HIBA_EXT_TOOBIG -4
#define HIBA_EXT_NOKEY -5
#define HIBA_UNKNOWN_EXT -6
#define HIBA_INTERNAL_ERROR -7
#define HIBA_INVALID_GRL -8

// Extensions sanity checks diagnostics
#define HIBA_EXT_NODOMAIN -20
#define HIBA_GRANT_BADVALIDITY -21
#define HIBA_PAIRS_TOOMANY -22
#define HIBA_PAIR_EXISTS -23
#define HIBA_UNEXPECTED_KEY -24
#define HIBA_GRANT_BADOPTIONS -25

// Check results
#define HIBA_CHECK_NOKEY -40
#define HIBA_CHECK_BADVERSION -41
#define HIBA_CHECK_EXPIRED -42
#define HIBA_CHECK_REVOKED -43
#define HIBA_CHECK_NOGRL -44
#define HIBA_CHECK_BADHOSTNAME -45
#define HIBA_CHECK_BADROLE -46
#define HIBA_CHECK_NOGRANTS -47
#define HIBA_CHECK_DENIED -48

/* Return human readable error messages. */
const char *hiba_err(int err);

#endif  // _ERRORS_H

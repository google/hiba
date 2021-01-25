/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#include "errors.h"
#include "ssherr.h"

const char *hiba_err(int err) {
	if (err == HIBA_OK)
		return "ok";

	switch(err) {
	case HIBA_INTERNAL_ERROR:
		return "internal error";
	case HIBA_INVALID_EXT:
		return "unexpected hiba magic header";
	case HIBA_BAD_VERSION:
		return "incompatible hiba version";
	case HIBA_BAD_PARAMS:
		return "invalid input parameter";
	case HIBA_EXT_TOOBIG:
		return "unexpected extra data in hiba extension";
	case HIBA_EXT_NOKEY:
		return "no such key in hiba extension";
	case HIBA_UNKNOWN_EXT:
		return "unknown hiba extension";
	case HIBA_EXT_NODOMAIN:
		return "missing mandatory domain";
	case HIBA_GRANT_BADVALIDITY:
		return "grant validity must be an integer";
	case HIBA_UNEXPECTED_KEY:
		return "used of reserved key for identity extension";
	case HIBA_GRANT_BADOPTIONS:
		return "grant options syntax error";
	case HIBA_PAIR_EXISTS:
		return "the key for identity extension must be unique";
	case HIBA_CHECK_NOKEY:
		return "schema mismatch";
	case HIBA_CHECK_BADVERSION:
		return "version mismatch";
	case HIBA_CHECK_EXPIRED:
		return "expired grant";
	case HIBA_CHECK_REVOKED:
		return "revoked grant";
	case HIBA_CHECK_NOGRL:
		return "missing grl file";
	case HIBA_CHECK_BADHOSTNAME:
		return "hostname mismatch";
	case HIBA_CHECK_BADROLE:
		return "role mismatch";
	case HIBA_CHECK_DENIED:
		return "no grants matching";
	case HIBA_CHECK_NOGRANTS:
		return "no grants attached";
	default:
		return "unknown error";
	}
}

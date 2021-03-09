/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#include <fnmatch.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "checks.h"
#include "errors.h"
#include "extensions.h"
#include "log.h"

#define _HIBA_CHECK_SUCCESS	"match"
#define _HIBA_CHECK_FAILURE	"invalid"
#define _HIBA_CHECK_FATAL	"fatal"

/* The hibaenv structure is only suppose to live for the time of a check:
 * 1. constuct the hibaenv.
 * 2. run the checks against N certificates.
 * 3. delete he hibaenv. */
struct hibaenv {
	// Host
	u_int64_t now;
	char hostname[HOST_NAME_MAX];
	const struct hibaext *identity;
	const void *grl;

	// Certificate
	u_int64_t cert_issue_ts;
	u_int64_t cert_serial;

	// Extension
	u_int32_t version;
	u_int32_t min_version;
};

int
hibachk_keycmp(const struct hibaext *identity, const char *key, const char *value) {
	int ret = HIBA_OK;
	char *must_match;

	debug2("hibachk_keycmp: testing %s = %s", key, value);

	// grant key MUST also be available in identity.
	if (hibaext_value_for_key(identity, key, &must_match) < 0)
		return HIBA_CHECK_NOKEY;

	debug2("hibachk_keycmp: processing against %s", must_match);

	// Compare must_match and value using globs
	if (fnmatch(value, must_match, 0) == FNM_NOMATCH)
		ret = HIBA_CHECK_DENIED;
	free(must_match);

	return ret;
}

void
hibachk_register_result(struct hibaext *result, const char *key, int status) {
	char *value;

	if (hibaext_value_for_key(result, key, &value) < 0) {
		if (status == 0) {
			debug2("hibachk_register_result: accepted");
			hibaext_add_pair(result, key, _HIBA_CHECK_SUCCESS);
		} else if (status == HIBA_CHECK_NOKEY) {
			debug2("hibachk_register_result: fatal");
			hibaext_add_pair(result, key, _HIBA_CHECK_FATAL);
		} else  {
			debug2("hibachk_register_result: refused");
			hibaext_add_pair(result, key, _HIBA_CHECK_FAILURE);
		}
	} else {
		if (strcmp(value, _HIBA_CHECK_SUCCESS) == 0) {
			debug2("hibachk_register_result: refused, but already accepted previously");
			free(value);
			return;
		}
		if (status == 0) {
			debug2("hibachk_register_result: accepted, overriding previous failures");
			hibaext_update_pair(result, key, _HIBA_CHECK_SUCCESS);
		} else {
			debug2("hibachk_register_result: refused again");
		}
	}
}

int
hibachk_result(struct hibaext *result) {
	int ret = HIBA_OK;
	u_int32_t i;
	char *key = NULL;
	char *value = NULL;

	debug3("hibachk_result: merging %d results", hibaext_pairs_len(result));
	for (i = 0; (ret == HIBA_OK) && (i < hibaext_pairs_len(result)); ++i) {

		free(key);
		free(value);

		if ((ret = hibaext_key_value_at(result, i, &key, &value)) < 0)
			return ret;

		verbose("hibachk_result: key %s -> %s", key, value);
		if (strcmp(value, _HIBA_CHECK_SUCCESS) == 0)
			continue;
		if (strcmp(value, _HIBA_CHECK_FATAL) == 0)
			ret = HIBA_CHECK_NOKEY;
		else if (strcmp(key, HIBA_KEY_HOSTNAME) == 0)
			ret = HIBA_CHECK_BADHOSTNAME;
		else if (strcmp(key, HIBA_KEY_ROLE) == 0)
			ret = HIBA_CHECK_BADROLE;
		else if (strcmp(key, HIBA_KEY_VALIDITY) == 0)
			ret = HIBA_CHECK_EXPIRED;
		else
			ret = HIBA_CHECK_DENIED;
	}

	free(key);
	free(value);

	return ret;
}

int
hibachk_authorize(const struct hibaenv *env, const struct hibaext *grant, const char *role) {
	int ret;
	u_int32_t i;
	u_int32_t version;
	u_int32_t min_version;
	struct hibaext *result = NULL;

	debug2("hibachk_authorize: performing sanity checks");

	// Basic sanity hibachks
	if ((env == NULL) || (grant == NULL))
		return HIBA_BAD_PARAMS;
	if ((ret = hibaext_sanity_check(grant)) < 0)
		return ret;

	// Test versions compatibility
	debug2("hibachk_authorize: checking version");
	if ((ret = hibaext_versions(grant, &version, &min_version)) < 0)
		return ret;

	debug2("hibachk_authorize: checking version: grant v%d (min_version=%d)", version, min_version);
	if (env->version < min_version)
		return HIBA_CHECK_BADVERSION;
	if (version < env->min_version)
		return HIBA_CHECK_BADVERSION;

	// Test GRL.
	debug2("hibachk_authorize: testing GRL against serial %" PRIx64, env->cert_serial);
	// TODO

	result = hibaext_new();

	// Test all other keys.
	for (i = 0; i < hibaext_pairs_len(grant); ++i) {
		char *key;
		char *value;

		if ((ret = hibaext_key_value_at(grant, i, &key, &value)) < 0) {
			debug2("hibachk_authorize: failed to extract key/pair");
			goto err;
		} else if (strcmp(key, HIBA_KEY_OPTIONS) == 0) {
			debug2("hibachk_authorize: skipping 'options' key");
			continue;
		} else if (strcmp(key, HIBA_KEY_VALIDITY) == 0) {
			int v = strtol(value, NULL, 0);

			debug2("hibachk_authorize: testing 'validity' key");
			ret = ((env->cert_issue_ts + v) < env->now);
		} else if (strcmp(key, HIBA_KEY_HOSTNAME) == 0) {
			debug2("hibachk_authorize: testing hostname %s", value);
			ret = strcmp(env->hostname, value);
		} else if (strcmp(key, HIBA_KEY_ROLE) == 0) {
			debug2("hibachk_authorize: testing role %s", value);
			ret = strcmp(role, value);
		} else {
			debug2("hibachk_authorize: testing generic key");
			ret = hibachk_keycmp(env->identity, key, value);
		}

		hibachk_register_result(result, key, ret);
		free(key);
		free(value);
	}

	ret = hibachk_result(result);
err:
	hibaext_free(result);
	return ret;
}

struct hibaenv*
hibaenv_from_host(const struct hibacert *host, const char *grl) {
	int len;
	int ret;
	struct hibaext **exts;
	struct hibaenv *env = calloc(sizeof(struct hibaenv), 1);

	if ((ret = hibacert_hibaexts(host, &exts, &len)) < 0) {
		debug3("hibaenv_from_host: hibacert_hibaexts returned %d: %s", ret, hiba_err(ret));
		goto err;
	}
	if (len != 1) {
		debug3("hibaenv_from_host: too many HIBA identities: got %d", len);
		goto err;
	}
	if ((ret = hibaext_sanity_check(exts[0])) < 0) {
		debug3("hibaenv_from_host: hibaext_sanity_check returned %d: %s", ret, hiba_err(ret));
		goto err;
	}

	env->identity = exts[0];
	env->now = time(NULL);
	gethostname(env->hostname, HOST_NAME_MAX);
	if ((ret = hibaext_versions(exts[0], &env->version, &env->min_version)) < 0) {
		debug3("hibaenv_from_host: hibaext_versions returned %d: %s", ret, hiba_err(ret));
		goto err;
	}
	env->cert_serial = hibacert_cert(host)->serial;
	env->cert_issue_ts = hibacert_cert(host)->valid_after;


	verbose("hibaenv_from_host: loading environment");
	verbose("  now: %" PRIu64, env->now);
	verbose("  hostname: %s", env->hostname);
	verbose("  version: %u", env->version);
	verbose("  min_version: %u", env->min_version);
	verbose("  cert_serial: %" PRIx64, env->cert_serial);
	verbose("  cert_issue_ts: %" PRIu64, env->cert_issue_ts);

	return env;
err:
	free(env);
	return NULL;
}

void
hibaenv_free(struct hibaenv *env) {
	free(env);
}

void hibachk_authorized_users(const struct hibaenv *env, const struct hibacert *cert, int idx, FILE *f) {
	int len;
	u_int32_t i;
	struct hibaext *grant;
	struct hibaext **grants;
	struct sshbuf *options;

	if (hibacert_hibaexts(cert, &grants, &len) < 0)
		return;
	if (idx >= len)
		return;
	grant = grants[idx];

	options = sshbuf_new();
	for (i = 0; i < hibaext_pairs_len(grant); ++i) {
		char *key;
		char *value;

		if (hibaext_key_value_at(grant, i, &key, &value)) {
			sshbuf_free(options);
			return;
                }

		if (strcmp(key, HIBA_KEY_OPTIONS) == 0) {
			int sz = strlen(value);

			if (sshbuf_len(options) > 0)
				sshbuf_put_u8(options, ',');
			sshbuf_put(options, value, sz);
		}

		free(key);
		free(value);
	}
        if (sshbuf_len(options) > 0)
          sshbuf_put_u8(options, ' ');
	sshbuf_put_u8(options, '\0');

	verbose("hibachk_authorized_users: access granted, generating list of authorized principals");
	for (i = 0; i < hibacert_cert(cert)->nprincipals; ++i) {
		fprintf(f, "%s%s\n", sshbuf_ptr(options), hibacert_cert(cert)->principals[i]);
	}

	fflush(f);
	sshbuf_free(options);
}

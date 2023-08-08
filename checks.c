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
#include "config.h"
#include "errors.h"
#include "extensions.h"
#include "log.h"

#define _HIBA_CHECK_SUCCESS	"accepted"
#define _HIBA_CHECK_FAILURE	"refused"
#define _HIBA_CHECK_FATAL	"fatal"

/* The hibaenv structure is only suppose to live for the time of a check:
 * 1. constuct the hibaenv.
 * 2. run the checks against N certificates.
 * 3. delete he hibaenv. */
struct hibaenv {
	/* Host */
	u_int64_t now;
	char hostname[HOST_NAME_MAX];
	const struct hibaext *identity;
	const struct hibagrl *grl;

	/* Certificate */
	u_int64_t user_cert_issue_ts;
	u_int64_t user_cert_serial;

	/* Grant */
	u_int32_t nprincipals;
	char **principals;

	/* Host extension */
	u_int32_t version;
	u_int32_t min_version;
};

int
hibachk_keycmp(const struct hibaext *identity, const char *key, const char *value) {
	int ret = HIBA_OK;
	char *must_match;

	debug2("hibachk_keycmp: testing %s = %s", key, value);

	/* grant key MUST also be available in identity. */
	if (hibaext_value_for_key(identity, key, &must_match) < 0)
		return HIBA_CHECK_NOKEY;

	debug2("hibachk_keycmp: processing against %s", must_match);

	/* Compare must_match and value using globs. */
	if (fnmatch(value, must_match, 0) != 0)
		ret = HIBA_CHECK_DENIED;
	free(must_match);

	return ret;
}

void
hibachk_register_result(struct hibaext *result, const char *key, int status, int negative_matching) {
	char *value;

	if (hibaext_value_for_key(result, key, &value) < 0) {
		/* First check for key: */
		char *on_match = _HIBA_CHECK_SUCCESS;
		char *on_miss = _HIBA_CHECK_FAILURE;

		if (negative_matching) {
			on_match = _HIBA_CHECK_FAILURE;
			on_miss = _HIBA_CHECK_SUCCESS;
		}
		if (status == 0) {
			debug2("hibachk_register_result: %s", on_match);
			hibaext_add_pair(result, key, on_match);
		} else if (status == HIBA_CHECK_NOKEY) {
			debug2("hibachk_register_result: fatal");
			hibaext_add_pair(result, key, _HIBA_CHECK_FATAL);
		} else  {
			debug2("hibachk_register_result: %s", on_miss);
			hibaext_add_pair(result, key, on_miss);
		}
	} else {
		/* Repeated key check, we must implement result merging as OR
		 * for positive matches, or AND for negative matches.
		 * Starting with a previously valid constraint: */
		if (strcmp(value, _HIBA_CHECK_SUCCESS) == 0) {
			if (negative_matching && status == 0) {
				/* On negative matching, one match fails the grant: */
				hibaext_update_pair(result, key, _HIBA_CHECK_FAILURE);
				debug2("hibachk_register_result: refused because negative matching");
			} else {
				/* Here, either:
				 * -  positive matching and previously granted
				 * -  negative matching, previously granted and
				 *    currently still not matching. */
				debug2("hibachk_register_result: still accepted");
			}
		} else {
			/* From here, we know previous contraint where invalid: */
			if (!negative_matching && status == 0) {
				/* newly valid constraint with positive matching: */
				debug2("hibachk_register_result: accepted, overriding previous failures");
				hibaext_update_pair(result, key, _HIBA_CHECK_SUCCESS);
			} else {
				if (negative_matching) {
					debug2("hibachk_register_result: negative matching previously refused");
				} else {
					debug2("hibachk_register_result: positive matching refused again");
				}
			}
		}
		free(value);
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
		else
			ret = HIBA_CHECK_DENIED;
	}

	free(key);
	free(value);

	return ret;
}

int
hibachk_authorize(const struct hibaenv *env, const struct hibaext *grant, u_int32_t idx, const char *role) {
	int ret;
	int expand_self = 0;
	long expiration = 0;
	long expiration_set = 0;
	u_int32_t i;
	u_int32_t version;
	u_int32_t min_version;

	debug2("hibachk_authorize: performing sanity checks");

	/* Basic sanity hibachks. */
	if ((env == NULL) || (grant == NULL))
		return HIBA_BAD_PARAMS;
	if (hibaext_type(grant) != HIBA_GRANT_EXT)
		return HIBA_BAD_PARAMS;
	if ((ret = hibaext_sanity_check(grant)) < 0)
		return ret;

	/* Test versions compatibility. */
	debug2("hibachk_authorize: checking version");
	if ((ret = hibaext_versions(grant, &version, &min_version)) < 0)
		return ret;

	debug2("hibachk_authorize: checking version: grant v%d (min_version=%d)", version, min_version);
	if (env->version < min_version)
		return HIBA_CHECK_BADVERSION;
	if (version < env->min_version)
		return HIBA_CHECK_BADVERSION;

	/* Test GRL. */
	debug2("hibachk_authorize: testing GRL against serial %" PRIx64, env->user_cert_serial);
	if (env->grl != NULL && (ret = hibagrl_check(env->grl, env->user_cert_serial, idx)) < 0) {
		return ret;
	}

	/* Check key needing special handling: HIBA_KEY_VALIDITY,
         * HIBA_KEY_ROLE. */
	for (i = 0; i < hibaext_pairs_len(grant); ++i) {
		char *key;
		char *value;

		if ((ret = hibaext_key_value_at(grant, i, &key, &value)) < 0) {
			debug2("hibachk_authorize: failed to extract key/pair");
			return ret;
		} else if (strcmp(key, HIBA_KEY_VALIDITY) == 0) {
			long v = strtol(value, NULL, 0);

			expiration_set = 1;
			/* We look for the expiration that is most distant in
			 * the future. */
			if (v > expiration)
				expiration = v;
		} else if ((strcmp(key, HIBA_KEY_ROLE) == 0) && (strcmp(value, HIBA_ROLE_PRINCIPALS) == 0)) {
			/* A grant using HIBA_ROLE_PRINCIPALS as role must be
			 * checked against all the principals declared in the
			 * certificate, on top of other roles declared in the
			 * grant. */
			expand_self = 1;
		}

		free(key);
		free(value);
	}

	/* Test for expiration. */
	if (expiration_set && ((env->user_cert_issue_ts + expiration) < env->now)) {
		debug2("hibachk_authorize: expired");
		return HIBA_CHECK_EXPIRED;
	}

	/* Check for role HIBA_ROLE_PRINCIPALS expansion. */
	if (expand_self) {
		int role_is_self = 0;
		for (i = 0; i < env->nprincipals; ++i) {
			if (strcmp(env->principals[i], role) == 0) {
				role_is_self = 1;
				break;
			}
		}
		if (role_is_self) {
			debug2("hibachk_authorize: expanding role as " HIBA_ROLE_PRINCIPALS);
			role = HIBA_ROLE_PRINCIPALS;
		}
	}

	/* The grant looks OK, we can run the policy authorization checks. */
	return hibachk_query(env->identity, grant, env->hostname, role);
}

int
hibachk_query(const struct hibaext *identity, const struct hibaext *grant, const char *hostname, const char *role) {
	int ret;
	u_int32_t i;
	struct hibaext *result = NULL;

	result = hibaext_new();
	hibaext_init(result, HIBA_GRANT_EXT);

	/* Test all keys from the grant against the identity: */
	for (i = 0; i < hibaext_pairs_len(grant); ++i) {
		int skip = 0;
		int key_offset = 0;
		int negative_matching = 0;
		char *key;
		char *value;

		if ((ret = hibaext_key_value_at(grant, i, &key, &value)) < 0) {
			debug2("hibachk_query: failed to extract key/pair");
			goto err;
		}
		if (key[0] == HIBA_NEGATIVE_MATCHING) {
			debug2("hibachk_query: found negative matching");
			negative_matching = 1;
			key_offset = 1;
		}

		if (strcmp(key, HIBA_KEY_OPTIONS) == 0) {
			debug2("hibachk_query: skipping 'options' key");
			skip = 1;
		} else if (strcmp(key, HIBA_KEY_VALIDITY) == 0) {
			debug2("hibachk_query: skipping 'validity' key: already verified");
			skip = 1;
		} else if (strcmp(key+key_offset, HIBA_KEY_HOSTNAME) == 0) {
			debug2("hibachk_query: testing hostname %s", value);
			ret = fnmatch(value, hostname, 0);
		} else if (strcmp(key+key_offset, HIBA_KEY_ROLE) == 0) {
			debug2("hibachk_query: testing role %s", value);
			ret = fnmatch(value, role, 0);
		} else {
			debug2("hibachk_query: testing generic key");
			ret = hibachk_keycmp(identity, key+key_offset, value);
		}

		if (!skip) {
			hibachk_register_result(result, key, ret, negative_matching);
		}
		free(key);
		free(value);
	}

	ret = hibachk_result(result);
err:
	hibaext_free(result);
	return ret;
}

struct hibaenv*
hibaenv_from_host(const struct hibacert *host, const struct hibacert *user, const struct hibagrl *grl) {
	int len;
	int ret;
	uint32_t i;
	struct hibaext **exts;
	struct hibaenv *env = calloc(sizeof(struct hibaenv), 1);

	if ((ret = hibacert_hibaexts(host, &exts, &len)) < 0) {
		debug2("hibaenv_from_host: hibacert_hibaexts returned %d: %s", ret, hiba_err(ret));
		goto err;
	}
	if (len != 1) {
		debug2("hibaenv_from_host: too many HIBA identities: got %d", len);
		goto err;
	}
	if ((ret = hibaext_sanity_check(exts[0])) < 0) {
		debug2("hibaenv_from_host: hibaext_sanity_check returned %d: %s", ret, hiba_err(ret));
		goto err;
	}

	env->identity = exts[0];
	env->now = time(NULL);
	gethostname(env->hostname, HOST_NAME_MAX);
	if ((ret = hibaext_versions(env->identity, &env->version, &env->min_version)) < 0) {
		debug2("hibaenv_from_host: hibaext_versions returned %d: %s", ret, hiba_err(ret));
		goto err;
	}

	env->user_cert_serial = hibacert_cert(user)->serial;
	env->user_cert_issue_ts = hibacert_cert(user)->valid_after;
	env->nprincipals = hibacert_cert(user)->nprincipals;
	env->principals = hibacert_cert(user)->principals;

	env->grl = grl;
	if (grl != NULL) {
		verbose("hibaenv_from_host: loading GRL v%d", hibagrl_version(env->grl));
		verbose("  comment: %s", hibagrl_comment(env->grl));
		verbose("  timestamp: %" PRIu64, hibagrl_timestamp(env->grl));
		verbose("  entries: %" PRIu64, hibagrl_serials_count(env->grl));
	}

	verbose("hibaenv_from_host: loading environment");
	verbose("  now: %" PRIu64, env->now);
	verbose("  hostname: %s", env->hostname);
	verbose("  version: %u", env->version);
	verbose("  min_version: %u", env->min_version);
	verbose("  user_cert_serial: %" PRIx64, env->user_cert_serial);
	verbose("  user_cert_issue_ts: %" PRIu64, env->user_cert_issue_ts);
	for (i = 0; i < env->nprincipals; ++i) {
		verbose("  user principal: %s", env->principals[i]);
	}

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

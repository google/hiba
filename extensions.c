/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "errors.h"
#include "extensions.h"
#include "log.h"
#include "ssherr.h"

#define HIBA_CURRENT_VERSION 		0x1
#define HIBA_MIN_SUPPORTED_VERSION	0x1

struct pair {
	char *key;
	char *val;
	struct pair *next;
};

struct hibaext {
	u_int32_t type;
	u_int32_t version;
	u_int32_t min_version;
	u_int32_t npairs;

	struct pair pairs;
};

int
hibaext_decode(struct hibaext *ext, struct sshbuf *blob) {
	int ret;
	u_int32_t i;
	u_int32_t magic;
	struct pair *pair;
	struct sshbuf *d = NULL;

	if (blob == NULL || ext == NULL)
		return HIBA_BAD_PARAMS;

	memset(ext, 0, sizeof(struct hibaext));

	if ((ret = sshbuf_peek_u32(blob, 0, &magic)) < 0) {
		debug3("hibaext_decode: sshbuf_peek_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if (magic != HIBA_MAGIC) {
		debug3("hibaext_decode: trying base64 decode");
		d = sshbuf_new();
		if ((ret = sshbuf_b64tod(d, (const char*)sshbuf_ptr(blob))) < 0) {
			debug3("hibaext_decode: sshbuf_b64tod returned %d: %s", ret, ssh_err(ret));
			ret = HIBA_INTERNAL_ERROR;
			goto err;
		}
	} else {
		d = sshbuf_fromb(blob);
	}

	debug3("hibaext_decode: reading header");
	if ((ret = sshbuf_get_u32(d, &magic)) != 0) {
		debug3("hibaext_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if (magic != HIBA_MAGIC)
		return HIBA_INVALID_EXT;
	if ((ret = sshbuf_get_u32(d, &ext->type)) != 0) {
		debug3("hibaext_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_get_u32(d, &ext->version)) != 0) {
		debug3("hibaext_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_get_u32(d, &ext->min_version)) != 0) {
		debug3("hibaext_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_get_u32(d, &ext->npairs)) != 0) {
		debug3("hibaext_decode: sshbuf_get_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((HIBA_MIN_SUPPORTED_VERSION > ext->version) ||
	    (ext->min_version > HIBA_CURRENT_VERSION)) {
		ret = HIBA_BAD_VERSION;
		goto err;
	}

	debug3("hibaext_decode: reading %d pairs", ext->npairs);
	pair = &ext->pairs;
	for (i = 0; i < ext->npairs; ++i) {
		pair->next = calloc(sizeof(struct pair), 1);
		pair = pair->next;
		if ((ret = sshbuf_get_cstring(d, &pair->key, NULL)) != 0) {
			debug3("hibaext_decode: sshbuf_get_cstring returned %d: %s", ret, ssh_err(ret));
			ret = HIBA_INTERNAL_ERROR;
			goto err;
		}
		if ((ret = sshbuf_get_cstring(d, &pair->val, NULL)) != 0) {
			debug3("hibaext_decode: sshbuf_get_cstring returned %d: %s", ret, ssh_err(ret));
			ret = HIBA_INTERNAL_ERROR;
			goto err;
		}
		debug3("hibaext_decode: reading pair%d: %s = %s", i, pair->key, pair->val);
	}
	debug3("hibaext_decode: %zu bytes left in buffer", sshbuf_len(d));
	if (sshbuf_len(d) > 0) {
		ret = HIBA_EXT_TOOBIG;
		goto err;
        }

	ret = hibaext_sanity_check(ext);
err:
	sshbuf_free(d);
	return ret;
}

int
hibaext_encode(const struct hibaext *ext, struct sshbuf *blob) {
	int ret;
	u_int32_t count = 0;
	u_int32_t sz = 0;
	const struct pair *pair;
	struct sshbuf *d;

	if (blob == NULL || ext == NULL)
		return HIBA_BAD_PARAMS;
	if ((ret = hibaext_sanity_check(ext)) != 0)
		return ret;

	// Pre-calculate size
	pair = &ext->pairs;
	while(pair->next != NULL && count < ext->npairs) {
		pair = pair->next;
		sz += sizeof(u_int32_t) + strlen(pair->key);
		sz += sizeof(u_int32_t) + strlen(pair->val);
		++count;
	}

	d = sshbuf_new();
	if ((ret = sshbuf_allocate(d, sizeof(u_int32_t) + sizeof(struct hibaext) + sz)) < 0) {
		debug3("hibaext_encode: sshbuf_allocate returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}

	// Construct the sshbuf
	debug3("hibaext_encode: encoding header");
	if ((ret = sshbuf_put_u32(d, HIBA_MAGIC)) != 0) {
		debug3("hibaext_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_put_u32(d, ext->type)) != 0) {
		debug3("hibaext_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_put_u32(d, ext->version)) != 0) {
		debug3("hibaext_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_put_u32(d, ext->min_version)) != 0) {
		debug3("hibaext_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_put_u32(d, count)) != 0) {
		debug3("hibaext_encode: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}

	debug3("hibaext_encode: encoding %d pairs", ext->npairs);
	count = 0;
	pair = &ext->pairs;
	while(pair->next != NULL && count < ext->npairs) {
		pair = pair->next;
		if ((ret = sshbuf_put_cstring(d, pair->key)) != 0) {
			debug3("hibaext_encode: sshbuf_put_cstring returned %d: %s", ret, ssh_err(ret));
			ret = HIBA_INTERNAL_ERROR;
			goto err;
		}
		if ((ret = sshbuf_put_cstring(d, pair->val)) != 0) {
			debug3("hibaext_encode: sshbuf_put_cstring returned %d: %s", ret, ssh_err(ret));
			ret = HIBA_INTERNAL_ERROR;
			goto err;
		}
		++count;
	}

	debug3("hibaext_encode: base64 encode");
	if ((ret = sshbuf_dtob64(d, blob, 0)) < 0) {
		debug3("hibaext_decode: sshbuf_dtob64 returned %d: %s", ret, ssh_err(ret));
	ret = HIBA_INTERNAL_ERROR;
	}

err:
	sshbuf_free(d);
	return ret;
}

struct hibaext*
hibaext_new() {
	struct hibaext *ext = calloc(sizeof(struct hibaext), 1);
	return ext;
}

int
hibaext_init(struct hibaext *ext, int type) {
	if (ext == NULL)
		return -1;
	if ((type != HIBA_IDENTITY_EXT) && (type != HIBA_GRANT_EXT))
		return HIBA_UNKNOWN_EXT;

	memset(ext, 0, sizeof(struct hibaext));

	ext->type = type;
	ext->version = HIBA_CURRENT_VERSION;
	ext->min_version = HIBA_MIN_SUPPORTED_VERSION;
	debug2("hibaext_init: initialize type %s: version %d (>= %d)", hibaext_id(ext), HIBA_CURRENT_VERSION, HIBA_MIN_SUPPORTED_VERSION);

	return HIBA_OK;
}

void
hibaext_free(struct hibaext *ext) {
	struct pair *pair;

	if (ext == NULL)
		return;

	pair = ext->pairs.next;
	while (pair != NULL) {
		struct pair *tbd = pair;
		pair = pair->next;

		free(tbd->key);
		free(tbd->val);
		free(tbd);
	}
	free(ext);
}

inline u_int32_t
hibaext_type(const struct hibaext *ext) {
	if (ext == NULL)
		return HIBA_UNKNOWN_EXT;

	return ext->type;
}

const char*
hibaext_id(const struct hibaext *ext) {
	if (ext == NULL)
		return hiba_err(-HIBA_UNKNOWN_EXT);

	switch (ext->type) {
	case HIBA_IDENTITY_EXT:
		return HIBA_IDENTITY_ID;
	case HIBA_GRANT_EXT:
		return HIBA_GRANT_ID;
	default:
		return hiba_err(-HIBA_UNKNOWN_EXT);
	}
}


int
hibaext_versions(const struct hibaext *ext, u_int32_t *vers, u_int32_t *min_vers) {
	if (ext == NULL)
		return HIBA_BAD_PARAMS;

	if (vers != NULL)
		*vers = ext->version;
	if (min_vers != NULL)
		*min_vers = ext->min_version;

	return HIBA_OK;
}

u_int32_t
hibaext_pairs_len(const struct hibaext *ext) {
	if (ext == NULL)
		return HIBA_BAD_PARAMS;

	return ext->npairs;
}

int
hibaext_key_value_at(const struct hibaext *ext, u_int32_t position, char **key, char **value) {
	struct pair *pair;

	if (ext == NULL)
		return HIBA_BAD_PARAMS;
	if (position >= ext->npairs)
		return HIBA_BAD_PARAMS;

	pair = ext->pairs.next;
	while(position != 0) {
		pair = pair->next;
		--position;
	}
	if (key != NULL)
		*key = strdup(pair->key);
	if (value != NULL)
		*value = strdup(pair->val);

	return HIBA_OK;
}

int
hibaext_value_for_key(const struct hibaext *ext, const char *key, char **value) {
	struct pair *pair;

	if (ext == NULL)
		return HIBA_BAD_PARAMS;
	if ((ext->type != HIBA_IDENTITY_EXT) && (ext->type != HIBA_GRANT_EXT))
		return HIBA_BAD_PARAMS;

	pair = ext->pairs.next;
	while(pair != NULL && strcmp(pair->key, key) != 0)
		pair = pair->next;
	if (pair == NULL)
		return HIBA_EXT_NOKEY;
	if (value != NULL)
		*value = strdup(pair->val);

	return HIBA_OK;
}

int
hibaext_add_pair(struct hibaext *ext, const char *key, const char *value) {
	struct pair *pair;
	struct pair *new;

	if (ext == NULL || key == NULL || value == NULL)
		return HIBA_BAD_PARAMS;
	if (ext->type == HIBA_IDENTITY_EXT && (hibaext_value_for_key(ext, key, NULL) == HIBA_OK))
		return HIBA_PAIR_EXISTS;

	debug3("hibaext_add_pair: add key '%s' = '%s'", key, value);
	ext->npairs++;
	new = calloc(sizeof(struct pair), 1);
	new->key = strdup(key);
	new->val = strdup(value);
	pair = &ext->pairs;
	while (pair->next != NULL)
		pair = pair->next;
	pair->next = new;

	return HIBA_OK;
}

int
hibaext_update_pair(struct hibaext *ext, const char *key, const char *value) {
	struct pair *pair;

	if (ext == NULL || key == NULL || value == NULL)
		return HIBA_BAD_PARAMS;

	pair = ext->pairs.next;
	while(pair != NULL && strcmp(pair->key, key) != 0)
		pair = pair->next;
	if (pair == NULL)
		return HIBA_EXT_NOKEY;
	debug3("hibaext_update_pair: update key '%s': '%s' -> '%s'", key, pair->val, value);
	free(pair->val);
	pair->val = strdup(value);

	return HIBA_OK;
}

int
hibaext_sanity_check(const struct hibaext *ext) {
	int ret = 0;

	if (ext == NULL)
		return HIBA_BAD_PARAMS;
	if ((ext->type != HIBA_IDENTITY_EXT) && (ext->type != HIBA_GRANT_EXT))
		return HIBA_UNKNOWN_EXT;
	if (hibaext_value_for_key(ext, HIBA_KEY_DOMAIN, NULL) < 0)
		return HIBA_EXT_NODOMAIN;
	if (ext->type == HIBA_GRANT_EXT) {
		int i = 0;
		char *key;
		char *value;

		while (hibaext_key_value_at(ext, i, &key, &value) == HIBA_OK) {
			if (strcmp(key, HIBA_KEY_VALIDITY) == 0) {
				char *ok;
				int v = strtol(value, &ok, 0);

				if (ok == value || *ok != '\0')
					ret = HIBA_GRANT_BADVALIDITY;
				else if (v < 0)
					ret =  HIBA_GRANT_BADVALIDITY;
			} else if (strcmp(key, HIBA_KEY_OPTIONS) == 0) {
				size_t i;
				int quoted = 0;
				int dquoted = 0;

				for (i = 0; i < strlen(value); ++i) {
					switch (value[i]) {
					case '\n':
						ret = HIBA_GRANT_BADOPTIONS;
						break;
					case ' ':
						if (!dquoted)
							ret = HIBA_GRANT_BADOPTIONS;
						break;
					case '\'':
						if (!dquoted)
							quoted = (quoted+1)%2;
						break;
					case '"':
						if (!quoted)
							dquoted = (dquoted+1)%2;
						break;
					}
					if (ret != 0)
						break;
				}
				if (quoted || dquoted)
					ret = HIBA_GRANT_BADOPTIONS;
                        }
			free(key);
			free(value);

			if (ret != 0)
				return ret;
			++i;
		}
	} else if (ext->type == HIBA_IDENTITY_EXT) {
		int i = 0;
		char *key;
		char *value;

		while (hibaext_key_value_at(ext, i, &key, &value) == HIBA_OK) {
			char *v = NULL;

			debug3("hibaext_sanity_check: checking key '%s'", key);
			if (strcmp(key, HIBA_KEY_HOSTNAME) == 0)
				ret = HIBA_UNEXPECTED_KEY;
			else if (strcmp(key, HIBA_KEY_ROLE) == 0)
				ret = HIBA_UNEXPECTED_KEY;
			else if (strcmp(key, HIBA_KEY_OPTIONS) == 0)
				ret = HIBA_UNEXPECTED_KEY;
			else if (strcmp(key, HIBA_KEY_VALIDITY) == 0)
				ret = HIBA_UNEXPECTED_KEY;
			else if (hibaext_value_for_key(ext, key, &v) == HIBA_OK &&
				 strcmp(value, v) != 0)
				ret = HIBA_UNEXPECTED_KEY;

			free(v);
			free(value);
			free(key);

			if (ret != 0)
				return ret;
			++i;
		}
	}

	return HIBA_OK;
}

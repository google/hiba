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

#include "config.h"

#ifdef WITH_EXTENSION_COMPRESSION
#define ZLIB_CONST
#include <zlib.h>
#endif  /* WITH_EXTENSION_COMPRESSION */

#include "errors.h"
#include "extensions.h"
#include "log.h"
#include "ssherr.h"
#include "xmalloc.h"

#define HIBA_CURRENT_VERSION		0x2
#define HIBA_MIN_SUPPORTED_VERSION	0x1

#define HIBA_NEGATIVE_MATCHING_VERSION	0x2

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

static struct sshbuf*
hibaext_maybe_inflate(struct sshbuf *extensions) {
	int ret;
	struct sshbuf *decomp = NULL;
#ifdef WITH_EXTENSION_COMPRESSION
	size_t len = sshbuf_len(extensions);
	const unsigned char *data = sshbuf_ptr(extensions);
	z_stream stream;

	memset(&stream, 0, sizeof(stream));

	inflateInit(&stream);
	stream.next_in = data;
	stream.avail_in = len;

	do {
		unsigned char buf[512];

		stream.next_out = buf;
		stream.avail_out = sizeof(buf);
		ret = inflate(&stream, Z_SYNC_FLUSH);
		if (ret != Z_OK && ret != Z_STREAM_END) {
			break;
		}
		if (decomp == NULL) {
			decomp = sshbuf_new();
		}
		if (sshbuf_put(decomp, buf, sizeof(buf) - stream.avail_out) < 0) {
			ret = Z_BUF_ERROR;
			break;
		}
	} while (ret != Z_STREAM_END);
	inflateEnd(&stream);

	if (ret == Z_STREAM_END) {
		debug2("hibaext_maybe_inflate: using decompressed extension %zu -> %zu bytes", len, sshbuf_len(decomp));
		return decomp;
	}
	sshbuf_free(decomp);
#endif /* WITH_EXTENSION_COMPRESSION */
	return sshbuf_fromb(extensions);
}

static int
hibaext_maybe_deflate(struct sshbuf *in, int compress, struct sshbuf *out) {
	int ret = HIBA_OK;
	struct sshbuf *temp = in;

#ifdef WITH_EXTENSION_COMPRESSION
	if (compress) {
		z_stream stream;

		temp = sshbuf_new();
		memset(&stream, 0, sizeof(stream));

		deflateInit(&stream, Z_BEST_COMPRESSION);
		stream.next_in = (unsigned char*)sshbuf_ptr(in);
		stream.avail_in = sshbuf_len(in);

		debug3("hibaext_maybe_deflate: compression in %d.", stream.avail_in);
		while (ret != Z_STREAM_END) {
			unsigned char buf[512];

			stream.next_out = buf;
			stream.avail_out = sizeof(buf);
			ret = deflate(&stream, Z_FINISH);
			if (ret != Z_OK && ret != Z_STREAM_END) {
				debug2("hibaext_maybe_deflate: deflate returned %d", ret);
				ret = HIBA_INTERNAL_ERROR;
				goto err;
			}
			if (sshbuf_put(temp, buf, sizeof(buf) - stream.avail_out) < 0) {
				ret = HIBA_INTERNAL_ERROR;
				goto err;
			}
		}
		ret = HIBA_OK;
		debug3("hibaext_maybe_deflate: compression out %zu.", sshbuf_len(temp));
err:
		deflateEnd(&stream);
	}
#endif  /* WITH_EXTENSION_COMPRESSION */

	if (ret == HIBA_OK) {
		if (sshbuf_putb(out, temp) < 0) {
			ret = HIBA_INTERNAL_ERROR;
		}
	}
	if (temp != in) {
		sshbuf_free(temp);
	}
	return ret;
}

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
	if (magic != HIBA_MAGIC) {
		ret = HIBA_INVALID_EXT;
		goto err;
	}
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

static int
hibaext_decode_one(struct hibaext ***exts, int nexts, const unsigned char *data, size_t len) {
	int ret;
	struct sshbuf *blob = sshbuf_new();
	if (sshbuf_put(blob, data, len) < 0) {
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	*exts = xreallocarray(*exts, nexts + 1, sizeof(struct hibaext*));
	(*exts)[nexts] = hibaext_new();
	ret = hibaext_decode((*exts)[nexts], blob);
err:
	sshbuf_free(blob);
	return ret;
}

int
hibaext_decode_all(struct hibaext ***exts, struct sshbuf *blob) {
	int nexts = 0;
	int ret = 0;
	size_t i = 0;
	u_int32_t magic;
	struct sshbuf *extensions = hibaext_maybe_inflate(blob);
	const unsigned char *data = sshbuf_ptr(extensions);
	size_t len = sshbuf_len(extensions);

	if (data == NULL) {
		ret = HIBA_INVALID_EXT;
		goto err;
	}

	magic = PEEK_U32(data);
	debug3("hibaext_decode_all: total extension len %zu, magic=0x%08x", len, magic);

	if (magic == HIBA_B64_MAGIC) {
		/* Base64 format.
		 * Either one or multiple comma separated extensions. */
		debug3("hibaext_decode_all: found base64 extension(s)");
		int pos = 0;
		while (i < len) {
			int extension_len = 0;

			/* If we find a comma or end of buffer, we should have
			 * a full extension to parse. */
			if (data[i] == ',') {
				extension_len = i - pos;
			} else if (i == len - 1) {
				extension_len = len - pos;
			}

			if (extension_len > 0) {
				debug3("hibaext_decode_all: found extension [%d, %zu]: %.*s", pos, i, extension_len, data+pos);
				if ((ret = hibaext_decode_one(exts, nexts, data+pos, extension_len)) < 0) {
					debug3("hibaext_decode_all: hibaext_decode_one returned %d: %s", ret, ssh_err(ret));
					break;
				}
				nexts++;
				pos = i+1;
			}
			++i;
		}
	} else if (magic == HIBA_MAGIC) {
		/* One extension using raw format. */
		debug3("hibaext_decode_all: found 1 raw extension");
		if ((ret = hibaext_decode_one(exts, nexts, data, len)) < 0) {
			debug3("hibaext_decode_all: hibaext_decode_one returned %d: %s", ret, ssh_err(ret));
		}
		nexts++;
	} else if (magic == HIBA_MULTI_EXTS) {
		/* Consume magic 'MULT' header. */
		struct sshbuf *raw_exts = sshbuf_from(data+4, len-4);

		debug3("hibaext_decode_all: found raw extension(s)");

		/* Multiple raw extensions starting with the size of the
		 * extension. */
		while (sshbuf_len(raw_exts) > 0) {
			size_t extension_len;
			const unsigned char *extension_data;

			if ((ret = sshbuf_get_string_direct(raw_exts, &extension_data, &extension_len)) < 0) {
		                debug3("hibaext_decode_all: sshbuf_get_string returned %d: %s", ret, ssh_err(ret));
				ret = HIBA_INTERNAL_ERROR;
				break;
		        }
			debug3("hibaext_decode_all: found 1 extension len: %zu", extension_len);
			if ((ret = hibaext_decode_one(exts, nexts, extension_data, extension_len)) < 0) {
				debug3("hibaext_decode_all: hibaext_decode_one returned %d: %s", ret, ssh_err(ret));
				break;
			}
			nexts++;
		}
		sshbuf_free(raw_exts);
	}
err:
	sshbuf_free(extensions);

	if (ret != HIBA_OK) {
		return ret;
	}
	return nexts;
}

static int
hibaext_encode_one_raw(const struct hibaext *ext, struct sshbuf *blob) {
	int ret;
	u_int32_t count = 0;
	u_int32_t sz = 0;
	const struct pair *pair;

	if (blob == NULL || ext == NULL)
		return HIBA_BAD_PARAMS;
	if ((ret = hibaext_sanity_check(ext)) != 0)
		return ret;

	/* Pre-calculate size. */
	pair = &ext->pairs;
	while(pair->next != NULL && count < ext->npairs) {
		pair = pair->next;
		sz += sizeof(u_int32_t) + strlen(pair->key);
		sz += sizeof(u_int32_t) + strlen(pair->val);
		++count;
	}

	if ((ret = sshbuf_allocate(blob, sizeof(u_int32_t) + sizeof(struct hibaext) + sz)) < 0) {
		debug3("hibaext_encode_one_raw: sshbuf_allocate returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}

	/* Construct the sshbuf. */
	debug3("hibaext_encode_one_raw: encoding header");
	if ((ret = sshbuf_put_u32(blob, HIBA_MAGIC)) != 0) {
		debug3("hibaext_encode_one_raw: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_put_u32(blob, ext->type)) != 0) {
		debug3("hibaext_encode_one_raw: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_put_u32(blob, ext->version)) != 0) {
		debug3("hibaext_encode_one_raw: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_put_u32(blob, ext->min_version)) != 0) {
		debug3("hibaext_encode_one_raw: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}
	if ((ret = sshbuf_put_u32(blob, count)) != 0) {
		debug3("hibaext_encode_one_raw: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
		goto err;
	}

	debug3("hibaext_encode_one_raw: encoding %d pairs", ext->npairs);
	count = 0;
	pair = &ext->pairs;
	while(pair->next != NULL && count < ext->npairs) {
		pair = pair->next;
		if ((ret = sshbuf_put_cstring(blob, pair->key)) != 0) {
			debug3("hibaext_encode_one_raw: sshbuf_put_cstring returned %d: %s", ret, ssh_err(ret));
			ret = HIBA_INTERNAL_ERROR;
			goto err;
		}
		if ((ret = sshbuf_put_cstring(blob, pair->val)) != 0) {
			debug3("hibaext_encode_one_raw: sshbuf_put_cstring returned %d: %s", ret, ssh_err(ret));
			ret = HIBA_INTERNAL_ERROR;
			goto err;
		}
		++count;
	}

err:
	return ret;
}

static int
hibaext_encode_one_b64(const struct hibaext *ext, struct sshbuf *blob) {
	int ret;
	struct sshbuf *d = sshbuf_new();

	if ((ret = hibaext_encode_one_raw(ext, d)) < 0) {
		debug3("hibaext_encode_one_b64: sshbuf_dtob64 returned %d: %s", ret, hiba_err(ret));
		ret = HIBA_INTERNAL_ERROR;
                goto err;
	}
	if ((ret = sshbuf_dtob64(d, blob, 0)) < 0) {
		debug3("hibaext_encode_one_b64: sshbuf_dtob64 returned %d: %s", ret, ssh_err(ret));
		ret = HIBA_INTERNAL_ERROR;
                goto err;
	}

err:
	sshbuf_free(d);
	return ret;
}

int
hibaext_encode_raw(const struct hibaext **ext, int count, int compress, struct sshbuf *blob) {
	int ret = 0;
	struct sshbuf *one = NULL;
	struct sshbuf *d = blob;

	sshbuf_reset(blob);

	if (ext == NULL || count == 0)
		return HIBA_BAD_PARAMS;
	if (blob == NULL)
		return HIBA_BAD_PARAMS;
	if (ext[0]->type == HIBA_IDENTITY_EXT && count > 1)
		return HIBA_ONE_IDENTITY_ONLY;

	if (compress) {
		d = sshbuf_new();
	}

	/* Single and multiple raw extensions are encoded differently.
	 * See PROTOCOL.extensions. */
	if (count == 1) {
		if ((ret = hibaext_encode_one_raw(ext[0], d)) < 0) {
			debug3("hibaext_encode_raw: hibaext_encode_one_raw returned %d: %s", ret, hiba_err(ret));
			goto err;
		}
	} else {
		int i;

		debug2("hibaext_encode_raw: encode single extension");
		one = sshbuf_new();
		if ((ret = sshbuf_put_u32(d, HIBA_MULTI_EXTS)) < 0) {
			debug3("hibaext_encode_raw: sshbuf_put_u32 returned %d: %s", ret, ssh_err(ret));
			goto err;
		}
		for (i = 0; i < count; ++i) {
			sshbuf_reset(one);
			debug2("hibaext_encode_raw: encode extension %d/%d", i+1, count);
			if ((ret = hibaext_encode_one_raw(ext[i], one)) < 0) {
				debug3("hibaext_encode_raw: hibaext_encode_one_raw returned %d: %s", ret, hiba_err(ret));
				goto err;
			}
			if ((ret = sshbuf_put_stringb(d, one)) < 0) {
				debug3("hibaext_encode_raw: sshbuf_put_stringb returned %d: %s", ret, ssh_err(ret));
				goto err;
			}
		}
	}

err:
	if (compress && ret == 0) {
		ret = hibaext_maybe_deflate(d, compress, blob);
	} else {
		d = NULL;
	}

	sshbuf_free(one);
	sshbuf_free(d);
	return ret;
}

int
hibaext_encode_b64(const struct hibaext **ext, int count, int compress, struct sshbuf *blob) {
	int i;
	int ret = HIBA_OK;
	struct sshbuf *d = blob;

	sshbuf_reset(blob);

	if (ext == NULL || count == 0)
		return HIBA_BAD_PARAMS;
	if (blob == NULL)
		return HIBA_BAD_PARAMS;
	if (ext[0]->type == HIBA_IDENTITY_EXT && count > 1)
		return HIBA_ONE_IDENTITY_ONLY;

	if (compress) {
		d = sshbuf_new();
	}

	/* Base64 extensions are a simple concatenation of single base64 encode
	 * HIBA extensions separated by commas. See PROTOCOL.extensions. */
	for (i = 0; i < count-1; ++i) {
		debug2("hibaext_encode_b64: encode extension %d/%d", i+1, count);
		if ((ret = hibaext_encode_one_b64(ext[i], d)) < 0) {
			debug3("hibaext_encode_b64: hibaext_encode_one_b64 returned %d: %s", ret, hiba_err(ret));
			goto err;
		}
		if ((ret = sshbuf_put_u8(d, ',')) < 0) {
			debug3("hibaext_encode_b64: sshbuf_put_u8 returned %d: %s", ret, ssh_err(ret));
			goto err;
		}
	}
	debug2("hibaext_encode_b64: encode extension %d/%d", i+1, count);
	if ((ret = hibaext_encode_one_b64(ext[i], d)) < 0) {
		debug3("hibaext_encode_b64: last hibaext_encode_one_b64 returned %d: %s", ret, hiba_err(ret));
		goto err;
	}

err:
	if (compress && ret == HIBA_OK) {
		ret = hibaext_maybe_deflate(d, compress, blob);
	} else {
		d = NULL;
	}

	sshbuf_free(d);
        return ret;
}

int hibaext_encode(const struct hibaext *ext, struct sshbuf *blob) {
	const struct hibaext *exts[1] = {ext};
	return hibaext_encode_b64(exts, 1, 0, blob);
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

__inline__ u_int32_t
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

	/* The use of negative matching constraints requires a bump of the
	 * min HIBA version required, to avoid accidental matching on older
	 * hiba-chk binaries. */
	if (key[0] == HIBA_NEGATIVE_MATCHING)
		ext->min_version = HIBA_NEGATIVE_MATCHING_VERSION;

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
			int key_offset = 0;
			int negative_matching = 0;
			if (key[0] == HIBA_NEGATIVE_MATCHING) {
				key_offset = 1;
				negative_matching = 1;
			}

			if (strcmp(key+key_offset, HIBA_KEY_VALIDITY) == 0) {
				char *ok;
				int v = strtol(value, &ok, 0);

				if (negative_matching)
					ret = HIBA_UNEXPECTED_KEY;
				else if (ok == value || *ok != '\0')
					ret = HIBA_GRANT_BADVALIDITY;
				else if (v < 0)
					ret =  HIBA_GRANT_BADVALIDITY;
			} else if (strcmp(key+key_offset, HIBA_KEY_OPTIONS) == 0) {
				size_t i;
				int quoted = 0;
				int dquoted = 0;

				if (negative_matching)
					ret = HIBA_UNEXPECTED_KEY;
				else for (i = 0; i < strlen(value); ++i) {
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
			if (key[0] == HIBA_NEGATIVE_MATCHING)
				ret = HIBA_UNEXPECTED_KEY;
			else if (strcmp(key, HIBA_KEY_HOSTNAME) == 0)
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

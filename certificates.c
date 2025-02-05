/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "extensions.h"
#include "certificates.h"
#include "errors.h"
#include "log.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "ssherr.h"

/* OpenSSH's sshkey_sign function depends on a sshsk_sign function provided by
 * the caller. HIBA doesn't use this symbols but it ends up implicitly imported
 * along with the sshkey_read function. To work around that and make the linker
 * happy, we declare a weak dummy sshsk_sign(). */
#ifndef __CYGWIN__
int  __attribute__((weak))
#else /* __CYGWIN__ */
int
#endif /* __CYGWIN__ */
sshsk_sign() { abort(); return 0; }

struct hibacert {
	struct sshkey *key;
	struct hibaext **exts;
	int nexts;
};

struct hibacert*
hibacert_new() {
	struct hibacert *cert = calloc(1, sizeof(struct hibacert));
	return cert;
}

void
hibacert_free(struct hibacert *cert) {
	int i;

	if (cert == NULL)
		return;

	for (i = 0; i < cert->nexts; ++i)
		hibaext_free(cert->exts[i]);
	sshkey_free(cert->key);
	free(cert->exts);
	free(cert);
}

int
hibacert_from_ext(struct hibacert *cert, struct hibaext *ext,
		const char *principal, u_int64_t validity,
		u_int64_t serial) {
	if (cert == NULL || ext == NULL)
		return HIBA_BAD_PARAMS;

	/* Create a dummy SSH certificate to support standalone HIBA extensions.
	 * The KEY_RSA_CERT type is picked at random and doesn't matter. */
	cert->key = sshkey_new(KEY_RSA_CERT);
	cert->key->cert->serial = serial;
	cert->key->cert->valid_after = validity;
	if (principal != NULL) {
		cert->key->cert->nprincipals = 1;
		cert->key->cert->principals = calloc(1, sizeof(char*));
		cert->key->cert->principals[0] = strdup(principal);
	}
	cert->nexts = 1;
	cert->exts = calloc(1, sizeof(struct hibaext*));
	cert->exts[0] = ext;

	return HIBA_OK;
}

int
hibacert_parse(struct hibacert *cert, struct sshkey *key) {
	int ret = HIBA_OK;
	char *expected_hiba_ext = NULL;
	struct sshbuf *extensions = NULL;

	if (key == NULL || cert == NULL)
		return HIBA_BAD_PARAMS;
	if (!sshkey_is_cert(key))
		return HIBA_BAD_PARAMS;

	cert->key = key;

	if (sshbuf_len(cert->key->cert->extensions) == 0)
		return HIBA_OK;
	if ((extensions = sshbuf_fromb(cert->key->cert->extensions)) == NULL)
		return HIBA_INTERNAL_ERROR;

	/* Look for HIBA extensions. */
	debug2("hibacert_parse: looking for HIBA extensions for cert type %d", cert->key->cert->type);
	if (cert->key->cert->type == SSH2_CERT_TYPE_HOST) {
		expected_hiba_ext = HIBA_IDENTITY_ID;
	} else if (cert->key->cert->type == SSH2_CERT_TYPE_USER) {
		expected_hiba_ext = HIBA_GRANT_ID;
	} else {
		ret = HIBA_BAD_PARAMS;
		goto err;
	}

	while (sshbuf_len(extensions) != 0) {
		size_t len = 0;
		const char *name = NULL;

		if ((ret = sshbuf_get_string_direct(extensions, (const unsigned char**)&name, &len)) < 0) {
			debug3("hibacert_parse: sshbuf_get_string_direct returned %d: %s", ret, ssh_err(ret));
			ret = HIBA_INTERNAL_ERROR;
			goto err;
		}
		debug2("hibacert_parse: found extension %s (%zu) vs %s (%zu)", name, len, expected_hiba_ext, strlen(expected_hiba_ext));

		if (strncmp(name, expected_hiba_ext, len) == 0) {
			struct sshbuf *data;
			struct sshbuf *extension;

			if ((ret = sshbuf_froms(extensions, &extension)) < 0) {
				debug3("hibacert_parse: sshbuf_froms returned %d: %s", ret, ssh_err(ret));
				ret = HIBA_INTERNAL_ERROR;
				goto err;
			}
			if ((ret = sshbuf_froms(extension, &data)) < 0) {
				debug3("hibacert_parse: sshbuf_froms returned %d: %s", ret, ssh_err(ret));
				ret = HIBA_INTERNAL_ERROR;
				goto err;
			}
			if ((cert->nexts = hibaext_decode_all(&cert->exts, data)) < 0) {
				sshbuf_free(data);
				sshbuf_free(extension);
				ret = HIBA_INTERNAL_ERROR;
				goto err;
			}
			sshbuf_free(data);
			sshbuf_free(extension);
		} else {
			sshbuf_skip_string(extensions);
		}
	}

err:
	sshbuf_free(extensions);
	return ret;
}

struct sshkey_cert*
hibacert_cert(const struct hibacert *cert) {
	if (cert == NULL)
		return NULL;
	return cert->key->cert;
}

int
hibacert_hibaexts(const struct hibacert *cert, struct hibaext ***exts, int *len) {
	if (cert == NULL)
		return HIBA_BAD_PARAMS;
	if (exts != NULL)
		*exts = cert->exts;
	if (len != NULL)
		*len = cert->nexts;
	return HIBA_OK;
}


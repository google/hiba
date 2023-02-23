/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "hiba.h"
#include "misc.h"
#include "openbsd-compat/bsd-misc.h"
#include "ssherr.h"
#include "sshkey.h"
#include "xmalloc.h"

void
decode_file(char *file, struct hibacert **outcert, struct hibaext **outext) {
	FILE *f = NULL;
	int ret;
	int direct = 0;
	struct stat st;
	size_t nbytes = 0;
	ssize_t linesize = 0;
	struct sshkey *key = NULL;
	char *line = NULL;

	if (!outcert || !outext)
		return;

	*outcert = NULL;
	*outext = NULL;

	if (strcmp(file, "-") != 0 && stat(file, &st) == -1) {
		if ((errno != ENOENT) && (errno != ENAMETOOLONG)) {
			fatal("decode_file: %s: %s", file, strerror(errno));
		}
		debug2("decode_file: reading from command line");
		linesize = strlen(file);
		line = file;
		direct = 1;
	} else if (strcmp(file, "-") == 0) {
		f = stdin;
	} else if ((f = fopen(file, "r")) == NULL) {
		fatal("decode_file: fopen %s: %s", file, strerror(errno));
	}

	while (direct || (linesize = getline(&line, &nbytes, f)) != -1) {
		char *cp;
		struct sshbuf *d;

		sshkey_free(key);
		key = NULL;

		/* Trim leading space and comments */
		cp = line + strspn(line, " \t");
		linesize -= (cp - line);
		if (*cp == '#' || *cp == '\0')
			continue;
		if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal("decode_file: sshkey_new");
		/* Try to read input as a wrapper base64 key. */
		ret = sshkey_read(key, &cp);
		debug3("decode_file: sshkey_read returned %d: %s", ret, ssh_err(ret));

		if (ret < 0) {
			/* Try to read input as a base64 key blob. */
			d = sshbuf_new();
			if (sshbuf_b64tod(d, cp) == 0) {
				sshkey_free(key);
				ret = sshkey_fromb(d, &key);
				debug3("decode_file: sshkey_fromb returned %d: %s", ret, ssh_err(ret));
			}
			sshbuf_free(d);
		}

		if (ret == 0) {
			/* Maybe a certificate. */
			struct hibacert *cert;

			if (!sshkey_is_cert(key))
				fatal("decode_file: provided file is not a certificate nor a HIBA extension");

			cert = hibacert_new();
			if ((ret = hibacert_parse(cert, key)) < 0)
				fatal("decode_file: failed to decode hiba extension from cert: %s", hiba_err(ret));
			*outcert = cert;
		} else {
			/* Maybe a HIBA extension. */
			struct sshbuf *buf = sshbuf_from(cp, linesize);
			struct hibaext *ext = NULL;

			sshkey_free(key);
			key = NULL;

			ext = hibaext_new();
			if ((ret = hibaext_decode(ext, buf)) < 0)
				fatal("decode_file: failed to decode hiba extension: %s", hiba_err(ret));

			*outext = ext;
			sshbuf_free(buf);
		}

		if (direct) {
			line = NULL;
			break;
		}
	}
	if (f)
		fclose(f);
	free(line);
}

#define CHUNK_SZ 1024

void
open_grl(const char *file, unsigned char **ptr, u_int64_t *sz, int *mmapped) {
	int f;
	struct stat st;

	if (!file || !sz || !ptr || !mmapped)
		return;

	*sz = 0;
	*ptr = NULL;
	*mmapped = 0;

	if (strcmp(file, "-") != 0 && stat(file, &st) == -1) {
		debug3("open_grl: %s: %s", file, strerror(errno));
		return;
	} else if (strcmp(file, "-") == 0) {
		while (1) {
			*ptr = xreallocarray(*ptr, *sz + CHUNK_SZ, sizeof(char));
			*sz += fread(*ptr + *sz, 1, CHUNK_SZ, stdin);
			if (ferror(stdin)) {
				fatal("open_grl: read stdin: %s", strerror(errno));
			} else if (feof(stdin) != 0) {
				return;
			}
		}
	} else if ((f = open(file, O_RDONLY)) < 0) {
		fatal("open_grl: open %s: %s", file, strerror(errno));
	}

	*ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, f, 0);
	*mmapped = 1;
	*sz = st.st_size;

	close(f);
}

void
close_grl(unsigned char *ptr, u_int64_t sz, int mmapped) {
	if (mmapped) {
		munmap(ptr, sz);
	} else {
		free(ptr);
	}
}

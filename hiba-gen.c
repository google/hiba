/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "hiba.h"
#include "misc.h"
#include "openbsd-compat/bsd-misc.h"
#include "ssherr.h"
#include "sshkey.h"
#include "util.h"

void
usage() {
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  Encode extensions (default to 'grant'):\n");
	fprintf(stderr, "    hiba-gen -f output.ext key1 value1 key2 value2 ...\n");
	fprintf(stderr, "    hiba-gen -i -f output.ext key1 value1 key2 value2 ...\n");
	fprintf(stderr, "  Decode extensions:\n");
	fprintf(stderr, "    hiba-gen -d -f input.ext\n");
	fprintf(stderr, "    hiba-gen -d -f certificate\n");
	exit(1);
}

void
print_hiba(const struct hibaext *ext) {
	const char *id;
	u_int32_t i;
	u_int32_t version;

	id = hibaext_id(ext);
	hibaext_versions(ext, &version, NULL);
	printf("%s (v%d):\n", id, version);
	for (i = 0; i < hibaext_pairs_len(ext); ++i) {
		int ret;
		char *key;
		char *value;
		if ((ret = hibaext_key_value_at(ext, i, &key, &value)) < 0)
			printf(" [%d] error: %s\n", i, hiba_err(ret));
		else
			printf(" [%d] %s = '%s'\n", i, key, value);
		free(key);
		free(value);
	}
}

void
handle_cert(struct hibacert *cert) {
	int i;
	int len;
	int ret;
	char *keyid;
	struct hibaext **exts;

	if ((ret = hibacert_hibaexts(cert, &exts, &len)) < 0)
		fatal("decode_cert: failed to fetch extension: %s", hiba_err(ret));

	keyid = hibacert_cert(cert)->key_id;
	printf("certificate '%s' contains %d HIBA grants\n", keyid, len);
	for (i = 0; i < len; ++i)
		print_hiba(exts[i]);

}

void
handle_ext(struct hibaext *ext) {
	print_hiba(ext);
}

void
encode_ext(const char *file, int type, int argc, char **argv) {
	int i;
	int ret;
	struct sshbuf *buf = NULL;
	struct hibaext *ext = NULL;

	verbose("encode_ext: %s", file);

	ext = hibaext_new();
	if ((ret = hibaext_init(ext, type)) < 0)
		fatal("encode_ext: failed to initialize hiba grant extension: %s", hiba_err(ret));

	if ((argc % 2) != 0)
		fatal("encode_ext: hiba requires key/value pairs");

	for (i = 0; i < argc; i+=2) {
		const char *key = argv[i];
		const char *value = argv[i+1];

		if ((ret = hibaext_add_pair(ext, key, value)) < 0)
			fatal("encode_ext: failed to add key %s to hiba grant extension: %s", key, hiba_err(ret));
	}

	buf = sshbuf_new();
	if ((ret = hibaext_encode(ext, buf)) < 0)
		fatal("encode_ext: failed to encode hiba grant extension: %s", hiba_err(ret));

	if ((ret = sshbuf_write_file(file, buf)) < 0)
		fatal("encode_ext: failed to write file: %s", ssh_err(ret));

	sshbuf_free(buf);
	hibaext_free(ext);
}

int
main(int argc, char **argv) {
	extern int optind;
	extern char *optarg;

	int debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	int opt;
	int decode = 0;
	int type = HIBA_GRANT_EXT;
	char *file = NULL;

	char *__progname = ssh_get_progname(argv[0]);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	if (argc <= 1)
		usage();

	while ((opt = getopt(argc, argv, "vdif:")) != -1) {
		switch (opt) {
		case 'v':
			if (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			else if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			else
				fatal("Too high debugging level.");
			break;
		case 'd':
			decode = 1;
			break;
		case 'i':
			type = HIBA_IDENTITY_EXT;
			break;
		case 'f':
			file = optarg;
			break;
		case '?':
		default:
			usage();
		}
	}
	argv += optind;
	argc -= optind;

	log_init("hiba-gen", log_level, SYSLOG_FACILITY_USER, 1);

	__progname = ssh_get_progname(argv[0]);
	if (debug_flag)
		verbose("%s: starting in debug mode", __progname);

	if (file == NULL)
		fatal("%s: missing hiba extension --file", __progname);
	free(__progname);

	if (decode == 1) {
		struct hibacert *cert;
		struct hibaext *ext;

		decode_file(file, &cert, &ext);
		if (cert != NULL) {
			handle_cert(cert);
			hibacert_free(cert);
		} else if (ext != NULL) {
			handle_ext(ext);
			hibaext_free(ext);
		}
	} else {
		encode_ext(file, type, argc, argv);
	}

	return 0;
}

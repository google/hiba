/*
 * Copyright 2022 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define HIBA_INTERNAL

#include "log.h"
#include "hiba.h"
#include "misc.h"
#include "openbsd-compat/bsd-misc.h"
#include "util.h"

void
usage() {
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  Revoke grants for the given serial:\n");
	fprintf(stderr, "    hiba-grl -f <file> -r -s <serial> [<id1> <id2> ...]\n");
	fprintf(stderr, "  Check grants for the given serial:\n");
	fprintf(stderr, "    hiba-grl -f <file> -c -s <serial> [<id1> <id2> ...]\n");
	fprintf(stderr, "  Dump current GRL in human readable form:\n");
	fprintf(stderr, "    hiba-grl -f <file> -d [-s <serial>]\n");
	exit(1);
}

static void do_revoke(struct hibagrl *grl, u_int64_t *serial, char *file, int argc, char **argv) {
	int i;
	int ret;
	struct sshbuf *blob;

	if (!serial) {
		fatal("do_revoke: missing serial");
	}
	if (argc == 0) {
		fatal("do_revoke: missing grant IDs");
	}

	/* perform revocations. */
	for (i = 0; i < argc; ++i) {
		char *err;
		u_int64_t id = strtoul(argv[i], &err, 0);
		if (*err != '\0')
			fatal("do_revoke: invalid grant ID %" PRIu64 ": %s", id, err);
		hibagrl_revoke_grant(grl, *serial, id, id);
	}

	/* Write back. */
	blob = sshbuf_new();
	if ((ret = hibagrl_encode(grl, blob)) < 0) {
		fatal("do_revoke: failed to serialize GRL: %s", hiba_err(ret));
	}

	if ((ret = sshbuf_write_file(file, blob)) < 0) {
                fatal("do_revoke: failed to write file: %s", ssh_err(ret));
	}
	sshbuf_free(blob);
	debug("do_revoke: wrote %s", file);
}

static int do_test(struct hibagrl *grl, u_int64_t *serial, int argc, char **argv) {
	int i;
	int revoked = 0;

	if (!serial) {
		fatal("do_test: missing serial");
	}
	if (argc == 0) {
		fatal("do_test: missing grant IDs");
	}

	/* Test. */
	for (i = 0; i < argc; ++i) {
		int ret;
		char *err;
		u_int64_t id = strtoul(argv[i], &err, 0);
		if (*err != '\0')
			fatal("do_revoke: invalid grant ID %" PRIu64 ": %s", id, err);
		ret = hibagrl_check(grl, *serial, id);
		if (ret == HIBA_CHECK_REVOKED) {
			++revoked;
			printf("[%.16" PRIX64 "]: %" PRIu64 " Revoked\n", *serial, id);
		} else {
			printf("[%.16" PRIX64 "]: %" PRIu64 " Valid\n", *serial, id);
		}
	}

	return revoked;
}

static void do_dump(struct hibagrl *grl, u_int64_t *serial, int argc, char **argv) {
	fprintf(stdout, "HIBA GRL (v%d):\n", hibagrl_version(grl));
	fprintf(stdout, "  comment: %s\n", hibagrl_comment(grl));
	fprintf(stdout, "  timestamp: %" PRIu64 "\n", hibagrl_timestamp(grl));
	fprintf(stdout, "  entries: %" PRIu64 "\n", hibagrl_serials_count(grl));
	hibagrl_dump_content(grl, serial, stdout);
}

#define NONE -1
#define DUMP 0
#define REVOKE 1
#define TEST 2

int
main(int argc, char **argv) {
	extern int optind;
	extern char *optarg;

	int opt;
	int ret = HIBA_OK;
	int action = NONE;
	int debug_flag = 0;
	int use_syslog = 0;
	int log_level = SYSLOG_LEVEL_INFO;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	u_int64_t s = 0;
	u_int64_t *serial = NULL;
	char *err;
	char *grl_file = NULL;
	char *comment = "Generated using hiba-grl";
	char *__progname = ssh_get_progname(argv[0]);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	while ((opt = getopt(argc, argv, "yvrdtf:s:c:l:")) != -1) {
		switch (opt) {
		case 'y':
			use_syslog = 1;
			break;
		case 'v':
			if (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			} else if (log_level < SYSLOG_LEVEL_DEBUG3) {
				log_level++;
			} else {
				fatal("Too high debugging level.");
			}
			break;
		case 'd':
			action = DUMP;
			break;
		case 'r':
			action = REVOKE;
			break;
		case 't':
			action = TEST;
			break;
		case 'f':
			grl_file = optarg;
			break;
		case 'c':
			comment = optarg;
			break;
		case 's':
			s = strtoul(optarg, &err, 0);
			serial = &s;
			if (*err != '\0')
				fatal("%s: invalid serial %" PRIu64 ": %s", __progname, s, err);
			break;
		case 'l':
			log_facility = log_facility_number(optarg);
			if (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			break;
		case '?':
		default:
			usage();
		}
	}

	argv += optind;
	argc -= optind;

	log_init("hiba-grl", log_level, log_facility, !use_syslog);

	if (debug_flag)
		debug2("%s: starting in debug mode", __progname);

	if (action == NONE)
		fatal("%s: missing action (-r|-d|-t)", __progname);
	if (grl_file == NULL)
		fatal("%s: missing GRL file path", __progname);

	{
		int mmapped;
		unsigned char *ptr;
		u_int64_t size;
		struct sshbuf *blob;
		struct hibagrl *grl = hibagrl_new();

		open_grl(grl_file, &ptr, &size, &mmapped);
		if (ptr == NULL) {
			if (action == TEST) {
				fatal("%s: GRL file doesn't exist: %s", __progname, grl_file);
			}
			debug("%s: Creating a new GRL file", __progname);
			hibagrl_init(grl, comment);
		} else {
			debug("%s: Loading an existing GRL file", __progname);
			blob = sshbuf_from(ptr, size);
			if ((ret = hibagrl_decode(grl, blob)) < 0) {
				fatal("%s: hibagrl_decode failed: %s", __progname, hiba_err(ret));
			}
			sshbuf_free(blob);
			if (action != TEST) {
				if ((ret = hibagrl_map(grl)) < 0) {
					fatal("%s: hibagrl_map failed: %s", __progname, hiba_err(ret));
				}
			}
		}

		if (action == DUMP) {
			do_dump(grl, serial, argc, argv);
		} else if (action == REVOKE) {
			do_revoke(grl, serial, grl_file, argc, argv);
		} else if (action == TEST) {
			ret = do_test(grl, serial, argc, argv);
		}

		hibagrl_free(grl);
		close_grl(ptr, size, mmapped);
	}
	free(__progname);

	return -ret;
}

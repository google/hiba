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
	fprintf(stderr, "  With certificates\n");
	fprintf(stderr, "    hiba-chk -i <identity> -r <role> -g <grl_path> certificate\n");
	fprintf(stderr, "  With grants\n");
	fprintf(stderr, "    hiba-chk -i <identity> -r <role> -g <grl_path> -p principal grant\n");
	exit(1);
}

int
check_access(const struct hibaenv *env, const struct hibacert *cert, const char *role) {
	int i;
	int ret;
	int len;
	int verdict = HIBA_CHECK_NOGRANTS;
	struct hibaext **grants;

	if ((ret = hibacert_hibaexts(cert, &grants, &len)) < 0)
		fatal("check_access: can't get grants from certificate: %s", hiba_err(ret));

	debug2("Testing %d grants", len);
	for (i = 0; i < len; ++i) {
		verbose("check_access: checking grant %d.", i);
		if ((ret = hibachk_authorize(env, grants[i], role)) == HIBA_OK) {
			verdict = 0;
			hibachk_authorized_users(env, cert, i, stdout);
		} else {
			if (verdict != 0)
				verdict = ret;
			verbose("check_access: denied: %s", hiba_err(ret));
		}
	}

	return verdict;
}

int
main(int argc, char **argv) {
	extern int optind;
	extern char *optarg;
	
	int opt;
	int ret;
	int debug_flag = 0;
	int log_level = SYSLOG_LEVEL_INFO;
	char *grl_file = NULL;
	char *principal = NULL;
	char *identity_file = NULL;
	char *role = NULL;
	struct hibacert *host;
	struct hibacert *user;
	struct hibaext *identity;
	struct hibaext *grant;
	char *__progname = ssh_get_progname(argv[0]);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	while ((opt = getopt(argc, argv, "vr:i:g:p:")) != -1) {
		switch (opt) {
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
		case 'r':
			role = optarg;
			break;
		case 'g':
			grl_file = optarg;
			break;
		case 'i':
			identity_file = optarg;
			break;
		case 'p':
			principal = optarg;
			break;
		case '?':
		default:
			usage();
		}
	}

	argv += optind;
	argc -= optind;

	log_init("hiba-chk", log_level, SYSLOG_FACILITY_USER, 1);

	if (debug_flag)
		debug2("%s: starting in debug mode", __progname);

	if (argc < 1) {
		error("%s: missing certificate/grant", __progname);
		usage();
	} else if (argc > 1) {
		error("%s: extra argument in command line", __progname);
		usage();
	}
	if (role == NULL)
		fatal("%s: missing role", __progname);
	if (identity_file == NULL)
		fatal("%s: missing host identity ", __progname);

	
	decode_file(identity_file, &host, &identity);
	decode_file(argv[0], &user, &grant);

	{
		struct hibaenv *env;

		if (host == NULL) {
			host = hibacert_new();
			if ((ret = hibacert_from_ext(host, identity, principal, 0, 42)) < 0)
				fatal("%s: creating host certificate from extension: %s", __progname, hiba_err(ret));
			identity = NULL;
		}
		if (user == NULL) {
			user = hibacert_new();
			if ((ret = hibacert_from_ext(user, grant, principal, time(NULL), 42)) < 0)
				fatal("%s: creating user certificate from extension: %s", __progname, hiba_err(ret));
			grant = NULL;
		}

		env = hibaenv_from_host(host, grl_file);
		ret = check_access(env, user, role);
		hibaenv_free(env);
	}

	hibacert_free(host);
	hibacert_free(user);
	hibaext_free(identity);
	hibaext_free(grant);

	free(__progname);

	return -ret;
}

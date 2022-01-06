/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#ifndef _CHECKS_H
#define _CHECKS_H

#include <stdint.h>

#include "certificates.h"
#include "extensions.h"
#include "revocations.h"

struct hibaenv;

/* Check whether the grant extension authorized access to the target
 * environment.
 * The `idx` parameter represents the position of the grant in the certificate,
 * used for the GRL check. */
int hibachk_authorize(const struct hibaenv *env, const struct hibaext *grant,
                      u_int32_t idx, const char *role);

/* Output the dynamically generated authorized_users.
 * The output will be generated for the 'idx'th grant of the given 'cert'
 * certificate. */
void hibachk_authorized_users(const struct hibaenv *env,
                              const struct hibacert *cert, int idx, FILE *f);

/* Create an environment from a host certificate with a HIBA identity grant
 * Resulting struct hibaenv must be released using hibaenv_free(). */
struct hibaenv *hibaenv_from_host(const struct hibacert *host, const struct hibagrl *grl);

/* Destructor for hibaenv. */
void hibaenv_free(struct hibaenv *env);

#endif  // _CHECKS_H

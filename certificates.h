/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#ifndef _CERTIFICATES_H
#define _CERTIFICATES_H

#include <stdint.h>

#include "extensions.h"
#include "sshkey.h"

struct hibacert;

/* Creator for hibacert.
 * Result must be freed with hibacert_free. */
struct hibacert *hibacert_new();

/* Destructor for hibacert */
void hibacert_free(struct hibacert *cert);

/* Parse HIBA extensions out of a SSH certificate passed a sshkey.
 * The struct hibacert must already be allocated and the sshkey
 * will be owned by the hibacert. */
int hibacert_parse(struct hibacert *cert, struct sshkey *key);

/* Return a pointer to the sshkey_cert contained by the hibacert.
 * The ownership remains in the hibacert. */
struct sshkey_cert *hibacert_cert(const struct hibacert *cert);

/* Return a pointer to an array of hibaexts contained in the hibacert.
 * The array's ownership remains in the hibacert. */
int hibacert_hibaexts(const struct hibacert *cert, struct hibaext ***exts,
                      int *len);

#ifdef HIBA_INTERNAL
/* Construct a hiba certificate from an extension.
 * The struct hibacert must already be allocated and the hibaext
 * will be owned by the hibacert; */
int hibacert_from_ext(struct hibacert *cert, struct hibaext *ext,
                      const char *principal, u_int64_t validity,
                      u_int64_t serial);
#endif  /* HIBA_INTERNAL */

#endif  /* _CERTIFICATES_H */

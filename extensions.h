/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#ifndef _EXTENSIONS_H
#define _EXTENSIONS_H

#include <sys/types.h>

#include "sshbuf.h"

/* HIBA extensions magic header. */
#define HIBA_MAGIC 0x48494241

/* HIBA extension types. */
#define HIBA_IDENTITY_EXT 'i'
#define HIBA_GRANT_EXT 'g'

/* HIBA Extensions IDs. */
#define HIBA_IDENTITY_ID "identity@hibassh.dev"
#define HIBA_GRANT_ID "grant@hibassh.dev"

/* HIBA pre defined options. */
#define HIBA_KEY_DOMAIN "domain"
#define HIBA_KEY_ROLE "role"
#define HIBA_KEY_VALIDITY "validity"
#define HIBA_KEY_HOSTNAME "hostname"
#define HIBA_KEY_OPTIONS "options"

/* HIBA extension type. */
struct hibaext;

/* Constructor for hibaext.
 * Result must be freed with hibaext_free. */
struct hibaext *hibaext_new();

/* Init a new hibaext for a given type (grant or identity).
 * The hibaext must already be allocated. */
int hibaext_init(struct hibaext *ext, int type);

/* Destructor for hibaext.
 * This releases all the memory used by the key/pairs as well as the extension
 * structure itself.  */
void hibaext_free(struct hibaext *ext);

/* Decode a serialized HIBA extension contained into a manageable object.
 * The struct hibaext must be already allocated.
 * The sshbuf will be consumed. */
int hibaext_decode(struct hibaext *ext, struct sshbuf *blob);

/* Encode a HIBA extension into a serialized blob to be included in a
 * certificate. blob must be already allocated. */
int hibaext_encode(const struct hibaext *ext, struct sshbuf *blob);

/* Sanity check a HIBA extension.
 * This verifies the following
 * - extension type is known
 * - extension contains the required 'domain' key/pair
 * - if the extension type is identity, it doesn't contain reserved keys
 *   (validity, hostname, role, options).
 * - if the 'validity' key is set, it must be an integer greated than 0.
 * - identity extensions don't have duplicate keys
 * - if the 'options' key is set, it must not contain \n or unquoted
 *   whitespaces, and open quotes must be closed.
 */
int hibaext_sanity_check(const struct hibaext *ext);

/* Return the extension ID corresponding to the type:
 * "grant@hibassh.dev"
 * "identity@hibassh.dev" */
const char *hibaext_id(const struct hibaext *ext);

/* Return the extension type. */
u_int32_t hibaext_type(const struct hibaext *ext);

/* Return the extension version and minimum supported version. */
int hibaext_versions(const struct hibaext *ext, u_int32_t *vers,
                     u_int32_t *min_vers);

/* Return the number of key value pairs attached to the hibaext. */
u_int32_t hibaext_pairs_len(const struct hibaext *ext);

/* Return the key and value stored at a given position.
 * If the requested position is out of the key/pair list bounds, HIBA_BAD_PARAMS
 * is returned.
 * Both the returned key and value must be freed. */
int hibaext_key_value_at(const struct hibaext *ext, u_int32_t position,
                         char **key, char **value);

/* Return the value for a given key in an identity extension.
 * This function doesn't apply to extensions with type grant as they can have
 * multiple values with the same key. For grants please use the
 * hibaext_key_value_at() function instead.
 * If the requested key doesn't exist, HIBA_EXT_NOKEY is returned.
 * The returned value must be freed. */
int hibaext_value_for_key(const struct hibaext *ext, const char *key,
                          char **value);

/* Add a key value pair to the hibaext.
 * If the key already exists, HIBA_PAIR_EXISTS is returned. */
int hibaext_add_pair(struct hibaext *ext, const char *key, const char *value);

/* Update an existing key value pair attached to the hibaext. */
int hibaext_update_pair(struct hibaext *ext, const char *key,
                        const char *value);

#endif /* _EXTENSIONS_H */

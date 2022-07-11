/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#ifndef _UTIL_H
#define _UTIL_H

#include <sys/types.h>

/* Swiss army knife function for decoding input of hiba-* tools.
 * It supports:
 * - wrapped base64 SSH certificate
 * - base64 SSH certificate blob
 * - base64 HIBA extensions
 * - binary HIBA extensions
 *
 * The input can be provided as a filename, from stdin (using the special value
 * '-') or directly as a command line argument.
 */
void decode_file(char *file, struct hibacert **cert, struct hibaext **ext);

/* Open a GRL.
 * The file will be mmapped to memory if possible. Resources must be released
 * using the close_grl() function to properly free / munmap data.
 *
 * The input can be provided as a filename or from stdin (using the special
 * value '-').
 */
void open_grl(const char *file, unsigned char **ptr, u_int64_t *sz, int *mmapped);

/* Release resources allocated by open_grl. */
void close_grl(unsigned char *ptr, u_int64_t sz, int mmapped);

#endif  // _UTIL_H

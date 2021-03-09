/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#ifndef _UTIL_H
#define _UTIL_H

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

#endif  // _UTIL_H

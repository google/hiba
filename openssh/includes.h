/*
 * Copyright 2021 The HIBA Authors
 *
 * Wrapper to openssh headers.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#ifndef _OPENSSH_WRAPPER_INCLUDES_H
#define _OPENSSH_WRAPPER_INCLUDES_H

#include <includes.h>

/*
 * The includes header indirectly includes the config.h file from the OpenSSH
 * project which conflicts/overrides HIBA's config.h
 */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION

#endif  /* _OPENSSH_WRAPPER_INCLUDES_H */

# Copyright (c) 2020 The HIBA Authors All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
m4_define([MAJOR], 1)
m4_define([MINOR], 0)

AC_PREREQ([2.69])
AC_INIT([HIBA], [MAJOR.MINOR], [hibassh@google.com])
AC_CONFIG_SRCDIR([hiba.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_LANG([C])

LT_INIT

# Values for SONAME. See -version-info for details.
AC_SUBST(SONAME_CURRENT, 0)
AC_SUBST(SONAME_REVISION, 0)
AC_SUBST(SONAME_AGE, 0)

# Checks for openssh sources
AC_ARG_WITH([opensshdir],
  [AS_HELP_STRING([--with-opensshdir=DIR], [openssh source directory])],
  [opensshdir=$withval],
  [AC_MSG_ERROR([unable to find the openssh library])])
AC_SUBST([opensshdir], [$opensshdir])

# Check for openssh use of openssl
AC_MSG_CHECKING(whether OpenSSH is configured with OpenSSL)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
    #include "$opensshdir/config.h"
  ], [
    #ifdef WITH_OPENSSL
    #if WITH_OPENSSL != 0
    #error 1
    #endif
    #endif
  ])],
  [need_openssl=false; AC_MSG_RESULT([no])],
  [need_openssl=true; AC_MSG_RESULT([yes])])
AC_SUBST([need_openssl])

# Checks for libraries.
AM_CONDITIONAL([NEED_OPENSSL], [test "x$need_openssl" = xtrue])
AM_COND_IF([NEED_OPENSSL], [
    AC_SEARCH_LIBS([RAND_add], [crypto], [], [AC_MSG_ERROR([unable to find the openssl library])])
  ], [])


# Checks for header files.
AC_CHECK_HEADERS([inttypes.h limits.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostname memset strdup strerror strspn strtol])

AM_INIT_AUTOMAKE([foreign no-dependencies])
AM_SILENT_RULES([yes])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
AC_MSG_NOTICE([/!\ Make sure to build openssh before building HIBA.])


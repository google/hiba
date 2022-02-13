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
AC_PROG_CC([cc gcc clang])

LT_INIT

# Values for SONAME. See -version-info for details.
AC_SUBST(SONAME_CURRENT, 0)
AC_SUBST(SONAME_REVISION, 0)
AC_SUBST(SONAME_AGE, 0)

save_cflags="$CFLAGS"
save_ldflags="$LDFLAGS"

# Check for required CFLAGS availability
AC_MSG_CHECKING(whether compiler supports hardening options)
CFLAGS="$CFLAGS -Wa,--noexecstack"
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM()],
  [hardening_cflags="$hardening_cflags -Wa,--noexecstack"; AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])])
CFLAGS="$save_cflags"

AC_MSG_CHECKING(whether compiler supports ASLR)
CFLAGS="$CFLAGS -fPIE"
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM()],
  [hardening_cflags="$hardening_cflags -fPIE"; AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])])
CFLAGS="$save_cflags"

AC_SUBST([hardening_cflags], [$hardening_cflags])

# Check for required LDFLAGS availability
AC_MSG_CHECKING(whether linker supports hardening options)
LDFLAGS="$LDFLAGS -Wl,-z,relro,-z,now"
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM()],
  [hardening_ldflags="$hardening_ldflags -Wl,-z,relro,-z,now"; AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])])
LDFLAGS="$save_ldflags"

AC_MSG_CHECKING(whether linker supports ASLR)
LDFLAGS="$LDFLAGS -pie"
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM()],
  [hardening_ldflags="$hardening_ldflags -pie"; AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])])
LDFLAGS="$save_ldflags"

AC_SUBST([hardening_ldflags], [$hardening_ldflags])

# Check for definition of max hostname length
AC_CHECK_DECL([HOST_NAME_MAX], [
  ], [
    AC_DEFINE([HOST_NAME_MAX], [64], [Maximum supported hostname size if not already defined by OS.])
  ], [#include <limits.h>])

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

# We can't generate dynamic libraries on cygwin since openssh only builds a static libssh.
case "$host" in
*-*-cygwin*)
  AS_VAR_IF([enable_shared], [yes],
	    [AC_DISABLE_SHARED AC_MSG_WARN([Only static libraries can be buit using cygwin])],
	    [])
  ;;
esac

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
AC_MSG_NOTICE([/!\ Make sure to configure and build OpenSSH before HIBA.])


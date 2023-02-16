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

AM_INIT_AUTOMAKE([foreign no-dependencies])
AM_SILENT_RULES([yes])

# Values for SONAME. See -version-info for details.
AC_SUBST(SONAME_CURRENT, 0)
AC_SUBST(SONAME_REVISION, 0)
AC_SUBST(SONAME_AGE, 0)

save_CFLAGS="$CFLAGS"
save_CPPFLAGS="$CPPFLAGS"
save_LDFLAGS="$LDFLAGS"
save_LIBS="$LIBS"

# Check for required CFLAGS & CPPFLAGS availability
for f in -fstack-protector-strong -fstack-protector-all -fstack-protector; do
	AC_MSG_CHECKING(whether $CC supports $f options)
	CFLAGS="$CFLAGS $extra_CFLAGS $f -Werror"
	LDFLAGS="$LDFLAGS $extra_LDFLAGS $f"
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM()], [
			extra_LDFLAGS="$extra_LDFLAGS $f"
			extra_CFLAGS="$extra_CFLAGS $f"
			AC_MSG_RESULT([yes])
			break
		], [AC_MSG_RESULT([no])],
	)
	# Restore CFLAGS & LDFLAGS in the loop as options are exclusive.
	LDFLAGS="$save_LDFLAGS"
	CFLAGS="$save_CFLAGS"
done

for f in -fpie -fPIE -fpic -fPIC; do
	AC_MSG_CHECKING(whether compiler supports $f)
	CFLAGS="$CFLAGS $extra_CFLAGS $f -Werror"
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM()], [
			extra_CFLAGS="$extra_CFLAGS $f"
			AC_MSG_RESULT([yes])
			break
		], [AC_MSG_RESULT([no])],
	)
	# Restore CFLAGS in the loop as options are exclusive.
	CFLAGS="$save_CFLAGS"
done

for f in -ansi -Wall -Wextra -Werror -Wno-attributes -Wno-unused-parameter -Wformat-security -Wuninitialized; do
	AC_MSG_CHECKING(whether $CC supports $f options)
	CFLAGS="$CFLAGS $extra_CFLAGS $f"
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM()], [
			extra_CFLAGS="$extra_CFLAGS $f"
			AC_MSG_RESULT([yes])
		], [AC_MSG_RESULT([no])],
	)
done
CFLAGS="$save_CFLAGS"

AC_MSG_CHECKING(whether preprocessor supports _DEFAULT_SOURCE)
CPPFLAGS="$CPPFLAGS $extra_CPPFLAGS -D_DEFAULT_SOURCE"
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM()], [
		extra_CPPFLAGS="$extra_CPPFLAGS -D_DEFAULT_SOURCE"
		AC_MSG_RESULT([yes])
	], [AC_MSG_ERROR([no])],
)
CPPFLAGS="$save_CPPFLAGS"

AC_MSG_CHECKING(whether preprocessor supports _FORTIFY_SOURCE)
CPPFLAGS="$CPPFLAGS $extra_CPPFLAGS -D_FORTIFY_SOURCE=2"
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM()], [
		extra_CPPFLAGS="$extra_CPPFLAGS -D_FORTIFY_SOURCE=2"
		AC_MSG_RESULT([yes])
	], [AC_MSG_RESULT([no])],
)
CPPFLAGS="$save_CPPFLAGS"

AC_MSG_CHECKING(whether compiler supports no-strict-aliasing option)
CFLAGS="$CFLAGS $extra_CFLAGS -fno-strict-aliasing -Werror"
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM()], [
		extra_CFLAGS="$extra_CFLAGS -fno-strict-aliasing"
		AC_MSG_RESULT([yes])
	], [AC_MSG_RESULT([no])],
)
CFLAGS="$save_CFLAGS"

AC_MSG_CHECKING(whether compiler supports hardening options)
CFLAGS="$CFLAGS $extra_CFLAGS -Wa,--noexecstack -Werror"
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM()], [
		extra_CFLAGS="$extra_CFLAGS -Wa,--noexecstack"
		AC_MSG_RESULT([yes])
	], [AC_MSG_RESULT([no])],
)
CFLAGS="$save_CFLAGS"

# Check for required LDFLAGS availability
AC_MSG_CHECKING(whether linker supports hardening options)
LDFLAGS="$LDFLAGS $extra_LDFLAGS -Wl,-z,relro,-z,now"
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM()], [
		extra_LDFLAGS="$extra_LDFLAGS -Wl,-z,relro,-z,now"
		AC_MSG_RESULT([yes])
	], [AC_MSG_RESULT([no])],
)
LDFLAGS="$save_LDFLAGS"

# Check for definition of max hostname length
AC_CHECK_DECL(
	[HOST_NAME_MAX], [], [AC_DEFINE([HOST_NAME_MAX], [64], [
		Maximum supported hostname size if not already defined by OS.
	])], [#include <limits.h>],
)

# Update flags.
CFLAGS="$CFLAGS $extra_CFLAGS"
CPPFLAGS="$CPPFLAGS $extra_CPPFLAGS"
LDFLAGS="$LDFLAGS $extra_LDFLAGS"

# We can't generate dynamic libraries on cygwin since openssh only builds a static libssh.
case "$host" in
*-*-cygwin*)
	AS_VAR_IF([enable_shared], [yes], [
		AC_DISABLE_SHARED AC_MSG_WARN([Only static libraries can be buit using cygwin])
		], [],
	)
  ;;
esac

# Checks for OpenSSH sources
AC_ARG_WITH(
	[opensshdir], [AS_HELP_STRING(
		[--with-opensshdir=DIR], [OpenSSH source directory],
	)], [opensshdir=$withval], [AC_MSG_ERROR([
		unable to find the OpenSSH sources. Set --with-opensshdir=<path to OpenSSH sources>
	])],
)

# Update flags with OpenSSH location
CFLAGS="$CFLAGS -I$opensshdir"
LDFLAGS="$LDFLAGS -L$opensshdir -L$opensshdir/openbsd-compat"

# Check for OpenSSH use of OpenSSL
AC_MSG_CHECKING(whether OpenSSH is configured with OpenSSL)
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([
		#include "$opensshdir/config.h"
	], [
		#ifdef WITH_OPENSSL
		#if WITH_OPENSSL != 0
		#error 1
		#endif
		#endif
	])], [
		need_openssl=false
		AC_MSG_RESULT([no])
	], [
		need_openssl=true
		AC_MSG_RESULT([yes])
	],
)
AM_CONDITIONAL([NEED_OPENSSL], [test "x$need_openssl" = xtrue])

# Checks for optional OpenSSL sources
AC_ARG_WITH(
	[openssldir], [AS_HELP_STRING(
		[--with-openssldir=DIR], [OpenSSL source directory],
	)], [openssldir=$withval], [],
)
AM_CONDITIONAL([OPENSSLDIR], [test "x$openssldir" != x])

# Maybe checks for OpenSSL library.
# First in openssldir if provided, then in sysroot.
AM_COND_IF(
	[NEED_OPENSSL], [
		# Check whether user specified a custom location:
		AC_MSG_CHECKING(whether custom OpenSSL folder is set)
		AM_COND_IF(
			[OPENSSLDIR], [
				CFLAGS="$CFLAGS -I$openssldir/include"
				LDFLAGS="$LDFLAGS -L$openssldir"
				AC_MSG_RESULT(yes)
			], [
				AC_MSG_RESULT(no)
			],
		)
		# In case of static libcrypto, we need explicit linking.
		AC_MSG_CHECKING(whether OpenSSL requires explicit linking)
		for l in '' '-ldl' '-lpthread' '-ldl -lpthread'; do
			LIBS="-lcrypto $l"
			AC_LINK_IFELSE(
				[AC_LANG_CALL([], [RSA_new])], [
					libcrypto_LIBS=$l
					break
				], [],
			)
		done
		LIBS="$save_LIBS"

		if test "x$libcrypto_LIBS" = x; then
			AC_MSG_RESULT(no)
		else
			AC_MSG_RESULT($libcrypto_LIBS)
		fi

		# Add the OpenSSL library.
		AC_SEARCH_LIBS(
			[RSA_new], [crypto], [], [
				AC_MSG_ERROR([unable to find a working OpenSSL library])
			], [$libcrypto_LIBS])
		LIBS="$LIBS $libcrypto_LIBS"
	], [],
)

# Checks for Zlib library
AC_ARG_ENABLE(
	[extension-compression], [AS_HELP_STRING(
		[--enable-extension-compression], [enable extension compression support],
	)], [zlib=$enableval], [zlib=yes])
AM_CONDITIONAL([WANT_ZLIB], [test "x$zlib" = xyes])

AC_ARG_WITH(
	[zlibdir], [AS_HELP_STRING(
		[--with-zlibdir=DIR], [path to source directory],
	)], [zlibdir=$withval], [zlibdir=])
AM_CONDITIONAL([CUSTOM_ZLIB], [test "x$zlibdir" != x])

# If we want Zlib, we need to sources and libraries available
AC_MSG_CHECKING(for compressed extensions support)
AM_COND_IF(
	[WANT_ZLIB], [
		AC_DEFINE([WITH_EXTENSION_COMPRESSION], [1], [
			Define to 1 if you have support for extension compression.
		])
		AC_MSG_RESULT(yes)
		AM_COND_IF(
			[CUSTOM_ZLIB], [
				LIBS="$LIBS -lz"
				CFLAGS="$CFLAGS -I$zlibdir"
				LDFLAGS="$LDFLAGS -L$zlibdir"

				AC_MSG_CHECKING(for zlib.h)
				AC_COMPILE_IFELSE(
					[AC_LANG_PROGRAM([#include "zlib.h"], [])], [
						AC_MSG_RESULT([yes])
					], [
						AC_MSG_ERROR([missing from custom directory $zlibdir])])

				AC_MSG_CHECKING(for library containing inflate)
				AC_LINK_IFELSE(
					[AC_LANG_CALL([], [inflate])], [
						AC_MSG_RESULT(yes)
					], [
						AC_MSG_ERROR([no, make sure to compile it in $zlibdir])
					])
			], [
				AC_CHECK_HEADER([zlib.h], , [
					AC_MSG_ERROR([Missing zlib.h, please install it to sysroot or use --with-zlibdir=path]),
				])
				AC_SEARCH_LIBS(
					[inflate], [z], [], [
						AC_MSG_ERROR([unable to find a working zlib library])
					])
			],
		)
	], [
		AC_MSG_RESULT(no)
	])

# Checks for OpenBSD compat library (part of OpenSSH).
AC_SEARCH_LIBS([ssh_get_progname], [openbsd-compat], [], [
	AC_MSG_ERROR([/!\ Make sure to configure and build OpenSSH before HIBA.])],
)

# Checks for OpenSSH compat library.
AC_SEARCH_LIBS([sshbuf_new], [ssh], [], [
	AC_MSG_ERROR([/!\ Make sure to configure and build OpenSSH before HIBA.])],
)
AC_SUBST([extra_LIBS], [$LIBS])
LIBS="$save_LIBS"

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h limits.h stdint.h stdlib.h string.h sys/types.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostname memset strdup strerror strspn strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# Print configuration summary
echo ""
echo "HIBA has been configure with the following options:"
echo ""
echo "              Host: $host"
echo "          Compiler: $CC"
echo "    Compiler flags: $CFLAGS"
echo "Preprocessor flags: $CPPFLAGS"
echo "            Linker: $LD"
echo "      Linker flags: $LDFLAGS"
echo "         Libraries: $LIBS $extra_LIBS"
echo "    Shared library: $enable_shared"
echo "    Static library: $enable_static"

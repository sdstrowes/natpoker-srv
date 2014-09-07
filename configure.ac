#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([natpoker-srv], [0.1], [sdstrowes@gmail.com])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE
AC_PROG_CC

AC_PROG_CC_STDC
CFLAGS="$CFLAGS -D_BSD_SOURCE=1 -Wall -Werror -std=c99"

AC_CANONICAL_HOST


AC_SUBST([NATP_LDADD], ['-lev'])


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h stdlib.h string.h sys/socket.h unistd.h])

AC_TYPE_UINT16_T

# Checks for library functions.
AC_CHECK_FUNCS([memset socket strerror])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT

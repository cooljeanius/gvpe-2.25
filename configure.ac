dnl#                                               -*- Autoconf -*-
dnl# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([gvpe],[2.25],[gvpe@schmorp.de])
AC_CONFIG_SRCDIR([src/gvpe.C])
AC_CANONICAL_TARGET
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([gnits])
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE

AH_TOP([
#ifndef CONFIG_H__
#define CONFIG_H__

#ifdef __cplusplus
   using namespace std;
#endif /* __cplusplus */

])

AH_BOTTOM([
typedef unsigned char u8;
typedef signed char s8;

#if __CYGWIN__

typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#else
# include <inttypes.h>

/* old modula-2 habits */
typedef uint16_t u16;
typedef uint32_t u32;
typedef int16_t s16;
typedef int32_t s32;
#endif /* __CYGWIN__ */

#endif /* CONFIG_H__ (from the AH_TOP fragment) */

#if HAVE_CLOCALE
# define CLOCALE <clocale>
#else
# define CLOCALE <locale.h>
#endif /* HAVE_CLOCALE */
])

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.3])

# Enable GNU extensions.
# Define this here, not in acconfig's @TOP@ section, since definitions
# in the latter do NOT make it into the configure-time tests.
AC_DEFINE([_GNU_SOURCE],[1],[Define to 1 to enable GNU extensions])

ALL_LINGUAS=""

dnl# Checks for programs.
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_RANLIB
AC_PATH_PROG([PERL],[perl perl5])

AC_DEFUN([AC_DUPLICATE_PROG_CHECKS],[
  AC_REQUIRE([AC_PROG_AWK])
  AC_REQUIRE([AC_PROG_GREP])
  AC_REQUIRE([AC_PROG_MAKE_SET])
  AC_REQUIRE([AC_PROG_SED])
])
AC_DUPLICATE_PROG_CHECKS

AC_ARG_ENABLE([iftype],
  [AS_HELP_STRING([--enable-iftype=TYPE/SUBTYPE],[
     Use kernel/net device interface TYPE/SUBTYPE.
     Working combinations are (see doc/gvpe.osdep.5.pod):
        "native/linux"
        "tincd/linux"
        "tincd/netbsd"
        "tincd/freebsd"
        "tincd/openbsd"
        "native/darwin"
        "tincd/darwin"
        "native/cygwin";
     Untested combinations are:
        "tincd/bsd"
        "tincd/solaris"
        "tincd/mingw"
        "tincd/raw_socket"
        "tincd/uml_socket";
     Broken combinations are:
        "tincd/cygwin";
     The default is to autodetect.
  ])],
  [
    IFTYPE=`echo ${enableval} | sed s%/.*%%`
    IFSUBTYPE=`echo ${enableval} | sed s%.*/%%`
  ])

dnl# Check and set OS
AC_MSG_CHECKING([for kernel networking interface type])

if test "x${IFTYPE}" = "x"; then
   case ${target_os} in
     *linux*)
       IFTYPE=native
       IFSUBTYPE=linux
       AC_DEFINE([HAVE_LINUX],[1],[Define to 1 when targeting Linux])
     ;;
     *freebsd*)
       IFTYPE=tincd
       IFSUBTYPE=freebsd
       AC_DEFINE([HAVE_FREEBSD],[1],[Define to 1 when targeting FreeBSD])
     ;;
     *darwin*)
       IFTYPE=native
       IFSUBTYPE=darwin
       AC_DEFINE([HAVE_DARWIN],[1],[Define to 1 when targeting Darwin/OSX])
     ;;
     *solaris*)
       IFTYPE=tincd
       IFSUBTYPE=solaris
       AC_DEFINE([HAVE_SOLARIS],[1],[Define to 1 for Solaris/SunOS])
     ;;
     *openbsd*)
       IFTYPE=tincd
       IFSUBTYPE=openbsd
       AC_DEFINE([HAVE_OPENBSD],[1],[Define to 1 when targeting OpenBSD])
     ;;
     *netbsd*)
       IFTYPE=tincd
       IFSUBTYPE=netbsd
       AC_DEFINE([HAVE_NETBSD],[1],[Define to 1 when targeting NetBSD])
     ;;
     *cygwin*)
       IFTYPE=native
       IFSUBTYPE=cygwin
       AC_DEFINE([HAVE_CYGWIN],[1],[Define to 1 when targeting Cygwin])
     ;;
     *)
       AC_MSG_ERROR(["Unknown operating system."])
     ;;
   esac
fi
AC_MSG_RESULT([${IFTYPE}/${IFSUBTYPE}])
AC_SUBST([IFTYPE],[${IFTYPE}])
AC_SUBST([IFSUBTYPE],[${IFSUBTYPE}])
AC_DEFINE_UNQUOTED([IFTYPE],["${IFTYPE}"],[kernel interface type])
AC_DEFINE_UNQUOTED([IFSUBTYPE],["${IFSUBTYPE}"],[kernel interface subtype])

# do NOT define POSIX_SOURCE for BSDs, including darwin
if test "x${IFSUBTYPE}" != "xfreebsd" -a "x${IFSUBTYPE}" != "xopenbsd" -a "x${IFSUBTYPE}" != "xnetbsd" -a "x${IFSUBTYPE}" != "xdarwin"; then
  AC_DEFINE([_POSIX_SOURCE],[1],
            [Define to 1 to enable POSIX 1003.1 extensions])
  AC_DEFINE([_XOPEN_SOURCE],[500],[Define to 1 to enable XOPEN extensions])
else
  AC_MSG_WARN([cannot define POSIX_SOURCE for your platform])
fi
dnl# TODO: instead of hardcoding by platform, do a conftest to see if
dnl# defining either of the above breaks anything (like asprintf(), which
dnl# can get broken on Darwin by defining one of the above)

AC_CACHE_SAVE

dnl# Checks for libraries.
dnl# (there are header checks in this section because they are
dnl# C++ header-only template libraries)

AC_LANG([C++])
AC_CHECK_HEADERS([tr1/unordered_map ext/hash_map clocale])

dnl# Checks for header files.
AC_HEADER_STDBOOL dnl# also "_CHECK"s it
AC_HEADER_TIME
AC_SYS_POSIX_TERMIOS
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h float.h gnu-versions.h \
                  libintl.h limits.h locale.h malloc.h malloc/malloc.h \
                  netdb.h netinet/in.h netinet/in_systm.h netinet/ip.h \
                  netinet/ip_icmp.h signal.h stdarg.h stddef.h stdio.h \
                  syslog.h sys/cygwin.h sys/file.h sys/ioctl.h sys/mman.h \
                  sys/param.h sys/socket.h sys/statfs.h sys/time.h \
                  sys/timeb.h termio.h termios.h unixlib.h wchar.h \
                  windows.h xlocale.h])
dnl# Some of these headers may be duplicated from above, but the conftests
dnl# use different includes this time around:
unset ac_cv_header_arpa_inet_h
unset ac_cv_header_netinet_in_h
unset ac_cv_header_netinet_in_systm_h
unset ac_cv_header_netinet_ip_h
unset ac_cv_header_netinet_ip_icmp_h
AC_CHECK_HEADERS([arpa/inet.h net/ethernet.h net/if.h netinet/ip.h \
                  netinet/ip_icmp.h netinet/tcp.h netinet/in_systm.h],[
],[],[
#include <sys/types.h>
#include <sys/socket.h>
#ifndef __CYGWIN__
# include <inttypes.h>
#endif /* !__CYGWIN__ */
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#else
# warning "this conftest expects <netinet/in.h> to be included."
#endif /* HAVE_NETINET_IN_H */
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#else
# warning "this conftest expects <arpa/inet.h> to be included."
#endif /* HAVE_ARPA_INET_H */
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#else
# warning "this conftest expects <netinet/in_systm.h> to be included."
#endif /* HAVE_NETINET_IN_SYSTM_H */
#ifdef HAVE_NETINET_IP_H
# include <netinet/ip.h>
#else
# warning "this conftest expects <netinet/ip.h> to be included."
#endif /* HAVE_NETINET_IP_H */
])

dnl# Checks for typedefs, structures, and compiler characteristics.
AC_C_CHAR_UNSIGNED
AC_C_BIGENDIAN
AC_C_CONST
AC_C_INLINE
AC_C_PROTOTYPES
AC_TYPE_GETGROUPS dnl# also checks "UID_T"
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INTMAX_T
AC_TYPE_INTPTR_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINTMAX_T
AC_TYPE_UINTPTR_T
AC_CHECK_SIZEOF([int])
AC_CHECK_ALIGNOF([int])
AC_CHECK_SIZEOF([short])
AC_CHECK_ALIGNOF([short])
AC_CHECK_SIZEOF([double])
AC_CHECK_ALIGNOF([double])
AC_CHECK_SIZEOF([long])
AC_CHECK_ALIGNOF([long])
AC_STRUCT_TM

AC_CACHE_CHECK([for socklen_t],[ac_cv_type_socklen_t],
[
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
  ]],[[socklen_t len = 42; return len;]])],[ac_cv_type_socklen_t=yes],[ac_cv_type_socklen_t=no])
])
if test "x${ac_cv_type_socklen_t}" = "xyes"; then
  AC_DEFINE([HAVE_SOCKLEN_T],[1],[Define to 1 if socklen_t is available])
fi

AC_CACHE_CHECK([for struct addrinfo], ac_cv_struct_addrinfo,
[
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
  ]],[[
struct addrinfo ai; ai.ai_family = AF_INET; return ai.ai_family;
  ]])],[ac_cv_struct_addrinfo=yes],[ac_cv_struct_addrinfo=no])
])
if test "x${ac_cv_struct_addrinfo}" = "xyes"; then
  AC_DEFINE([HAVE_STRUCT_ADDRINFO],[1],
            [Define to 1 if struct addrinfo is available])
fi

dnl# begin what used to be AC\_TYPE\_SIGNAL
AC_CACHE_CHECK([return type of signal handlers],[ac_cv_type_signal],[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <signal.h>
]],[[
return *(signal (0, 0)) (0) == 1;
]])],[ac_cv_type_signal=int],[ac_cv_type_signal=void])])
AC_DEFINE_UNQUOTED([RETSIGTYPE],[${ac_cv_type_signal}],
                   [Define as the return type of signal handlers
		    (`int' or `void').])
dnl# end what used to be AC\_TYPE\_SIGNAL
AC_CHECK_MEMBERS([struct stat.st_rdev])

dnl# Checks for library functions.

AC_LANG_PUSH([C])

dnl# argl, could somebody catapult darwin into the 21st century??? (huh?)
AC_CHECK_FUNCS([asprintf daemon dup2 fprintf getcwd getenv \
                gettimeofday getpid get_current_dir_name inet_ntoa \
                memcmp memcpy memmove memset mkdir mlockall ntohl putenv \
                rmdir setlocale socket strcasecmp strchr strcmp \
                strdup strerror strlen strncmp strrchr strsignal strstr \
                strtol uname unsetenv])
AC_CHECK_FUNCS_ONCE([gethostbyname select]) 
AC_FUNC_ERROR_AT_LINE
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_LSTAT dnl# also checks whether it "_FOLLOWS_SLASHED_SYMLINK"
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R

dnl# Support for SunOS

if test "x${ac_cv_func_socket}" = "x"; then
  test -z "${ac_cv_func_socket}"
  AC_CHECK_FUNC([socket],[
    AC_MSG_NOTICE([socket function found, skipping explicit check for socket library])
  ],[
    AC_CHECK_LIB([socket],[connect])
  ])
elif test "x${ac_cv_func_socket}" = "xno"; then
  AC_CHECK_LIB([socket],[connect])
elif test "x${ac_cv_func_socket}" = "xyes"; then
  AC_MSG_NOTICE([socket function has already been found, skipping explicit check for socket library])
else
  AC_MSG_WARN([ac_cv_func_socket should be either "yes", "no", or empty])
fi
if test "x${ac_cv_func_gethostbyname}" = "x"; then
  test -z "${ac_cv_func_gethostbyname}"
  AC_CHECK_FUNC([gethostbyname],[
    AC_MSG_NOTICE([gethostbyname function found, skipping explicit check for nsl library])
  ],[
    AC_CHECK_LIB([nsl],[gethostbyname])
  ])
elif test "x${ac_cv_func_gethostbyname}" = "xno"; then
  AC_CHECK_LIB([nsl],[gethostbyname])
elif test "x${ac_cv_func_gethostbyname}" = "xyes"; then
  AC_MSG_NOTICE([gethostbyname function has already been found, skipping explicit check for nsl library])
else
  AC_MSG_WARN([ac_cv_func_gethostbyname should be either "yes", "no", or empty])
fi

dnl# libev support
m4_include([libev/libev.m4])

dnl# libev is kinda C++ itself, should we pop the lang before its macros?
AC_LANG_POP

dnl# keep autoscan happy, but avoid duplicate checks by not actually doing
dnl# them:
if test "x" = "y"; then
  test -x `which autoheader`
  if test "x${ac_cv_func_gethostbyname}" != "x"; then
    test ! -z "${ac_cv_func_gethostbyname}"
    unset ac_cv_func_gethostbyname
  fi
  if test "x${ac_cv_func_select}" != "x"; then
    test ! -z "${ac_cv_func_select}"
    unset ac_cv_func_select
  fi
  AC_CHECK_FUNCS([gethostbyname select])
  AC_CHECK_FUNCS_ONCE([freeaddrinfo gai_strerror getaddrinfo getnameinfo])
fi

AC_CACHE_SAVE

AC_MSG_NOTICE([running tinc checks])
dnl# These are defined in files in m4/
tinc_TUNTAP

tinc_OPENSSL
if test "x${openssl_include}" != "x"; then
   CXXFLAGS="${CXXFLAGS} -I${openssl_include}"
fi
m4_ifdef([tinc_ZLIB],[tinc_ZLIB])

AC_ARG_ENABLE([threads],
  [AS_HELP_STRING([--enable-threads],[try to use threads for long-running asynchronous operations (default enabled).])],
  [try_threads=${enableval}],
  [try_threads=yes])

if test "x${try_threads}" = xyes; then
   AC_CHECK_HEADER([pthread.h],[
      LIBS="${LIBS} -lpthread"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <pthread.h>
      ]],[[
pthread_t id; pthread_create (&id, 0, 0, 0);
      ]])],[AC_DEFINE_UNQUOTED([ENABLE_PTHREADS],[1],
                               [POSIX thread support.])
      ])
   ])
fi

AC_ARG_ENABLE([static-daemon],
  [AS_HELP_STRING([--enable-static-daemon],[enable statically linked daemon.])],
  [LDFLAGS_DAEMON=-static])
AC_SUBST([LDFLAGS_DAEMON])

AC_ARG_ENABLE([rohc],
  [AS_HELP_STRING([--enable-rohc],[enable robust header compression (rfc3095).])],
  [
  echo
  echo "******************************************************************"
  echo "******************************************************************"
  echo "**** --enable-rohc is highly experimental, do not use ************"
  echo "******************************************************************"
  echo "******************************************************************"
  echo
  export rohc=true
  AC_DEFINE_UNQUOTED([ENABLE_ROHC],[1],[Define to 1 for ROHC support])
  ])

AM_CONDITIONAL([ROHC],[test "x${rohc}" = "xtrue"])

AC_ARG_ENABLE([bridging],
  [AS_HELP_STRING([--enable-bridging],[enable bridging support (default disabled).])],[
  AC_DEFINE_UNQUOTED([ENABLE_BRIDGING],[1],[Define to 1 for bridging support.])
])

ICMP=1
AC_ARG_ENABLE([icmp],
  [AS_HELP_STRING([--disable-icmp],[enable icmp protocol support (default enabled).])],[
  if test "x${enableval}" = "xno"; then
     export ICMP=0
  fi
])
if test "x${ICMP}" = "x1"; then
  AC_DEFINE_UNQUOTED([ENABLE_ICMP],[1],[Define to 1 for ICMP protocol support.])
fi

TCP=1
AC_ARG_ENABLE([tcp],
  [AS_HELP_STRING([--disable-tcp],[enable tcp protocol support (default enabled).])],[
  if test "x${enableval}" = "xno"; then
     export TCP=0
  fi
])
if test "x${TCP}" = x1; then
  AC_DEFINE_UNQUOTED([ENABLE_TCP],[1],[Define to 1 for TCP protocol support.])
fi

HTTP=1
AC_ARG_ENABLE([http-proxy],
  [AS_HELP_STRING([--disable-http-proxy],[enable http proxy connect support (default enabled).])],[
  if test "x${enableval}" = "xno"; then
     export HTTP=0
  fi
])
if test "x${HTTP}" = "x1"; then
  AC_DEFINE_UNQUOTED([ENABLE_HTTP_PROXY],[1],[Define to 1 for http proxy connect support.])
fi

AC_ARG_ENABLE([dns],
  [AS_HELP_STRING([--enable-dns],[enable dns tunnel protocol support (default disabled, as it requires gmp).])],
  [
    AC_CHECK_HEADER([gmp.h],[],[AC_MSG_ERROR([gmp.h not found, required for --enable-dns])])
    AC_CHECK_LIB([gmp],[main],[],[AC_MSG_ERROR([libgmp not found, required for --enable-dns])])

    AC_DEFINE_UNQUOTED([ENABLE_DNS],[1],[Define to 1 for DNS tunnel protocol support.])
  ])

HMAC=12
AC_ARG_ENABLE([hmac-length],
  [AS_HELP_STRING([--enable-hmac-length=BYTES],[
      use a hmac of length BYTES bytes (default 12). Allowed values are 4, 8, 12, 16.])],[
  export HMAC=${enableval}
])
AC_DEFINE_UNQUOTED([HMACLENGTH],[${HMAC}],[Size of HMAC in each packet in bytes.])

RAND=8
AC_ARG_ENABLE([rand-length],
  [AS_HELP_STRING([--enable-rand-length=BYTES],
      [use BYTES bytes of extra randomness (default 8). Allowed values are 0, 4, 8.])],[
  export RAND=${enableval}
])
AC_DEFINE_UNQUOTED([RAND_SIZE],[${RAND}],[Add this many bytes of randomness to each packet.])

MTU=1500
AC_ARG_ENABLE([max-mtu],
  [AS_HELP_STRING([--enable-max-mtu=BYTES],[enable mtu sizes upto BYTES bytes (default 1500). Use 9100 for jumbogram support.])],[
  export MTU=${enableval}
])
AC_DEFINE_UNQUOTED([MAX_MTU],[(${MTU} + 14)],[Maximum MTU supported.])

COMPRESS=1
AC_ARG_ENABLE([compression],
  [AS_HELP_STRING([--disable-compression],[Disable compression support.])],[
  if test "x${enableval}" = "xno"; then
     export COMPRESS=0
  fi
])
AC_DEFINE_UNQUOTED([ENABLE_COMPRESSION],[${COMPRESS}],[Enable compression support.])

CIPHER=aes_128_cbc
AC_ARG_ENABLE([cipher],
  [AS_HELP_STRING([--enable-cipher=CIPHER],[
      Select the symmetric cipher (default "aes-128").
      Must be one of "bf" (blowfish), "aes-128" (rijndael), "aes-192" or "aes-256".])],[
  if test "x${enableval}" = "xbf"     ; then export CIPHER=bf_cbc     ; fi
  if test "x${enableval}" = "xaes-128"; then export CIPHER=aes_128_cbc; fi
  if test "x${enableval}" = "xaes-192"; then export CIPHER=aes_192_cbc; fi
  if test "x${enableval}" = "xaes-256"; then export CIPHER=aes_256_cbc; fi
])
AC_DEFINE_UNQUOTED([ENABLE_CIPHER],[EVP_${CIPHER}],[Select the symmetric cipher to use.])

DIGEST=ripemd160
AC_ARG_ENABLE([digest],
  [AS_HELP_STRING([--enable-digest=CIPHER],[
    Select the digest algorithm to use (default "ripemd160"). Must be 1 of
    "sha512", "sha256", "sha1" (legacy), "ripemd160", "md5" (insecure) or "md4" (insecure).])],[
  if test "x${enableval}" = "xsha512"   ; then export DIGEST=sha512   ; fi
  if test "x${enableval}" = "xsha256"   ; then export DIGEST=sha256   ; fi
  if test "x${enableval}" = "xsha1"     ; then export DIGEST=sha1     ; fi
  if test "x${enableval}" = "xripemd160"; then export DIGEST=ripemd160; fi
  if test "x${enableval}" = "xmd5"      ; then export DIGEST=md5      ; fi
  if test "x${enableval}" = "xmd4"      ; then export DIGEST=md4      ; fi
])
AC_DEFINE_UNQUOTED([ENABLE_DIGEST],[EVP_${DIGEST}],[Select the digest algorithm to use.])

if ${CXX} -v --help 2>&1 | grep -q fno-rtti; then
   CXXFLAGS="${CXXFLAGS} -fno-rtti"
fi

if test "x${disable_exceptions}" = "xyes"; then
  if ${CXX} -v --help 2>&1 | grep -q fexceptions; then
     CXXFLAGS="${CXXFLAGS} -fno-exceptions"
  fi
fi

LIBS="${EXTRA_LIBS} ${LIBS}"

if test "x${enable_function_sections}" = "xyes"; then
  if ${CXX} -v --help 2>&1 | grep -q ffunction-sections; then
     CXXFLAGS="${CXXFLAGS} -ffunction-sections"
  fi
fi

if ${LD} -v --help 2>&1 | grep -q gc-sections; then
   LDFLAGS="${LDFLAGS} -Wl,--gc-sections"
fi

if test "x${AM_CPPFLAGS}" = "x"; then
  test -z "${AM_CPPFLAGS}"
  export AM_CPPFLAGS="${CPPFLAGS} -Wimplicit -Wno-unused"
fi
AC_SUBST([AM_CPPFLAGS])

AC_CONFIG_FILES([Makefile \
po/Makefile.in \
src/Makefile \
src/rohc/Makefile \
doc/Makefile \
lib/Makefile \
m4/Makefile])
AC_OUTPUT

echo
echo "***"
echo "*** Configuration Summary"
echo "***"
echo "*** Kernel Iface: ${IFTYPE}/${IFSUBTYPE}"
echo "*** Cipher used:  ${CIPHER}"
echo "*** Digest used:  ${DIGEST}"
echo "*** HMAC length:  ${HMAC}"
echo "*** RAND used:    ${RAND}"
echo "*** Max. MTU:     ${MTU}"

echo "***"
echo "*** Enable options:"
grep ENABLE_ config.h | sed -e 's/^/*** /'

if test "x${DIGEST}" = xmd4; then
echo "***"
echo "** WARNING: The digest you chose (${DIGEST}) is known to be insecure"
fi

if test "x${DIGEST}" = xmd5; then
echo "***"
echo "*** WARNING: The digest you chose (${DIGEST}) is quite insecure"
fi

if test "${HMAC}" -lt 12; then
echo "***"
echo "*** WARNING: The hmac length you chose (${HMAC}) is quite insecure"
fi

if test "${RAND}" -lt 8; then
echo "***"
echo "WARNING: The random prefix you chose (${RAND}) is probably insecure"
fi

echo "***"
echo



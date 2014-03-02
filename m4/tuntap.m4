dnl# Check to find out whether the running kernel has support for TUN/TAP

AC_DEFUN([tinc_TUNTAP],
[
AC_ARG_WITH([kernel],
  [AS_HELP_STRING([--with-kernel=dir],[Give a path to the directory containing Linux kernel sources (default: /usr/src/linux). This is to check for tuntap support.])],
  [kerneldir="${withval}"],
  [kerneldir="/usr/src/linux"])

AC_CACHE_CHECK([for linux/if_tun.h],[tinc_cv_linux_if_tun_h],
[ 
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include "${kerneldir}/include/linux/if_tun.h"
  ]],[[
int a = IFF_TAP;
  ]])],[if_tun_h="\"${kerneldir}/include/linux/if_tun.h\""],
       [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <linux/if_tun.h>
        ]],[[
int a = IFF_TAP;
        ]])],[if_tun_h="default"],[if_tun_h="no"])
  ])

  if test "x${if_tun_h}" = "xno"; then
    tinc_cv_linux_if_tun_h=none
  else
    tinc_cv_linux_if_tun_h="${if_tun_h}"
  fi
])

if test "x${tinc_cv_linux_if_tun_h}" != "xnone"; then
  AC_DEFINE([HAVE_TUNTAP],[1],[Universal tun/tap driver present])
  if test "x${tinc_cv_linux_if_tun_h}" != "xdefault"; then
   AC_DEFINE_UNQUOTED([LINUX_IF_TUN_H],[${tinc_cv_linux_if_tun_h}],[Location of if_tun.h])
  fi
elif test "x${tinc_cv_linux_if_tun_h}" = "x"; then
  test -z "${tinc_cv_linux_if_tun_h}"
  AC_CHECK_HEADERS_ONCE([linux/if_tun.h])
fi
AC_SUBST([LINUX_IF_TUN_H])
AC_SUBST([HAVE_TUNTAP])
])

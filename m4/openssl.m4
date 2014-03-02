dnl Check to find the OpenSSL headers/libraries

AC_DEFUN([tinc_OPENSSL],
[
  tinc_ac_save_CPPFLAGS="$CPPFLAGS"

  AC_ARG_WITH(openssl-include,
    [  --with-openssl-include=DIR  OpenSSL headers directory (without trailing /openssl)],
    [openssl_include="$withval"
     CFLAGS="$CFLAGS -I$withval"
     CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(openssl-lib,
    [  --with-openssl-lib=DIR  OpenSSL library directory],
    [openssl_lib="$withval"
     LIBS="$LIBS -L$withval"]
  )

  AC_CHECK_HEADERS(openssl/evp.h openssl/rsa.h openssl/rand.h openssl/err.h openssl/sha.h openssl/pem.h,
    [],
    [AC_MSG_ERROR([OpenSSL header files not found.]); break]
  )

  CPPFLAGS="$tinc_ac_save_CPPFLAGS"

  AC_CHECK_LIB(crypto, SHA1_Init,
    [LIBS="$LIBS -lcrypto"],
    [AC_MSG_ERROR([OpenSSL libraries not found.])]
  )

  AC_CHECK_FUNCS([RAND_pseudo_bytes OPENSSL_add_all_algorithms_noconf OpenSSL_add_all_algorithms SSLeay_add_all_algorithms])

  AC_CHECK_FUNC(dlopen,
    [],
    [AC_CHECK_LIB(dl, dlopen,
      [LIBS="$LIBS -ldl"],
      [AC_MSG_ERROR([OpenSSL depends on libdl.])]
    )]
  )

  AC_CHECK_FUNC(inflate,
    [],
    [AC_CHECK_LIB(z, inflate,
      [LIBS="$LIBS -lz"],
      [AC_MSG_ERROR([OpenSSL depends on libz.])]
    )]
  )
])

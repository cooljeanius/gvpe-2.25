noinst_LIBRARIES = libgvpe.a

AM_CPPFLAGS = @AM_CPPFLAGS@ -I. -I$(top_builddir)

AM_CFLAGS = -Wall -Wno-unused
AM_CXXFLAGS = -Wall -Wno-unused

libgvpe_a_SOURCES = pidfile.c getopt.c getopt1.c dropin.c

libgvpe_a_LIBADD = @LIBOBJS@ @ALLOCA@
libgvpe_a_DEPENDENCIES = $(libgvpe_a_LIBADD)

noinst_HEADERS = pidfile.h getopt.h dropin.h gettext.h


## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnits

SUBDIRS = m4 lib src doc po

ACLOCAL_AMFLAGS = -I m4 --install

AM_CPPFLAGS = @AM_CPPFLAGS@
AM_CFLAGS = -Wimplicit -Wno-unused
AM_CXXFLAGS = -Wno-unused -std=gnu++98

EXTRA_DIST = build-aux/config.rpath build-aux/mkinstalldirs build-aux/depcomp \
	     TODO libev/ev.c libev/ev.h libev/libev.m4 libev/ev++.h \
	     libev/ev_epoll.c libev/ev_kqueue.c libev/ev_poll.c \
	     libev/ev_select.c libev/ev_vars.h libev/ev_win32.c \
	     libev/ev_wrap.h

CVS_CREATED = ABOUT-NLS configure aclocal.m4 config.h.in config.guess \
 config.sub install-sh missing mkinstalldirs \
 stamp-h.in m4/Makefile.am po/Makefile.in.in \
 po/vpe.pot po/*.sed po/*.header po/*.sin po/Rules-quot \
 src/.libs intl depcomp

if CUSTOM_OPENSSL_PREFIX
AM_DISTCHECK_CONFIGURE_FLAGS = --with-openssl-include=$(openssl_include) --with-openssl-lib=$(openssl_lib)
else
AM_DISTCHECK_CONFIGURE_FLAGS =
endif

DISTCLEANFILES = *~ .DS_Store po/*~

distclean-local:
	rm -rf autom4te.cache || rmdir autom4te.cache

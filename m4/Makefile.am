## Process this file with automake to produce Makefile.in   -*-Makefile-*-

##m4-files-begin
EXTRA_DIST = README Makefile.am.in aclocal-include.m4 codeset.m4 \
fcntl-o.m4 gettext.m4 glibc2.m4 glibc21.m4 iconv.m4 intdiv0.m4 \
intl.m4 intldir.m4 intlmacosx.m4 intmax.m4 inttypes-pri.m4 inttypes.m4 \
inttypes_h.m4 isc-posix.m4 lcmessage.m4 lib-ld.m4 lib-link.m4 \
lib-prefix.m4 lock.m4 longlong.m4 nls.m4 openssl.m4 po.m4 printf-posix.m4 \
progtest.m4 size_max.m4 stdint_h.m4 threadlib.m4 tuntap.m4 uintmax_t.m4 \
ulonglong.m4 visibility.m4 wchar_t.m4 wint_t.m4 xsize.m4

##m4-files-end

Makefile.am: Makefile.am.in
	rm -f $@ $@t
	sed -n '1,/^##m4-files-begin/p' $< > $@t
	( echo EXTRA_DIST = README Makefile.am.in; \
	  find . -type f -name '*.m4' -print |sed 's,^\./,,' |sort ) \
	  |fmt | (tr '\012' @; echo) \
	      |sed 's/@$$/%/;s/@/ \\@/g' |tr @% '\012\012' \
	        >> $@t
	sed -n '/^##m4-files-end/,$$p' $< >> $@t
	chmod a-w $@t
	mv $@t $@

DISTCLEANFILES = *~ .DS_Store

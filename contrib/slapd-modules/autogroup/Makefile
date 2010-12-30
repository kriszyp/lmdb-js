LIBTOOL=../../../libtool

CPPFLAGS+=-I../../../include -I../../../servers/slapd

ldap_subdir = openldap
prefix=/usr/local
exec_prefix = $(prefix)
libdir = $(exec_prefix)/lib
libexecdir = $(exec_prefix)/libexec
moduledir = $(exec_prefix)/libexec/$(ldap_subdir)

all: autogroup.la

autogroup.lo:	autogroup.c
	$(LIBTOOL) --mode=compile $(CC) $(CPPFLAGS) -Wall -c $?

autogroup.la:	autogroup.lo
	$(LIBTOOL) --mode=link $(CC) -version-info 0:0:0 \
	-rpath $(libdir) -module -o $@ $? 

clean:
	rm -f autogroup.lo autogroup.la

install: autogroup.la
	mkdir -p $(DESTDIR)$(moduledir)
	$(LIBTOOL) --mode=install cp autogroup.la $(DESTDIR)$(moduledir)
	$(LIBTOOL) --finish $(DESTDIR)$(moduledir)

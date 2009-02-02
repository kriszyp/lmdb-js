# $OpenLDAP$
CPPFLAGS+=-I../../../include -I../../../servers/slapd 
CPPFLAGS+=-DSLAPD_OVER_NOPS=SLAPD_MOD_DYNAMIC
LIBS=-lldap_r -llber -lcrypto

all: nops.la

nops.lo:    nops.c
	$(LIBTOOL) --mode=compile $(CC) $(CPPFLAGS) -c $?

nops.la:    nops.lo
	$(LIBTOOL) --mode=link $(CC) -version-info 0:0:0 \
		   -rpath $(PREFIX)/lib -module -o $@ $? $(LIBS)

clean:
	rm nops.lo nops.la

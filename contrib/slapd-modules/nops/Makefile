CPPFLAGS+=-I../../../include -I../../../servers/slapd

all: nops.la

nops.lo:    nops.c
	$(LIBTOOL) --mode=compile $(CC) $(CPPFLAGS) -c $?

nops.la:    nops.lo
	$(LIBTOOL) --mode=link $(CC) -version-info 0:0:0 \
		   -rpath $(PREFIX)/lib -module -o $@ $? 

clean:
	rm nops.lo nops.la

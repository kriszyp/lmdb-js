# Copyright 2009 Jonathan Clarke <jonathan@phillipoux.net>.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only as authorized by the OpenLDAP
# Public License.
#
# A copy of this license is available in the file LICENSE in the
# top-level directory of the distribution or, alternatively, at
# <http://www.OpenLDAP.org/license.html>.

CPPFLAGS+=-I../../../include -I../../../servers/slapd 
CPPFLAGS+=-DSLAPD_OVER_LASTBIND=SLAPD_MOD_DYNAMIC
#LIBTOOL=libtool
LIBTOOL=../../../libtool


all: lastbind.la

lastbind.lo:    lastbind.c
	$(LIBTOOL) --mode=compile $(CC) $(CPPFLAGS) -Wall -c $?

lastbind.la:    lastbind.lo
	$(LIBTOOL) --mode=link $(CC) -version-info 0:0:0 \
		   -rpath $(PREFIX)/lib -module -o $@ $?

clean:
	rm -rf lastbind.lo lastbind.la lastbind.o .libs/

# $OpenLDAP$
## Copyright 1998,1999 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makefile Template for Shared Libraries
##

COMPILE = $(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c
MKDEPFLAG = -l

.SUFFIXES: .c .o .lo

.c.lo:
	$(COMPILE) $<

$(LIBRARY):  version.lo
	$(LTLIBLINK) -rpath $(libdir) -o $@ $(OBJS) version.lo
	$(RM) ../$@;	\
	(d=`$(PWD)` ; $(LN_S) `$(BASENAME) $$d`/$@ ../$@)
	$(RM) ../`$(BASENAME) $@ .la`.a;	\
	(d=`$(PWD)`; t=`$(BASENAME) $@ .la`.a; $(LN_S) `$(BASENAME) $$d`/.libs/$$t ../$$t)

Makefile: $(top_srcdir)/build/lib-shared.mk

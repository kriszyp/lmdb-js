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
	# If we want our binaries to link dynamically with libldap{,_r} liblber...
	# We also symlink the .so.# so we can run the tests without installing
	if test "$(LINK_BINS_DYNAMIC)" = "yes"; then \
		(d=`$(PWD)`; t=`$(BASENAME) $@ .la`.so; $(LN_S) `$(BASENAME) $$d`/.libs/$$t ../$$t); \
		(d=`$(PWD)`; b=`$(BASENAME) $@ .la`; t=`ls $$d/.libs/$$b.so.?`; $(LN_S) `$(BASENAME) $$d`/.libs/`$(BASENAME) $$t` ../`$(BASENAME) $$t`); \
	fi

Makefile: $(top_srcdir)/build/lib-shared.mk

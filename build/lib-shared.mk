# $OpenLDAP$
## Copyright 1998,1999 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makefile Template for Shared Libraries
##

NT_LTFLAGS = --only-$(LINKAGE)
LTFLAGS = $(@PLAT@_LTFLAGS) 

NT_DYN_LT_NO_UNDEF = -no-undefined
LT_NO_UNDEF = $(@PLAT@_@LIB_LINKAGE@_LT_NO_UNDEF)

COMPILE = $(LIBTOOL) $(LTFLAGS) --mode=compile $(CC) $(CFLAGS) $(EXTRA_DEFS) -c
LTLIBLINK = $(LIBTOOL) $(LTFLAGS) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) \
		$(LTVERSION) $(LT_NO_UNDEF)

MKDEPFLAG = -l

.SUFFIXES: .c .o .lo

.c.lo:
	$(COMPILE) $<


# DYN_EXT (@DYN_EXT@) describes the extension assoicated with a
# dynamic library, e.g. so, dll

DYN_EXT=@DYN_EXT@

$(LIBRARY):  version.lo
	$(LTLIBLINK) -rpath $(libdir) -o $@ $(OBJS) version.lo $(EXTRA_LIBS)
	$(RM) ../$@
	(d=`$(PWD)` ; $(LN_S) `$(BASENAME) $$d`/$@ ../$@)
	$(RM) ../`$(BASENAME) $@ .la`.a;	\
	(d=`$(PWD)`; t=`$(BASENAME) $@ .la`.a; $(LN_S) `$(BASENAME) $$d`/.libs/$$t ../$$t)
	# If we want our binaries to link dynamically with libldap{,_r} liblber...
	# We also symlink the .so.# so we can run the tests without installing
	if test "$(LINK_BINS_DYNAMIC)" = "yes"; then \
		(d=`$(PWD)`; b=`$(BASENAME) $@ .la`; t=`ls $$d/.libs/$$b*.$(DYN_EXT)`; t=`$(BASENAME) $$t`; $(LN_S) `$(BASENAME) $$d`/.libs/$$t ../$$t); \
		if test "$(DYN_EXT)" != dll; then \
		    (d=`$(PWD)`; b=`$(BASENAME) $@ .la`; t=`ls $$d/.libs/$$b.$(DYN_EXT).?`; $(LN_S) `$(BASENAME) $$d`/.libs/`$(BASENAME) $$t` ../`$(BASENAME) $$t`); \
		fi \
	fi

Makefile: $(top_srcdir)/build/lib-shared.mk


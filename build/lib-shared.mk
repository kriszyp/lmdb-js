# $OpenLDAP$
## Copyright 1998-2000 The OpenLDAP Foundation
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
LTLIBLINK = $(LIBTOOL) $(LTFLAGS) --mode=link $(CC) -rpath $(libdir) \
	$(CFLAGS) $(LDFLAGS) $(LTVERSION) $(LT_NO_UNDEF)

MKDEPFLAG = -l

.SUFFIXES: .c .o .lo

.c.lo:
	$(COMPILE) $<


# DYN_EXT (@DYN_EXT@) describes the extension assoicated with a
# dynamic library, e.g. so, dll

DYN_EXT=@DYN_EXT@

$(LIBRARY):  version.lo
	$(LTLIBLINK) -o $@ $(OBJS) version.lo $(EXTRA_LIBS)
	$(RM) ../$@
	d=`$(PWD)`; d=`$(BASENAME) $$d`; cd ..; $(LN_S) $$d/$@ $@; \
	t=`$(BASENAME) $@ .la`.a; $(RM) $$t; $(LN_S) $$d/.libs/$$t $$t
	if test "$(LINK_BINS_DYNAMIC)" = "yes"; then \
		d=`$(PWD)`; d=`$(BASENAME) $$d`; b=`$(BASENAME) $@ .la`; \
		 cd .libs; t=`echo $$b*.$(DYN_EXT)`; (cd ../.. ; $(RM) $$t; \
		 $(LN_S) $$d/.libs/$$t $$t); \
		if test "$(DYN_EXT)" != dll; then \
		    t=`echo $$b.$(DYN_EXT).?`; cd ../.. ; \
		    $(RM) $$t; \
		    $(LN_S) $$d/.libs/$$t $$t; \
		fi \
	fi

Makefile: $(top_srcdir)/build/lib-shared.mk


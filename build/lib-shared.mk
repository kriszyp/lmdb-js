##---------------------------------------------------------------------------
##
## Makefile Template for Shared Libraries
##

LTVERSION = -version-info $(LIBVERSION)
LINK    = $(LTLINK)
COMPILE = $(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c
MKDEPFLAG = -l

.SUFFIXES: .c .o .lo

.c.lo:
	$(COMPILE) $<

$(LIBRARY):  version.lo
	$(LINK) -rpath $(libdir) -o $@ $(OBJS) version.lo
	$(RM) ../$@;	\
	(d=`$(PWD)` ; $(LN_S) `$(BASENAME) $$d`/$@ ../$@)
	$(RM) ../`$(BASENAME) $@ .la`.a;	\
	(d=`$(PWD)`; t=`$(BASENAME) $@ .la`.a; $(LN_S) `$(BASENAME) $$d`/.libs/$$t ../$$t)

Makefile: $(top_srcdir)/build/lib-shared.mk

##---------------------------------------------------------------------------
##
## Makefile Template for Shared Libraries
##

LINK    = $(LTLINK) -version-info $(LIBVERSION)
COMPILE = $(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c
MKDEPFLAG = -l

.SUFFIXES: .c .o .lo

.c.lo:
	$(COMPILE) $<

$(LIBRARY):  version.lo
	$(LINK) -rpath $(libdir) -o $@ $(OBJS) version.lo
	@$(RM) ../$@;	\
	(d=`$(PWD)` ; $(LN_S) `$(BASENAME) $$d`/$@ ../$@)

Makefile: $(top_srcdir)/build/lib-shared.mk

##---------------------------------------------------------------------------
##
## Makefile Template for Libraries
##

all-common: $(LIBRARY) $(PROGRAMS)

version.c: $(OBJS) $(srcdir)/Version.c
	$(RM) $@
	(u=$${USER-root} v=`$(CAT) $(VERSIONFILE)` d=`$(PWD)` \
	h=`$(HOSTNAME)` t=`$(DATE)`; $(SED) -e "s|%WHEN%|$${t}|" \
	-e "s|%WHOANDWHERE%|$${u}@$${h}:$${d}|" \
	-e "s|%VERSION%|$${v}|" \
	< $(srcdir)/Version.c > $@)

install-common: FORCE

lint: lint-local FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

lint5: lint5-local FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

clean-common: 	FORCE
	$(RM) $(LIBRARY) ../$(LIBRARY) $(XLIBRARY) \
		$(PROGRAMS) $(XPROGRAMS) $(XSRCS) \
		*.o *.lo a.out core version.c .libs/*

depend-common: FORCE
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)

lint-local: FORCE
lint5-local: FORCE

Makefile: $(top_srcdir)/build/lib.mk

##---------------------------------------------------------------------------
##
## Makefile Template for Libraries
##

all-common: $(LIBRARY) $(PROGRAMS)

$(LIBRARY): version.o
	$(AR) ru $@ $(OBJS) version.o
	@$(RANLIB) $@;	\
	$(RM) ../$@;	\
	(d=`$(PWD)` ; $(LN_S) `$(BASENAME) $$d`/$@ ../$@)

version.c: $(OBJS) $(srcdir)/Version.c
	$(RM) $@
	(u=$${USER-root} v=`$(CAT) $(VERSIONFILE)` d=`$(PWD)` \
	h=`$(HOSTNAME)` t=`$(DATE)`; $(SED) -e "s|%WHEN%|$${t}|" \
	-e "s|%WHOANDWHERE%|$${u}@$${h}:$${d}|" \
	-e "s|%VERSION%|$${v}|" \
	< $(srcdir)/Version.c > $@)

install-common: all-common install-local

lint: lint-local FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

lint5: lint5-local FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

clean-common: 	clean-local
	$(RM) $(LIBRARY) ../$(LIBRARY) $(PROGRAMS) $(XPROGRAMS) $(XSRCS) \
		*.o a.out core version.c

depend-common: depend-local
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)

veryclean-common: veryclean-local clean-common

lint-local: FORCE
lint5-local: FORCE

Makefile: $(top_srcdir)/build/lib.mk

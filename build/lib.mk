##
## Makefile Template for Libraries
##

all: $(LIBRARY) $(PROGRAMS)

$(LIBRARY): version.o
	$(AR) ru $@ $(OBJS) version.o
	@$(RANLIB) $@;	\
	$(RM) ../$@;	\
	(d=`$(PWD)` ; $(LN_S) `$(BASENAME) $$d`/$@ ../$@)

version.c: $(OBJS)
	$(RM) $@
	(u=$${USER-root} v=`$(CAT) $(VERSIONFILE)` d=`$(PWD)` \
	h=`$(HOSTNAME)` t=`$(DATE)`; $(SED) -e "s|%WHEN%|$${t}|" \
	-e "s|%WHOANDWHERE%|$${u}@$${h}:$${d}|" \
	-e "s|%VERSION%|$${v}|" \
	< Version.c > $@)

install: all

lint: FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

lint5: FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

clean: 	FORCE
	$(RM) $(LIBRARY) ../$(LIBRARY) $(PROGRAMS) $(XPROGRAMS) $(XSRCS) \
		*.o a.out core version.c

depend: FORCE
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)


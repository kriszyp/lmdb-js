##
## Makefile Template for Programs
##

all: $(PROGRAMS)

install: all

lint: FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

lint5: FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

clean: 	FORCE
	$(RM) $(PROGRAMS) $(XPROGRAMS) $(XSRCS) \
		*.o a.out core

depend: FORCE
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)


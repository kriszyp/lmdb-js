##---------------------------------------------------------------------------
##
## Makefile Template for Programs
##

all-common: all-local $(PROGRAMS)

install-common: all-common install-local

clean-common: 	clean-local
	$(RM) $(PROGRAMS) $(XPROGRAMS) $(XSRCS) *.o a.out core

veryclean-common: veryclean-local clean-local

depend-common: depend-local
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)

lint: lint-local
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

lint5: lint5-local
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

# these could be empty
lint-local: FORCE
lint5-local: FORCE

Makefile: $(top_srcdir)/build/rules.mk

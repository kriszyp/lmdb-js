## Copyright 1998,1999 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makefile Template for Servers
##

all-common: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) all-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to build $(PROGRAMS)"; \
	fi

clean-common: clean-srv FORCE
veryclean-common: veryclean-srv FORCE

lint-common: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) lint-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to lint $(PROGRAMS)"; \
	fi

5lint-common: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) 5lint-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to 5lint $(PROGRAMS)"; \
	fi

depend-common: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) depend-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to depend $(PROGRAMS)"; \
	fi

install-common: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) install-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to install $(PROGRAMS)"; \
	fi

all-local-srv:
all-srv: all-local-srv FORCE

install-local-srv:
install-srv: install-local-srv FORCE

lint-local-srv:
lint-srv: lint-local-srv FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

5lint-local-srv:
5lint-srv: 5lint-local-srv FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

clean-local-srv:
clean-srv: 	clean-local-srv FORCE
	$(RM) $(PROGRAMS) $(XPROGRAMS) $(XSRCS) *.o a.out core .libs/*

depend-local-srv:
depend-srv: depend-local-srv FORCE
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)

veryclean-local-srv:
veryclean-srv: 	clean-srv veryclean-local-srv

Makefile: $(top_srcdir)/build/srv.mk

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

all-srv: FORCE

install-srv: FORCE

lint-srv: FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

5lint-srv: FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

clean-srv: 	FORCE
	$(RM) $(PROGRAMS) $(XPROGRAMS) $(XSRCS) *.o a.out core .libs/*

depend-srv: FORCE
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)

veryclean-srv: 	clean-srv

Makefile: $(top_srcdir)/build/srv.mk

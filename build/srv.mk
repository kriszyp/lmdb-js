##
## Makefile Template for Servers
##

all: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) all-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to build $(PROGRAMS)"; \
	fi

clean: clean-srv FORCE
lint: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) lint-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to lint $(PROGRAMS)"; \
	fi

5lint: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) 5lint-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to 5lint $(PROGRAMS)"; \
	fi

depend: FORCE
	@if [ "$(BUILD_SRV)" = "yes" ]; then \
		$(MAKE) $(MFLAGS) depend-srv; \
	else \
		echo "run configure with $(BUILD_OPT) to mkdepend $(PROGRAMS)"; \
	fi

all-srv: FORCE

install-srv: all-srv FORCE

lint-srv: FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

5lint-srv: FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

clean-srv: 	FORCE
	$(RM) $(PROGRAMS) $(XPROGRAMS) $(XSRCS) \
		*.o a.out core

depend-srv: FORCE
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)

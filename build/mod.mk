## Copyright 1998,1999 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makefile Template for Server Modules
##

LIBRARY = $(LIBBASE).la
LIBSTAT = lib$(LIBBASE).a

all-common: FORCE
	@if test "$(BUILD_MOD)" = "yes"; then \
		$(MAKE) $(MFLAGS) LTFLAGS=--only-shared all-mod; \
	elif test "$(BUILD_LIB)" = "yes" ; then \
		$(MAKE) $(MFLAGS) LTFLAGS=--only-static all-lib; \
	else \
		echo "run configure with $(BUILD_OPT) to build $(LIBBASE)"; \
	fi

version.c: $(OBJS)
	$(RM) $@
	$(MKVERSION) $(LIBBASE) > $@

$(LIBRARY): version.lo
	$(LTLIBLINK) -module -rpath $(moduledir) -o $@ $(OBJS) version.lo

$(LIBSTAT): version.lo
	$(AR) ruv $@ `echo $(OBJS) | sed s/\.lo/.o/g` version.o
	@$(RANLIB) $@

clean-common: clean-lib FORCE
veryclean-common: veryclean-lib FORCE

lint-common: FORCE
	@if test "$(BUILD_LIB)" = "yes" ; then \
		$(MAKE) $(MFLAGS) lint-lib; \
	else \
		echo "run configure with $(BUILD_OPT) to lint $(LIBBASE)"; \
	fi

5lint-common: FORCE
	@if test "$(BUILD_LIB)" = "yes" ; then \
		$(MAKE) $(MFLAGS) 5lint-lib; \
	else \
		echo "run configure with $(BUILD_OPT) to 5lint $(LIBBASE)"; \
	fi

depend-common: FORCE
	@if test "$(BUILD_LIB)" = "yes" ; then \
		$(MAKE) $(MFLAGS) depend-lib; \
	else \
		echo "run configure with $(BUILD_OPT) to depend $(LIBBASE)"; \
	fi

install-common: FORCE
	@if test "$(BUILD_MOD)" = "yes" ; then \
		$(MAKE) $(MFLAGS) install-mod; \
	elif test "$(BUILD_LIB)" = "yes" ; then \
		$(MAKE) $(MFLAGS) install-lib; \
	else \
		echo "run configure with $(BUILD_OPT) to install $(LIBBASE)"; \
	fi

all-local-mod:
all-mod: $(LIBRARY) all-local-mod FORCE

all-local-lib:
all-lib: $(LIBSTAT) all-local-lib FORCE

install-mod: $(LIBRARY)
	@-$(MKDIR) $(moduledir)
	$(LTINSTALL) $(INSTALLFLAGS) -m 755 $(LIBRARY) $(moduledir)

install-local-lib:
install-lib: install-local-lib FORCE

lint-local-lib:
lint-lib: lint-local-lib FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

5lint-local-lib:
5lint-lib: 5lint-local-lib FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

clean-local-lib:
clean-lib: 	clean-local-lib FORCE
	$(RM) $(LIBRARY) $(LIBSTAT) $(MODULE) *.o *.lo a.out core .libs/*

depend-local-lib:
depend-lib: depend-local-lib FORCE

COMPILE = $(LIBTOOL) $(LTFLAGS) --mode=compile $(CC) $(CFLAGS) -c
MKDEPFLAG = -l

.SUFFIXES: .c .o .lo

.c.lo:
	$(COMPILE) $<

Makefile: $(top_srcdir)/build/mod.mk

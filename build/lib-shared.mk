# $OpenLDAP$
## Copyright 1998-2000 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makefile Template for Shared Libraries
##

MKDEPFLAG = -l

.SUFFIXES: .c .o .lo

.c.lo:
	$(LTCOMPILE_LIB) $<

#
# symlinks for libraries: UNIX and Windows (a.k.a. NT) need to be handled
# differently. In UNIX, the static and shared libraries, as well as shared
# library symlinks, can all be symlinked in the 'libraries' directory. In
# Windows, only the static library (.a file) or the shared library (.dll)
# file should be present. The current mingw linker (i.e. ld) WILL look
# for a .dll file at link time and internally generate an import library
# for it. However, ld will not do this if a static library is present.
# That doesn't seem very correct, but that's the behavior, like it or not.
#
# Note that there doesn't seem to be a true need for the .la file at
# this level, so it is left out.
#
# The set of symlinks are determined by examining the library's .la file.
#
$(LIBRARY): version.lo
	$(LTLINK_LIB) -o $@ $(OBJS) version.lo $(LINK_LIBS)
	@d=`$(PWD)`; b=`$(BASENAME) $$d`; \
	echo cd ..; \
	cd ..; \
	arlib=`grep '^old_library=' $$b/$@`; \
	arlib=`expr "$$arlib" : "[^']*'\(.*\)'"`; \
	libs=$$arlib; \
	if test "$(BUILD_LIBS_DYNAMIC)" = "shared"; then \
		shlibs=`grep '^library_names' $$b/$@`; \
		shlibs=`expr "$$shlibs" : "[^']*'\(.*\)'"`; \
		libs="$$libs $$shlibs"; \
	fi; \
	for i in $$libs; do \
		echo $(RM) $$i; \
		$(RM) $$i; \
		echo $(LN_S) $$b/.libs/$$i $$i; \
		$(LN_S) $$b/.libs/$$i $$i; \
	done

Makefile: $(top_srcdir)/build/lib-shared.mk


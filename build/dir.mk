## Copyright 1998,1999 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makes subdirectories
##

all-common install-common clean-common veryclean-common depend-common: FORCE
	@t=`echo $@ | cut -d- -f1`; \
	echo "Making $$t in `$(PWD)`"; \
	for i in $(SUBDIRS); do \
		echo "  Entering subdirectory $$i to execute:"; \
		echo "    $(MAKE) $(MFLAGS) $$t"; \
		( cd $$i; $(MAKE) $(MFLAGS) $$t ); \
	done

Makefile: $(top_srcdir)/build/dir.mk

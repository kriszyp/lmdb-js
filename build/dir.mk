## Copyright 1998,1999 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makes subdirectories
##

all-common install-common clean-common veryclean-common depend-common: FORCE
	@T=`echo $@ | cut -d- -f1`; echo "Making $$T in `$(PWD)`"; \
	 $(MAKE) $(MFLAGS) $(SUBDIRS) TARG=$$T

$(SUBDIRS): FORCE
	@echo "  Entering subdirectory $@"; cd $@; $(MAKE) $(MFLAGS) $(TARG); \
	echo ""

Makefile: $(top_srcdir)/build/dir.mk

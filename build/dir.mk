# $OpenLDAP$
## Copyright 1998-2000 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makes subdirectories
##


all-common: FORCE
	@echo "Making all in `$(PWD)`"
	@for i in $(SUBDIRS) $(ALLDIRS); do 		\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) all );		\
		echo " ";								\
	done

install-common: FORCE
	@echo "Making install in `$(PWD)`"
	@for i in $(SUBDIRS) $(INSTALLDIRS); do 	\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) install );	\
		echo " ";								\
	done

clean-common: FORCE
	@echo "Making clean in `$(PWD)`"
	@for i in $(SUBDIRS) $(CLEANDIRS); do		\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) clean );	\
		echo " ";								\
	done

veryclean-common: FORCE
	@echo "Making veryclean in `$(PWD)`"
	@for i in $(SUBDIRS) $(CLEANDIRS); do		\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) veryclean );	\
		echo " ";								\
	done

depend-common: FORCE
	@echo "Making depend in `$(PWD)`"
	@for i in $(SUBDIRS) $(DEPENDDIRS); do		\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) depend );	\
		echo " ";								\
	done

Makefile: $(top_srcdir)/build/dir.mk

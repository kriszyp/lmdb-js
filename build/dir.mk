##---------------------------------------------------------------------------
##
## Makes subdirectories
##


all-common: all-local FORCE
	@echo "Making all in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) all );		\
		echo " ";								\
	done

install-common: install-local FORCE
	@echo "Making install in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) install );	\
		echo " ";								\
	done

clean-common: clean-local FORCE
	@echo "Making clean in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) clean );	\
		echo " ";								\
	done

veryclean-common: veryclean-local FORCE
	@echo "Making veryclean in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) veryclean );	\
		echo " ";								\
	done

depend-common: depend-local FORCE
	@echo "Making depend in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) depend );	\
		echo " ";								\
	done

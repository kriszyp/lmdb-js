##
## Makes subdirectories
##

all:	allsubs
allsubs: FORCE
	@echo "Making all in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) all );		\
		echo " ";								\
	done

install:	installsubs
installsubs: FORCE
	@echo "Making install in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) install );	\
		echo " ";								\
	done

clean:	cleansubs
cleansubs: FORCE
	@echo "Making clean in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) clean );	\
		echo " ";								\
	done

veryclean: verysubs
verysubs: FORCE
	@echo "Making veryclean in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) veryclean );	\
		echo " ";								\
	done

depend: dependsubs
dependsubs: FORCE
	@echo "Making depend in `$(PWD)`"
	@for i in $(SUBDIRS); do 					\
		echo "  Entering subdirectory $$i";		\
		( cd $$i; $(MAKE) $(MFLAGS) depend );	\
		echo " ";								\
	done

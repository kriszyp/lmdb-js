##---------------------------------------------------------------------------
##
## Makefile Template for Static Libraries
##

$(LIBRARY): version.o
	$(AR) ru $@ $(OBJS) version.o
	@$(RANLIB) $@;	\
	$(RM) ../$@;	\
	(d=`$(PWD)` ; $(LN_S) `$(BASENAME) $$d`/$@ ../$@)

Makefile: $(top_srcdir)/build/lib-static.mk

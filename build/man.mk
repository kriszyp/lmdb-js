##---------------------------------------------------------------------------
##
## Makefile Template for Manual Pages
##

MANDIR=$(mandir)/man$(MANSECT)

install-common: FORCE
	-$(MKDIR) -p $(MANDIR)
	@TMPMAN=/tmp/ldapman.$$$$$(MANCOMPRESSSUFFIX); \
	VERSION=`$(CAT) $(VERSIONFILE)`; \
	for page in *.$(MANSECT); do \
		$(SED) -e "s%LDVERSION%$$VERSION%" \
			-e 's%ETCDIR%$(sysconfdir)%' \
			-e 's%SYSCONFDIR%$(sysconfdir)%' \
			-e 's%SBINDIR%$(sbindir)%' \
			-e 's%BINDIR%$(bindir)%' \
			-e 's%LIBDIR%$(libdir)%' \
			-e 's%LIBEXECDIR%$(libexecdir)%' \
			$$page | $(MANCOMPRESS) > $$TMPMAN; \
		echo "installing $(MANDIR)/$$page"; \
		$(RM) $(MANDIR)/$$page $(MANDIR)/$$page$(MANCOMPRESSSUFFIX); \
		$(INSTALL) $(INSTALLFLAGS) -m 644 $$TMPMAN $(MANDIR)/$$page$(MANCOMPRESSSUFFIX); \
		if [ -f "$$page.links" ]; then \
			for link in `$(CAT) $$page.links`; do \
				echo "installing $(MANDIR)/$$link as link to $$page"; \
				$(RM) $(INSTDIR)/$$link $(MANDIR)/$$link$(MANCOMPRESSSUFFIX); \
				ln -sf $$page$(MANCOMPRESSSUFFIX) $(MANDIR)/$$link$(MANCOMPRESSSUFFIX); \
			done; \
		fi; \
	done; \
	$(RM) $$TMPMAN

Makefile: $(top_srcdir)/build/lib.mk


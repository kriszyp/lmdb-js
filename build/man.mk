## Copyright 1998,1999 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makefile Template for Manual Pages
##

MANDIR=$(mandir)/man$(MANSECT)

install-common: FORCE
	-$(MKDIR) -p $(MANDIR)
	@TMPMAN=/tmp/ldapman.$$$$$(MANCOMPRESSSUFFIX); \
	VERSION=`$(CAT) $(VERSIONFILE)`; \
	cd $(srcdir); \
	for page in *.$(MANSECT); do \
		$(SED) -e "s%LDVERSION%$$VERSION%" \
			-e 's%ETCDIR%$(sysconfdir)%' \
			-e 's%LOCALSTATEDIR%$(localstatedir)%' \
			-e 's%SYSCONFDIR%$(sysconfdir)%' \
			-e 's%DATADIR%$(datadir)%' \
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
				$(RM) $(MANDIR)/$$link $(MANDIR)/$$link$(MANCOMPRESSSUFFIX); \
				ln -sf $$page$(MANCOMPRESSSUFFIX) $(MANDIR)/$$link$(MANCOMPRESSSUFFIX); \
			done; \
		fi; \
	done; \
	$(RM) $$TMPMAN

Makefile: $(top_srcdir)/build/lib.mk


## Copyright 1998,1999 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makefile Template for Manual Pages
##

MANDIR=$(mandir)/man$(MANSECT)
TMP_SUFFIX=tmp

all-common: FORCE
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
			$$page > $$page.$(TMP_SUFFIX); \
	done
	touch all-common

install-common:
	-$(MKDIR) -p $(MANDIR)
	for page in *.$(MANSECT); do \
		echo "installing $(MANDIR)/$$page"; \
		$(RM) $(MANDIR)/$$page; \
		$(INSTALL) $(INSTALLFLAGS) -m 644 $$page.$(TMP_SUFFIX) $(MANDIR)/$$page; \
		if [ -f "$$page.links" ]; then \
			for link in `$(CAT) $$page.links`; do \
				echo "installing $(MANDIR)/$$link as link to $$page"; \
				$(RM) $(INSTDIR)/$$link $(MANDIR)/$$link; \
				$(LN_S) -sf $$page $(MANDIR)/$$link; \
			done; \
		fi; \
	done; \
	$(RM) $$TMPMAN

Makefile: $(top_srcdir)/build/lib.mk

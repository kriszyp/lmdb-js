# $OpenLDAP$
## Copyright 1998-2000 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##---------------------------------------------------------------------------
##
## Makefile Template for Manual Pages
##

MANDIR=$(mandir)/man$(MANSECT)
TMP_SUFFIX=tmp

all-common:
	PAGES=`cd $(srcdir); echo *.$(MANSECT)`; \
	for page in $$PAGES; do \
		$(SED) -e "s%LDVERSION%$(VERSION)%" \
			-e 's%ETCDIR%$(sysconfdir)%' \
			-e 's%LOCALSTATEDIR%$(localstatedir)%' \
			-e 's%SYSCONFDIR%$(sysconfdir)%' \
			-e 's%DATADIR%$(datadir)%' \
			-e 's%SBINDIR%$(sbindir)%' \
			-e 's%BINDIR%$(bindir)%' \
			-e 's%LIBDIR%$(libdir)%' \
			-e 's%LIBEXECDIR%$(libexecdir)%' \
			$(srcdir)/$$page > $$page.$(TMP_SUFFIX); \
	done

install-common:
	-$(MKDIR) $(DESTDIR)$(MANDIR)
	PAGES=`cd $(srcdir); echo *.$(MANSECT)`; \
	for page in $$PAGES; do \
		echo "installing $(MANDIR)/$$page"; \
		$(RM) $(DESTDIR)$(MANDIR)/$$page; \
		$(INSTALL) $(INSTALLFLAGS) -m 644 $$page.$(TMP_SUFFIX) $(DESTDIR)$(MANDIR)/$$page; \
		if test -f "$(srcdir)/$$page.links" ; then \
			for link in `$(CAT) $(srcdir)/$$page.links`; do \
				echo "installing $(MANDIR)/$$link as link to $$page"; \
				$(RM) $(DESTDIR)$(MANDIR)/$$link ; \
				$(LN_S) $$page $(DESTDIR)$(MANDIR)/$$link; \
			done; \
		fi; \
	done

clean-common:   FORCE
	$(RM) *.tmp all-common

Makefile: $(top_srcdir)/build/man.mk

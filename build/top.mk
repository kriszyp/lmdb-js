# $OpenLDAP$
## Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
## All rights reserved.
##
## Redistribution and use in source and binary forms are permitted only
## as authorized by the OpenLDAP Public License.  A copy of this
## license is available at http://www.OpenLDAP.org/license.html or
## in file LICENSE in the top-level directory of the distribution.
##
PACKAGE= @PACKAGE@
VERSION= @VERSION@

@SET_MAKE@
SHELL = /bin/sh

top_builddir = @top_builddir@

srcdir = @srcdir@
top_srcdir = @top_srcdir@
VPATH = @srcdir@
prefix = @prefix@
exec_prefix = @exec_prefix@
ldap_subdir = @ldap_subdir@

bindir = @bindir@
datadir = @datadir@$(ldap_subdir)
includedir = @includedir@
infodir = @infodir@
libdir = @libdir@
libexecdir = @libexecdir@
localstatedir = @localstatedir@
mandir = @mandir@
moduledir = @libexecdir@$(ldap_subdir)
sbindir = @sbindir@
sharedstatedir = @sharedstatedir@
sysconfdir = @sysconfdir@$(ldap_subdir)

EXEEXT = @EXEEXT@
OBJEXT = @OBJEXT@

INSTALL = @INSTALL@
INSTALL_PROGRAM = @INSTALL_PROGRAM@
INSTALL_DATA = @INSTALL_DATA@
INSTALL_SCRIPT = @INSTALL_SCRIPT@

LINT = lint
5LINT = 5lint

MKDEP = $(top_srcdir)/build/mkdep $(MKDEPFLAG) \
	-d "$(srcdir)" -c "$(MKDEP_CC)" -m "$(MKDEP_CFLAGS)"
MKDEP_CC	= @OL_MKDEP@
MKDEP_CFLAGS = @OL_MKDEP_FLAGS@

MKVERSION = $(top_srcdir)/build/mkversion -v "$(VERSION)"

LIBTOOL = @LIBTOOL@
LIBVERSION = 0:0:0
LTVERSION = -version-info $(LIBVERSION)
LTLINK  = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS)
LTINSTALL = $(LIBTOOL) --mode=install $(INSTALL) 

# Misc UNIX commands used in build environment
AR = ar
AWK = @AWK@
BASENAME = basename
CAT = cat
CHMOD = chmod
DATE = date
HOSTNAME = uname -n
LN = ln
LN_H = @LN_H@
LN_S = @LN_S@
MAKEINFO = @MAKEINFO@
MKDIR = mkdir -p
MV = mv
PWD = pwd
RANLIB = @RANLIB@
RM = rm -f
SED = sed

# Misc UNIX commands used in programs
EDITOR = @EDITOR@
FINGER = @FINGER@
SENDMAIL = @SENDMAIL@

# For manual pages
# MANCOMPRESS=@MANCOMPRESS@
# MANCOMPRESSSUFFIX=@MANCOMPRESSSUFFIX@
MANCOMPRESS=$(CAT)
MANCOMPRESSSUFFIX=

INCLUDEDIR= $(top_srcdir)/include
LDAP_INCPATH= -I$(LDAP_INCDIR) -I$(INCLUDEDIR)
LDAP_LIBADIR= $(top_builddir)/libraries
LDAP_LIBPATH= -L$(LDAP_LIBADIR)

LUTIL_LIBS = @LUTIL_LIBS@
LDIF_LIBS = @LDIF_LIBS@
LDBM_LIBS = @LDBM_LIBS@
LTHREAD_LIBS = @LTHREAD_LIBS@

LDAP_LIBLBER_DEPEND = $(LDAP_LIBDIR)/liblber/liblber.la
LDAP_LIBLDAP_DEPEND = $(LDAP_LIBDIR)/libldap/libldap.la
LDAP_LIBLDIF_DEPEND = $(LDAP_LIBDIR)/libldif/libldif.a
LDAP_LIBLUTIL_DEPEND = $(LDAP_LIBDIR)/liblutil/liblutil.a

LDAP_LIBAVL_DEPEND = $(LDAP_LIBDIR)/libavl/libavl.a
LDAP_LIBLDBM_DEPEND = $(LDAP_LIBDIR)/libldbm/libldbm.a
LDAP_LIBLTHREAD_DEPEND = $(LDAP_LIBDIR)/libldap_r/libldap_r.la

LDAP_LIBDEPEND = $(LDAP_LIBLDAP_DEPEND) $(LDAP_LIBLBER_DEPEND) \
	$(LDAP_LIBLDIF_DEPEND) $(LDAP_LIBLUTIL_DEPEND)
SLAPD_LIBDEPEND = $(LDAP_LIBDEPEND) $(LDAP_LIBAVL_DEPEND) \
	$(LDAP_LIBLDBM_DEPEND) $(LDAP_LIBLTHREAD_DEPEND)

WRAP_LIBS = @WRAP_LIBS@
# AutoConfig generated 
AC_CC	= @CC@
AC_CFLAGS = @CFLAGS@
AC_DEFS = @CPPFLAGS@ # @DEFS@
AC_LDFLAGS = @LDFLAGS@
AC_LIBS = @LIBS@

KRB_LIBS = @KRB_LIBS@
SASL_LIBS = @SASL_LIBS@
TLS_LIBS = @TLS_LIBS@
SECURITY_LIBS = @SASL_LIBS@ @KRB_LIBS@ @TLS_LIBS@

MODULES_CPPFLAGS = @SLAPD_MODULES_CPPFLAGS@
MODULES_LDFLAGS = @SLAPD_MODULES_LDFLAGS@
MODULES_LIBS = @MODULES_LIBS@
TERMCAP_LIBS = @TERMCAP_LIBS@
SLAPD_PERL_LDFLAGS = @SLAPD_PERL_LDFLAGS@
LINK_BINS_DYNAMIC = @LINK_BINS_DYNAMIC@

LDAPD_LIBS = @LDAPD_LIBS@
SLAPD_LIBS = @SLAPD_LIBS@ @SLAPD_PERL_LDFLAGS@
SLURPD_LIBS = @SLURPD_LIBS@

# Our Defaults
CC = $(AC_CC)
DEFS = $(LDAP_INCPATH) $(XINCPATH) $(XDEFS) $(AC_DEFS) $(DEFINES)
CFLAGS = $(AC_CFLAGS) $(DEFS)
LDFLAGS = $(LDAP_LIBPATH) $(AC_LDFLAGS) $(XLDFLAGS)
LIBS = $(XLIBS) $(XXLIBS) $(AC_LIBS) $(XXXLIBS)

all:		all-common all-local FORCE
install:	install-common install-local FORCE
clean:		clean-common clean-local FORCE
veryclean:	veryclean-common veryclean-local FORCE
depend:		depend-common depend-local FORCE

# empty common rules
all-common:
install-common:
clean-common:
veryclean-common:	clean-common FORCE
depend-common:
lint-common:
lint5-common:

# empty local rules
all-local:
install-local:
clean-local:
veryclean-local:	clean-local FORCE
depend-local:
lint-local:
lint5-local:

veryclean: FORCE
	$(RM) Makefile
	$(RM) -r .libs

Makefile: Makefile.in $(top_srcdir)/build/top.mk

# empty rule for forcing rules
FORCE:

##---------------------------------------------------------------------------


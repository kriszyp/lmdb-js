##
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
datadir = @datadir@/$(ldap_subdir)
includedir = @includedir@
infodir = @infodir@
libdir = @libdir@
libexecdir = @libexecdir@
localstatedir = @localstatedir@
mandir = @mandir@
sbindir = @sbindir@
sharedstatedir = @sharedstatedir@
sysconfdir = @sysconfdir@/$(ldap_subdir)

INSTALL = @INSTALL@
INSTALL_PROGRAM = @INSTALL_PROGRAM@
INSTALL_DATA = @INSTALL_DATA@
INSTALL_SCRIPT = @INSTALL_SCRIPT@

MV = mv
LN = ln
LN_S = @LN_S@
RM = rm -f
MAKEINFO = @MAKEINFO@
RANLIB = @RANLIB@
AR = ar

LINT = lint
5LINT = 5lint
MKDEP = $(top_srcdir)/build/mkdep $(MKDEPFLAG) -c "$(CC)"

LIBTOOL = @LIBTOOL@
LIBVERSION = 0:0:0
LTLINK  = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LFLAGS) $(LTVERSION)
LTINSTALL = $(LIBTOOL) --mode=install $(INSTALL) 

# Misc UNIX commands used in makefiles
SED = sed
DATE = date
HOSTNAME = uname -n
BASENAME = basename
PWD = pwd
CAT = cat
MKDIR = mkdir -p
CHMOD = chmod

# Misc UNIX commands used in programs
EDITOR = @EDITOR@
FINGER = @FINGER@
SENDMAIL = @SENDMAIL@

# For manual pages
# MANCOMPRESS=@MANCOMPRESS@
# MANCOMPRESSSUFFIX=@MANCOMPRESSSUFFIX@
MANCOMPRESS=$(CAT)
MANCOMPRESSSUFFIX=

# Version
VERSIONFILE = $(top_srcdir)/build/version

INCLUDEDIR= $(top_srcdir)/include
LDAP_INCPATH= -I$(LDAP_INCDIR) -I$(INCLUDEDIR)
LDAP_LIBADIR= $(top_builddir)/libraries
LDAP_LIBPATH= -L$(LDAP_LIBADIR)

LDAP_LIBLBER = $(LDAP_LIBADIR)/liblber/liblber.la
LDAP_LIBLDAP = $(LDAP_LIBADIR)/libldap/libldap.la

LDAP_LIBLBER_DEPEND = $(LDAP_LIBDIR)/liblber/liblber.la
LDAP_LIBLDAP_DEPEND = $(LDAP_LIBDIR)/libldap/libldap.la

LDAP_LIBS = $(LDAP_LIBPATH) -lldif $(LDAP_LIBLDAP) $(LDAP_LIBLBER)
LDAP_LIBDEPEND = $(LDAP_LIBDIR)/libldif.a $(LDAP_LIBLDAP) $(LDAP_LIBLBER)

# AutoConfig generated 
AC_CC	= @CC@
AC_DEFS = @CPPFLAGS@ @DEFS@
AC_LIBS = @LDFLAGS@ @LIBS@
AC_CFLAGS = @CFLAGS@
AC_LDFLAGS =

KRB_LIBS = @KRB_LIBS@
TERMCAP_LIBS = @TERMCAP_LIBS@

# Our Defaults
CC = $(AC_CC)
DEFS = $(LDAP_INCPATH) $(XINCPATH) $(XDEFS) $(AC_DEFS) 
LIBS = $(LDAP_LIBS) $(XLIBS) $(AC_LIBS)

CFLAGS = $(AC_CFLAGS) $(DEFS) $(DEFINES)
LDFLAGS = $(AC_LDFLAGS)

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

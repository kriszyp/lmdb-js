##
## Copyright 1998 The OpenLDAP Foundation
## COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
## of this package for details.
##
@SET_MAKE@

SHELL = /bin/sh

srcdir = @srcdir@
top_srcdir = @top_srcdir@
VPATH = @srcdir@
prefix = @prefix@
exec_prefix = @exec_prefix@

bindir = @bindir@
sbindir = @sbindir@
libexecdir = @libexecdir@
datadir = @datadir@
sysconfdir = @sysconfdir@/ldap
sharedstatedir = @sharedstatedir@
localstatedir = @localstatedir@
libdir = @libdir@
infodir = @infodir@
mandir = @mandir@
includedir = @includedir@

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
MKDEP = $(top_srcdir)/build/mkdep

# Misc UNIX commands used in makefiles
SED = sed
DATE = date
HOSTNAME = uname -n
BASENAME = basename
PWD = pwd
CAT = cat
MKDIR = mkdir
CHMOD = chmod

# Misc UNIX commands used in programs
EDITOR = @EDITOR@
FINGER = @FINGER@
SENDMAIL = @SENDMAIL@

# Version
VERSIONFILE = $(top_srcdir)/build/version

INCLUDEDIR = $(top_srcdir)/include
LDAP_INCPATH = -I$(LDAP_INCDIR) -I$(INCLUDEDIR)
LDAP_LIBPATH = -L$(LDAP_LIBDIR)

LDAP_LIBS = $(LDAP_LIBPATH) -lldif -lldap -llber
LDAP_LIBDEPEND = $(LDAP_LIBDIR)/libldif.a $(LDAP_LIBDIR)/libldap.a $(LDAP_LIBDIR)/liblber.a

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

all:		all-common FORCE
install:	install-common FORCE
clean:		clean-common FORCE
veryclean:	veryclean-common FORCE
depend:		depend-common FORCE

# empty local rules
all-local:
install-local:
clean-local:
veryclean-local:
depend-local:
lint-local:
lint5-local:

Makefile: Makefile.in $(top_srcdir)/build/top.mk

# empty rule for forcing rules
FORCE:

##---------------------------------------------------------------------------

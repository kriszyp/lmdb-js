# $OpenLDAP$
## Copyright 1998-2003 The OpenLDAP Foundation, Redwood City, California, USA
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.  A copy of this license is available at
## http://www.OpenLDAP.org/license.html or in file LICENSE in the
## top-level directory of the distribution.
##
PACKAGE= @PACKAGE@
VERSION= @VERSION@
RELEASEDATE= @OPENLDAP_RELEASE_DATE@

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
schemadir = $(sysconfdir)/schema

PLAT = @PLAT@
EXEEXT = @EXEEXT@
OBJEXT = @OBJEXT@

BUILD_LIBS_DYNAMIC = @BUILD_LIBS_DYNAMIC@

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

SHTOOL = $(top_srcdir)/build/shtool

LIBTOOL = @LIBTOOL@
LIBVERSION = @OPENLDAP_LIBVERSION@
LTVERSION = -version-info $(LIBVERSION)

# libtool --only flag for libraries: platform specific
NT_LTONLY_LIB = # --only-$(BUILD_LIBS_DYNAMIC)
LTONLY_LIB = $(@PLAT@_LTONLY_LIB)

# libtool --only flag for modules: depends on linkage of module
# The BUILD_MOD_DYNAMIC macro is defined in each backend Makefile.in file
LTONLY_MOD = # --only-$(BUILD_MOD_DYNAMIC)

# platform-specific libtool flags
NT_LTFLAGS_LIB = -no-undefined -avoid-version -rpath $(libdir)
NT_LTFLAGS_MOD = -no-undefined -avoid-version -rpath $(moduledir)
UNIX_LTFLAGS_LIB = $(LTVERSION) -rpath $(libdir)
UNIX_LTFLAGS_MOD = $(LTVERSION) -rpath $(moduledir)

# libtool flags
LTFLAGS     = $(@PLAT@_LTFLAGS)
LTFLAGS_LIB = $(@PLAT@_LTFLAGS_LIB)
LTFLAGS_MOD = $(@PLAT@_LTFLAGS_MOD)

# LIB_DEFS defined in liblber and libldap Makefile.in files.
# MOD_DEFS defined in backend Makefile.in files.

# platform-specific LINK_LIBS defined in various Makefile.in files.
# LINK_LIBS referenced in library and module link commands.
LINK_LIBS = $(@PLAT@_LINK_LIBS)

LTSTATIC = @LTSTATIC@

LTLINK   = $(LIBTOOL) --mode=link \
	$(CC) $(LTSTATIC) $(LT_CFLAGS) $(LDFLAGS) $(LTFLAGS)

LTCOMPILE_LIB = $(LIBTOOL) $(LTONLY_LIB) --mode=compile \
	$(CC) $(LT_CFLAGS) $(LT_CPPFLAGS) $(LIB_DEFS) -c

LTLINK_LIB = $(LIBTOOL) $(LTONLY_LIB) --mode=link \
	$(CC) $(LT_CFLAGS) $(LDFLAGS) $(LTFLAGS_LIB)

LTCOMPILE_MOD = $(LIBTOOL) $(LTONLY_MOD) --mode=compile \
	$(CC) $(LT_CFLAGS) $(LT_CPPFLAGS) $(MOD_DEFS) -c

LTLINK_MOD = $(LIBTOOL) $(LTONLY_MOD) --mode=link \
	$(CC) $(LT_CFLAGS) $(LDFLAGS) $(LTFLAGS_MOD)

LTINSTALL = $(LIBTOOL) --mode=install $(INSTALL) 
LTFINISH = $(LIBTOOL) --mode=finish

# Misc UNIX commands used in build environment
AR = @AR@
BASENAME = basename
CAT = cat
CHMOD = chmod
DATE = date
HOSTNAME = $(SHTOOL) echo -e "%h%d"
LN = ln
LN_H = @LN_H@
LN_S = @LN_S@
MAKEINFO = @MAKEINFO@
MKDIR = $(SHTOOL) mkdir -p
MV = mv
PWD = pwd
RANLIB = @RANLIB@
RM = rm -f
SED = sed

# For manual pages
# MANCOMPRESS=@MANCOMPRESS@
# MANCOMPRESSSUFFIX=@MANCOMPRESSSUFFIX@
MANCOMPRESS=$(CAT)
MANCOMPRESSSUFFIX=

INCLUDEDIR= $(top_srcdir)/include
LDAP_INCPATH= -I$(LDAP_INCDIR) -I$(INCLUDEDIR)
LDAP_LIBDIR= $(top_builddir)/libraries

LUTIL_LIBS = @LUTIL_LIBS@
LDBM_LIBS = @LDBM_LIBS@
LTHREAD_LIBS = @LTHREAD_LIBS@

LDAP_LIBLBER_LA = $(LDAP_LIBDIR)/liblber/liblber.la
LDAP_LIBLDAP_LA = $(LDAP_LIBDIR)/libldap/libldap.la
LDAP_LIBLDAP_R_LA = $(LDAP_LIBDIR)/libldap_r/libldap_r.la

LDAP_LIBLDBM_A_no =
LDAP_LIBLDBM_A_yes = $(LDAP_LIBDIR)/libldbm/libldbm.a

LDAP_LIBAVL_A = $(LDAP_LIBDIR)/libavl/libavl.a
LDAP_LIBLDBM_A = $(LDAP_LIBLDBM_A_@BUILD_LDBM@)
LDAP_LIBREWRITE_A = $(LDAP_LIBDIR)/librewrite/librewrite.a
LDAP_LIBLUNICODE_A = $(LDAP_LIBDIR)/liblunicode/liblunicode.a
LDAP_LIBLUTIL_A = $(LDAP_LIBDIR)/liblutil/liblutil.a

LDAP_L = $(LDAP_LIBLUTIL_A) \
	$(LDAP_LIBLDAP_LA) $(LDAP_LIBLBER_LA)
SLURPD_L = $(LDAP_LIBLUTIL_A) \
	$(LDAP_LIBLDAP_R_LA) $(LDAP_LIBLBER_LA)
SLAPD_L = $(LDAP_LIBAVL_A) $(LDAP_LIBLDBM_A) \
	$(LDAP_LIBLUNICODE_A) $(LDAP_LIBREWRITE_A) \
	$(SLURPD_L)

WRAP_LIBS = @WRAP_LIBS@
# AutoConfig generated 
AC_CC	= @CC@
AC_CFLAGS = @CFLAGS@
AC_DEFS = @CPPFLAGS@ # @DEFS@
AC_LDFLAGS = @LDFLAGS@
AC_LIBS = @LIBS@

KRB4_LIBS = @KRB4_LIBS@
KRB5_LIBS = @KRB5_LIBS@
KRB_LIBS = @KRB4_LIBS@ @KRB5_LIBS@
SASL_LIBS = @SASL_LIBS@
TLS_LIBS = @TLS_LIBS@
AUTH_LIBS = @AUTH_LIBS@
SECURITY_LIBS = $(SASL_LIBS) $(KRB_LIBS) $(TLS_LIBS) $(AUTH_LIBS)

MODULES_CPPFLAGS = @SLAPD_MODULES_CPPFLAGS@
MODULES_LDFLAGS = @SLAPD_MODULES_LDFLAGS@
MODULES_LIBS = @MODULES_LIBS@
TERMCAP_LIBS = @TERMCAP_LIBS@
SLAPD_PERL_LDFLAGS = @SLAPD_PERL_LDFLAGS@

SLAPD_SQL_LDFLAGS = @SLAPD_SQL_LDFLAGS@
SLAPD_SQL_INCLUDES = @SLAPD_SQL_INCLUDES@
SLAPD_SQL_LIBS = @SLAPD_SQL_LIBS@

SLAPD_LIBS = @SLAPD_LIBS@ @SLAPD_PERL_LDFLAGS@ @SLAPD_SQL_LDFLAGS@ @SLAPD_SQL_LIBS@ @SLAPD_SLP_LIBS@
SLURPD_LIBS = @SLURPD_LIBS@

# Our Defaults
CC = $(AC_CC)
DEFS = $(LDAP_INCPATH) $(XINCPATH) $(XDEFS) $(AC_DEFS) $(DEFINES)
CFLAGS = $(AC_CFLAGS) $(DEFS)
LDFLAGS = $(LDAP_LIBPATH) $(AC_LDFLAGS) $(XLDFLAGS)
LIBS = $(XLIBS) $(XXLIBS) $(AC_LIBS) $(XXXLIBS)

LT_CFLAGS = $(AC_CFLAGS)
LT_CPPFLAGS = $(DEFS)

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

pathtest:
	$(SHTOOL) --version

# empty rule for forcing rules
FORCE:

##---------------------------------------------------------------------------


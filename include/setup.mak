# $OpenLDAP$
#
# Copyright 1998-2004 The OpenLDAP Foundation, All Rights Reserved.
# COPYING RESTRICTIONS APPLY, see COPYRIGHT file
#

!include ../build/version.var

!if "$(ol_patch)" != "X"
ol_version=$(ol_major).$(ol_minor).$(ol_patch)
ol_type=Release
!elseif "$(ol_minor)" != "X"
ol_version=$(ol_major).$(ol_minor).$(ol_patch)
ol_type=Engineering
!else
ol_version=$(ol_major).$(ol_minor)
ol_type=Devel
!endif
ol_string="$(ol_package) $(ol_version)-$(ol_type)"

.SUFFIXES: .nt

.nt.h:
	copy $*.nt $*.h

all: setup.txt

setup.txt: lber_types.h ldap_config.h ldap_features.h portable.h setup.mak
	copy setup.mak setup.txt

lber_types.h: lber_types.nt
ldap_config.h: ldap_config.nt
ldap_features.h: ldap_features.nt

# note - the edlin script has non-printable characters:
# you must use a Ctrl-C to terminate the (i)nput command
portable.h: portable.nt
	echo Setting up $(ol_string)...
	copy portable.nt portable.h
	edlin portable.h < <<
1,#sOPENLDAP_PACKAGE
d
i
#define OPENLDAP_PACKAGE "$(ol_package)"


1,#sOPENLDAP_VERSION
d
i
#define OPENLDAP_VERSION "$(ol_version)"


e
<<NOKEEP


# $OpenLDAP$
#
# Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
# COPYING RESTRICTIONS APPLY, see COPYRIGHT file
#

.SUFFIXES: .nt

.nt.h:
	copy $*.nt $*.h

all: setup.txt ol_version0.h

setup.txt: lber_types.h ldap_config.h ldap_features.h portable.h setup.mak
	copy setup.mak setup.txt

lber_types.h: lber_types.nt
ldap_config.h: ldap_config.nt
ldap_features.h: ldap_features.nt
portable.h: portable.nt

ol_version0.h:	../build/version.h
	$(CPP) /EP /D_OLV_PKG=\"OpenLDAP\" /D_OLV_VER=\"2.1.16\" -D_OLV_WHO=\"$(USERNAME)@$(COMPUTERNAME)\" $? > $@

#
# Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
# COPYING RESTRICTIONS APPLY, see COPYRIGHT file
#

all: setup.txt

setup.txt: lber_types.h ldap_config.h ldap_features.h portable.h
        copy setup.mak setup.txt

lber_types.h: lber_types.h.nt
	copy lber_types.h.nt lber_types.h

ldap_config.h: ldap_config.h.nt
	copy ldap_config.h.nt ldap_config.h

ldap_features.h: ldap_features.h.nt
	copy ldap_features.h.nt ldap_features.h

portable.h: portable.h.nt
	copy portable.h.nt portable.h


all: setup.txt

setup.txt: ldap_config.h ldap_features.h portable.h
        copy setup.mak setup.txt

ldap_config.h: ldap_config.h.nt
	copy ldap_config.h.nt ldap_config.h

ldap_features.h: ldap_features.h.nt
	copy ldap_features.h.nt ldap_features.h

portable.h: portable.h.nt
	copy portable.h.nt portable.h

/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * OpenLDAP API Test
 *      Written by: Pierangelo Masarati <ando@OpenLDAP.org>
 *
 * This program is designed to test the ldap_str2dn/ldap_dn2str
 * functions
 */
#include "portable.h"

#include <ac/stdlib.h>
#include <ac/string.h>

#include <stdio.h>

#include <ldap.h>
#include "ldif.h"
#include "lutil.h"
#include "lutil_ldap.h"
#include "ldap_defaults.h"

int
main(int argc, char *argv[])
{
	int 		rc, i, debug = -1;
	unsigned 	flags[ 2 ] = { 0U, 0U };
	char		*str, buf[1024];
	LDAPDN		*dn = NULL;

	if (argc < 2) {
		fprintf(stderr, "usage: dntest <dn> [flags-in[,...]] [flags-out[,...]]\n\n");
		fprintf(stderr, "\tflags-in:  V3,V2,DCE,PEDANTIC\n");
		fprintf(stderr, "\tflags-out: V3,V2,UFN,DCE,AD,PEDANTIC\n\n");
		return 0;
	}

	if (ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &debug) != LBER_OPT_SUCCESS) {
		fprintf(stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", debug);
	}
	if (ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug) != LDAP_OPT_SUCCESS) {
		fprintf(stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", debug);
	}

	if ( strcmp(argv[1], "-") == 0) {
		size_t len;
		
		fgets(buf, sizeof(buf), stdin);
		len = strlen(buf)-1;
		if (len >= 0 && buf[len] == '\n') {
			buf[len] = '\0';
		}
		str = buf;
	} else {
		str = argv[1];
	}

	if (argc >= 3) {
		for ( i = 0; i < argc-2; i++ ) {
			char *s, *e;
			for (s = argv[2+i]; s; s = e) {
				e = strchr(s, ',');
				if (e != NULL) {
					e[0] = '\0';
					e++;
				}
	
				if (!strcasecmp(s, "V3")) {
					flags[i] |= LDAP_DN_FORMAT_LDAPV3;
				} else if (!strcasecmp(s, "V2")) {
					flags[i] |= LDAP_DN_FORMAT_LDAPV2;
				} else if (!strcasecmp(s, "DCE")) {
					flags[i] |= LDAP_DN_FORMAT_DCE;
				} else if (!strcasecmp(s, "UFN")) {
					flags[i] |= LDAP_DN_FORMAT_UFN;
				} else if (!strcasecmp(s, "AD")) {
					flags[i] |= LDAP_DN_FORMAT_AD_CANONICAL;
				} else if (!strcasecmp(s, "PEDANTIC")) {
					flags[i] |= LDAP_DN_PEDANTIC;
				}
			}
		}
	}
				
	rc = ldap_str2dn(str, &dn, flags[0]);

	if ( rc == LDAP_SUCCESS && 
			ldap_dn2str( dn, &str, flags[argc > 3 ? 1 : 0] ) 
			== LDAP_SUCCESS ) {
		fprintf( stdout, "%s\n", str );
	}

	return 0;
}


/* $OpenLDAP$ */
/*
 * Copyright 1999 The OpenLDAP Foundation, All Rights Reserved.
 *
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file in the top level
 * directory of this package.
 */
/* Portions
 * Copyright (c) 1998 Will Ballantyne, ITSD, Government of BC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to ITSD, Government of BC. The name of ITSD
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/socket.h>
#include "slap.h"

/* 
 * given a normalized uppercased dn (or root part),
 * return an aliased dn if any of the alias suffixes match
 */
char *suffix_alias(
	Backend *be,
	char *dn )
{
	int 	i, dnLength;

	if(dn == NULL) return NULL;
	if(be == NULL) return dn;

	dnLength = strlen ( dn );

	for ( i = 0;
		be->be_suffixAlias != NULL && be->be_suffixAlias[i] != NULL;
		i += 2 )
	{
		int aliasLength = strlen (be->be_suffixAlias[i]);
		int diff = dnLength - aliasLength;

		if ( diff < 0 ) {
			/* alias is longer than dn */
			continue;
		} else if ( diff > 0 ) {
			if ( ! DNSEPARATOR(dn[diff-1]) ) {
				/* boundary is not at a DN separator */
				continue;
			}
			/* At a DN Separator */
			/* XXX or an escaped separator... oh well */
		}

		if (!strcmp(be->be_suffixAlias[i], &dn[diff])) {
			char *oldDN = dn;
			dn = ch_malloc( diff + strlen(be->be_suffixAlias[i+1]) + 1 );
			strncpy( dn, oldDN, diff );
			strcpy( &dn[diff], be->be_suffixAlias[i+1] );
			Debug( LDAP_DEBUG_ARGS,
				"suffix_alias: converted \"%s\" to \"%s\"\n",
				oldDN, dn, 0);
			free (oldDN);
			break;
		}
	}

	return dn;
}

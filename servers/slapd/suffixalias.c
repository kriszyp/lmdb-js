/* $OpenLDAP$ */
/*
 * Copyright 1999-2003 The OpenLDAP Foundation, All Rights Reserved.
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
void suffix_alias(
	Backend *be,
	struct berval *dn )
{
	int	i, dnLength;

	if(dn == NULL || be == NULL || dn->bv_len == 0)
		return;

	dnLength = dn->bv_len;

	for ( i = 0;
		be->be_suffixAlias != NULL && be->be_suffixAlias[i].bv_val != NULL;
		i += 2 )
	{
		int aliasLength = be->be_suffixAlias[i].bv_len;
		int diff = dnLength - aliasLength;

		if ( diff < 0 ) {
			/* alias is longer than dn */
			continue;
		} else if ( diff > 0 ) {
			if ( ! DN_SEPARATOR(dn->bv_val[diff-1]) ) {
				/* boundary is not at a DN separator */
				continue;
			}
			/* At a DN Separator */
			/* XXX or an escaped separator... oh well */
		}

		if (!strcmp(be->be_suffixAlias[i].bv_val, &dn->bv_val[diff])) {
			char *oldDN = dn->bv_val;
			dn->bv_len = diff + be->be_suffixAlias[i+1].bv_len;
			dn->bv_val = ch_malloc( dn->bv_len + 1 );
			strncpy( dn->bv_val, oldDN, diff );
			strcpy( &dn->bv_val[diff], be->be_suffixAlias[i+1].bv_val );
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, 
				"suffix_alias: converted \"%s\" to \"%s\"\n",
				oldDN, dn->bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ARGS,
				"suffix_alias: converted \"%s\" to \"%s\"\n",
				oldDN, dn->bv_val, 0);
#endif

			free (oldDN);
			break;
		}
	}
}

/*
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
#include <string.h>
#include <ac/socket.h>		/* Get struct sockaddr for slap.h */
#include "slap.h"

/* 
 * given a dn (or root part), return an aliased dn if any of the 
 * alias suffixes match
 */
char *suffixAlias (char *dn, Operation *op, Backend *be)
{
	int 	i, dnLength;

	dnLength = strlen ( dn );
        op->o_suffix = NULL;
        op->o_suffixAliased = NULL;
        for ( i = 0;
              be->be_suffixAlias != NULL && be->be_suffixAlias[i] != NULL;
              i += 2) {
                int aliasLength = strlen (be->be_suffixAlias[i]);
                if (aliasLength > dnLength) {
                        continue;
                }

                if (!strcasecmp(be->be_suffixAlias[i], 
				dn + (dnLength - aliasLength))) {
                        char *oldDN = dn;
                        op->o_suffixAliased = ch_strdup ( be->be_suffixAlias[i] );
                        dn = ch_malloc ( (dnLength - aliasLength) +
                                          strlen (be->be_suffixAlias[ i+1 ]) + 1);
                        strncpy (dn, oldDN, dnLength - aliasLength);
                        strcpy  (dn + (dnLength - aliasLength), be->be_suffixAlias[ i+1 ]);
                        op->o_suffix = ch_strdup (dn);
                        Debug( LDAP_DEBUG_ARGS, "ALIAS: converted %s to %s", oldDN, dn, 0);
                        free (oldDN);
			break;
		}
	}
	return dn;
}

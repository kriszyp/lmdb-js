/* suffixmassage.c - massages ldap backend dns */
/* $OpenLDAP$ */

/* 
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 * Copyright 2000, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * Module back-ldap, originally developed by Howard Chu
 *
 * has been modified by Pierangelo Masarati. The original copyright
 * notice has been maintained.
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

/*
 * ldap_back_dn_massage
 * 
 * Aliases the suffix; based on suffix_alias (servers/slapd/suffixalias.c).
 */
char *
ldap_back_dn_massage(
	struct ldapinfo *li,
	char *dn,
	int normalized
)
{
	int     i, dnLength;

        if ( dn == NULL ) {
		return NULL;
	}
        if ( li == NULL ) {
		return dn;
	}

        dnLength = strlen ( dn );

        for ( i = 0;
                li->suffix_massage != NULL && li->suffix_massage[i] != NULL;
                i += 4 ) {
                int aliasLength = strlen( li->suffix_massage[i+normalized] );
                int diff = dnLength - aliasLength;

                if ( diff < 0 ) {
                        /* alias is longer than dn */
                        continue;
										                } else if ( diff > 0 ) {
                        if ( normalized && ( ! DN_SEPARATOR(dn[diff-1]) ) ) {
                                /* boundary is not at a DN separator */
                                continue;
			}
                        /* At a DN Separator */
                        /* XXX or an escaped separator... oh well */
                }

                if ( !strcmp( li->suffix_massage[i+normalized], &dn[diff] ) ) {
                        char *oldDN = dn;
                        dn = ch_malloc( diff + strlen( li->suffix_massage[i+2+normalized] ) + 1 );
                        strncpy( dn, oldDN, diff );
                        strcpy( &dn[diff], li->suffix_massage[i+2+normalized] );
                        Debug( LDAP_DEBUG_ARGS,
                                "ldap_back_dn_massage:"
				" converted \"%s\" to \"%s\"\n",
                                oldDN, dn, 0 );
                        free( oldDN );
                        break;
                }
        }

        return dn;
}

/*
 * ldap_back_dn_restore
 * 
 * Restores the original suffix;
 * based on suffix_alias (servers/slapd/suffixalias.c).
 */
char *
ldap_back_dn_restore(
        struct ldapinfo *li,
        char *dn,
        int normalized
	)
{
        int     i, dnLength;

        if ( dn == NULL ) {
                return NULL;
        }
        if ( li == NULL ) {
                return dn;
        }

        dnLength = strlen ( dn );

        for ( i = 0;
                li->suffix_massage != NULL && li->suffix_massage[i] != NULL;
                i += 4 ) {
                int aliasLength = strlen( li->suffix_massage[i+2+normalized] );
                int diff = dnLength - aliasLength;

                if ( diff < 0 ) {
                        /* alias is longer than dn */
                        continue;

                } else if ( diff > 0 ) {
                        if ( normalized && ( ! DN_SEPARATOR(dn[diff-1]) ) ) {
                                /* boundary is not at a DN separator */
                                continue;
                        }
                        /* At a DN Separator */
                        /* XXX or an escaped separator... oh well */
                }

                if ( !strcmp( li->suffix_massage[i+2+normalized], &dn[diff] ) ) {
                        char *oldDN = dn;
                        dn = ch_malloc( diff + strlen( li->suffix_massage[i+normalized] ) + 1 );
                        strncpy( dn, oldDN, diff );
                        strcpy( &dn[diff], li->suffix_massage[i+normalized] );
			Debug( LDAP_DEBUG_ARGS,
                        	"ldap_back_dn_restore:"
                                " converted \"%s\" to \"%s\"\n",
                                oldDN, dn, 0 );
                        free( oldDN );
                        break;
                }
        }

        return dn;
}


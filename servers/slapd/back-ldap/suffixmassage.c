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

#ifndef ENABLE_REWRITE

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

/*
 * ldap_back_dn_massage
 * 
 * Aliases the suffix; based on suffix_alias (servers/slapd/suffixalias.c).
 */
void
ldap_back_dn_massage(
	struct ldapinfo *li,
	struct berval *dn,
	struct berval *res,
	int normalized,
	int tofrom
)
{
	int     i, src, dst;

	assert( res );

	res->bv_val = NULL;
	res->bv_len = 0;
        if ( dn == NULL ) {
		return;
	}
        if ( li == NULL || li->suffix_massage == NULL ) {
		*res = *dn;
		return;
	}

	if ( tofrom ) {
		src = 0 + normalized;
		dst = 2 + normalized;
	} else {
		src = 2 + normalized;
		dst = 0 + normalized;
	}

        for ( i = 0;
                li->suffix_massage[i].bv_val != NULL;
                i += 4 ) {
                int aliasLength = li->suffix_massage[i+src].bv_len;
                int diff = dn->bv_len - aliasLength;

                if ( diff < 0 ) {
                        /* alias is longer than dn */
                        continue;
										                } else if ( diff > 0 ) {
                        if ( normalized && ( ! DN_SEPARATOR(dn->bv_val[diff-1]) ) ) {
                                /* boundary is not at a DN separator */
                                continue;
			}
                        /* At a DN Separator */
                        /* XXX or an escaped separator... oh well */
                }

                if ( !strcasecmp( li->suffix_massage[i+src].bv_val, &dn->bv_val[diff] ) ) {
			res->bv_len = diff + li->suffix_massage[i+dst].bv_len;
                        res->bv_val = ch_malloc( res->bv_len + 1 );
                        strncpy( res->bv_val, dn->bv_val, diff );
                        strcpy( &res->bv_val[diff], li->suffix_massage[i+dst].bv_val );
#ifdef NEW_LOGGING
					LDAP_LOG ( BACK_LDAP, ARGS, 
						"ldap_back_dn_massage: converted \"%s\" to \"%s\"\n",
						dn->bv_val, res->bv_val, 0 );
#else
                        Debug( LDAP_DEBUG_ARGS,
                                "ldap_back_dn_massage:"
				" converted \"%s\" to \"%s\"\n",
                                dn->bv_val, res->bv_val, 0 );
#endif
                        break;
                }
        }

        return;
}
#endif /* !ENABLE_REWRITE */

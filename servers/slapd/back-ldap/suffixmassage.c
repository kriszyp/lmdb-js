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

#ifdef ENABLE_REWRITE
int
ldap_back_dn_massage(
	dncookie *dc,
	struct berval *dn,
	struct berval *res
)
{
	int rc = 0;

	switch (rewrite_session( dc->li->rwinfo, dc->ctx, dn->bv_val, dc->conn, 
				&res->bv_val )) {
	case REWRITE_REGEXEC_OK:
		if ( res->bv_val != NULL && res->bv_val[ 0 ] != '\0' ) {
			res->bv_len = strlen( res->bv_val );
		} else {
			*res = *dn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] %s: \"%s\" -> \"%s\"\n", dc->ctx, dn->bv_val, res->bv_val );		
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
			"[rw] %s: \"%s\" -> \"%s\"\n", dc->ctx, dn->bv_val, res->bv_val );		
#endif /* !NEW_LOGGING */
		break;
 		
 	case REWRITE_REGEXEC_UNWILLING:
		if ( dc->rs ) {
			dc->rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			dc->rs->sr_text = "Operation not allowed";
		}
		rc = -1;
		break;
	       	
	case REWRITE_REGEXEC_ERR:
		if ( dc->rs ) {
			dc->rs->sr_err = LDAP_OTHER;
			dc->rs->sr_text = "Rewrite error";
		}
		rc = -1;
		break;
	}
	return rc;
}

#else
/*
 * ldap_back_dn_massage
 * 
 * Aliases the suffix; based on suffix_alias (servers/slapd/suffixalias.c).
 */
int
ldap_back_dn_massage(
	dncookie *dc,
	struct berval *odn,
	struct berval *res
)
{
	int     i, src, dst;
	struct berval pretty = {0,NULL}, *dn = odn;

	assert( res );

	if ( dn == NULL ) {
		res->bv_val = NULL;
		res->bv_len = 0;
		return 0;
	}
	if ( dc->li == NULL || dc->li->suffix_massage == NULL ) {
		*res = *dn;
		return 0;
	}

	if ( dc->tofrom ) {
		src = 0 + dc->normalized;
		dst = 2 + dc->normalized;
	} else {
		src = 2 + dc->normalized;
		dst = 0 + dc->normalized;
		/* DN from remote server may be in arbitrary form.
		 * Pretty it so we can parse reliably.
		 */
		dnPretty2( NULL, dn, &pretty );
		if (pretty.bv_val) dn = &pretty;
	}

	for ( i = 0;
		dc->li->suffix_massage[i].bv_val != NULL;
		i += 4 ) {
		int aliasLength = dc->li->suffix_massage[i+src].bv_len;
		int diff = dn->bv_len - aliasLength;

		if ( diff < 0 ) {
			/* alias is longer than dn */
			continue;
		} else if ( diff > 0 && ( !DN_SEPARATOR(dn->bv_val[diff-1]))) {
			/* boundary is not at a DN separator */
			continue;
			/* At a DN Separator */
		}

		if ( !strcmp( dc->li->suffix_massage[i+src].bv_val, &dn->bv_val[diff] ) ) {
			res->bv_len = diff + dc->li->suffix_massage[i+dst].bv_len;
			res->bv_val = ch_malloc( res->bv_len + 1 );
			strncpy( res->bv_val, dn->bv_val, diff );
			strcpy( &res->bv_val[diff], dc->li->suffix_massage[i+dst].bv_val );
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
	if (pretty.bv_val) {
		ch_free(pretty.bv_val);
		dn = odn;
	}
	/* Nothing matched, just return the original DN */
	if (res->bv_val == NULL) {
		*res = *dn;
	}

	return 0;
}
#endif /* !ENABLE_REWRITE */

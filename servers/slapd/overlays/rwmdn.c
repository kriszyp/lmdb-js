/* rwmdn.c - massages dns */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999-2003 Howard Chu.
 * Portions Copyright 2000-2003 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */


#include "portable.h"

#ifdef SLAPD_OVER_RWM

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "rwm.h"

/* FIXME: after rewriting, we should also remap attributes ...  */

#ifdef ENABLE_REWRITE
int
rwm_dn_massage(
	dncookie *dc,
	struct berval *in,
	struct berval *dn,
	struct berval *ndn
)
{
	int		rc = 0;
	struct berval	mdn;

	assert( in );

	if ( dn == NULL && ndn == NULL ) {
		return LDAP_OTHER;
	}

	rc = rewrite_session( dc->rwmap->rwm_rw, dc->ctx,
			( in->bv_len ? in->bv_val : "" ), 
			dc->conn, &mdn.bv_val );
	switch ( rc ) {
	case REWRITE_REGEXEC_OK:
		if ( !BER_BVISNULL( &mdn ) ) {

			mdn.bv_len = strlen( mdn.bv_val );
			
			if ( dn != NULL && ndn != NULL ) {
				rc = dnPrettyNormal( NULL, &mdn, dn, ndn, NULL );

			} else if ( dn != NULL ) {
				rc = dnPretty( NULL, &mdn, dn, NULL );

			} else if ( ndn != NULL) {
				rc = dnNormalize( 0, NULL, NULL, &mdn, ndn, NULL );
			}

			if ( mdn.bv_val != in->bv_val ) {
				ch_free( mdn.bv_val );
			}

		} else {
			/* we assume the input string is already in pretty form,
			 * and that the normalized version is already available */
			if ( dn ) {
				*dn = *in;
				if ( ndn ) {
					BER_BVZERO( ndn );
				}
			} else {
				*ndn = *in;
			}
			rc = LDAP_SUCCESS;
		}

		Debug( LDAP_DEBUG_ARGS,
			"[rw] %s: \"%s\" -> \"%s\"\n",
			dc->ctx, in->bv_val, dn ? dn->bv_val : ndn->bv_val );
		break;
 		
 	case REWRITE_REGEXEC_UNWILLING:
		if ( dc->rs ) {
			dc->rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			dc->rs->sr_text = "Operation not allowed";
		}
		rc = LDAP_UNWILLING_TO_PERFORM;
		break;
	       	
	case REWRITE_REGEXEC_ERR:
		if ( dc->rs ) {
			dc->rs->sr_err = LDAP_OTHER;
			dc->rs->sr_text = "Rewrite error";
		}
		rc = LDAP_OTHER;
		break;
	}

	return rc;
}

#else /* ! ENABLE_REWRITE */
/*
 * rwm_dn_massage
 * 
 * Aliases the suffix; based on suffix_alias (servers/slapd/suffixalias.c).
 */
int
rwm_dn_massage(
	dncookie *dc,
	struct berval *tmpin,
	struct berval *dn,
	struct berval *ndn
)
{
	int     	i, src, dst;
	struct berval	pretty = BER_BVNULL,
			normal = BER_BVNULL,
			*in = tmpin;

	if ( dn == NULL && ndn == NULL ) {
		return LDAP_OTHER;
	}

	if ( in == NULL || BER_BVISNULL( in ) ) {
		if ( dn ) {
			BER_BVZERO( dn );
		}
		if ( ndn ) {
			BER_BVZERO( ndn );
		}
		return LDAP_SUCCESS;
	}

	if ( dc->rwmap == NULL || dc->rwmap->rwm_suffix_massage == NULL ) {
		if ( dn ) {
			*dn = *in;
			if ( ndn ) {
				BER_BVZERO( ndn );
			}
		} else {
			*ndn = *in;
		}
		return LDAP_SUCCESS;
	}

	if ( dc->tofrom ) {
		src = 0 + dc->normalized;
		dst = 2 + dc->normalized;

	} else {
		int	rc;

		src = 2 + dc->normalized;
		dst = 0 + dc->normalized;

		/* DN from remote server may be in arbitrary form.
		 * Pretty it so we can parse reliably.
		 */
		if ( dc->normalized && dn == NULL ) {
			rc = dnNormalize( 0, NULL, NULL, in, &normal, NULL );

		} else if ( !dc->normalized && ndn == NULL ) {
			rc = dnPretty( NULL, in, &pretty, NULL );

		} else {
			rc = dnPrettyNormal( NULL, in, &pretty, &normal, NULL );
		}

		if ( rc != LDAP_SUCCESS ) {
			return rc;
		}

		if ( dc->normalized && !BER_BVISNULL( &normal ) ) {
			in = &normal;

		} else if ( !dc->normalized && !BER_BVISNULL( &pretty ) ) {
			in = &pretty;
		}
	}

	for ( i = 0;
		dc->rwmap->rwm_suffix_massage[i].bv_val != NULL;
		i += 4 ) {
		int aliasLength = dc->rwmap->rwm_suffix_massage[i+src].bv_len;
		int diff = in->bv_len - aliasLength;

		if ( diff < 0 ) {
			/* alias is longer than dn */
			continue;

		} else if ( diff > 0 && ( !DN_SEPARATOR(in->bv_val[diff-1]))) {
			/* FIXME: DN_SEPARATOR() is intended to work
			 * on a normalized/pretty DN, so that ';'
			 * is never used as a DN separator */
			continue;
			/* At a DN Separator */
		}

		if ( !strcmp( dc->rwmap->rwm_suffix_massage[i+src].bv_val, &in->bv_val[diff] ) ) {
			struct berval	*out;

			if ( dn ) {
				out = dn;
			} else {
				out = ndn;
			}
			out->bv_len = diff + dc->rwmap->rwm_suffix_massage[i+dst].bv_len;
			out->bv_val = ch_malloc( out->bv_len + 1 );
			strncpy( out->bv_val, in->bv_val, diff );
			strcpy( &out->bv_val[diff], dc->rwmap->rwm_suffix_massage[i+dst].bv_val );
			Debug( LDAP_DEBUG_ARGS,
				"rwm_dn_massage:"
				" converted \"%s\" to \"%s\"\n",
				in->bv_val, out->bv_val, 0 );
			if ( dn && ndn ) {
				rc = dnNormalize( 0, NULL, NULL, dn, ndn, NULL );
			}

			break;
		}
	}

	if ( !BER_BVISNULL( &pretty ) ) {
		ch_free( pretty.bv_val );
	}

	if ( !BER_BVISNULL( &normal ) ) {
		ch_free( normal.bv_val );
	}

	in = tmpin;

	/* Nothing matched, just return the original DN */
	if ( dc->normalized && BER_BVISNULL( ndn ) ) {
		*ndn = *in;

	} else if ( !dc->normalized && BER_BVISNULL( dn ) ) {
		*dn = *in;
	}

	return LDAP_SUCCESS;
}
#endif /* ! ENABLE_REWRITE */

#endif /* SLAPD_OVER_RWM */

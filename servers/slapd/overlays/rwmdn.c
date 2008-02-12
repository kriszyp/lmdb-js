/* rwmdn.c - massages dns */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2008 The OpenLDAP Foundation.
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
 * This work was initially developed by Howard Chu for inclusion
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

/*
 * massages "in" and normalizes it into "ndn"
 *
 * "ndn" may be untouched if no massaging occurred and its value was not null
 */
int
rwm_dn_massage_normalize(
	dncookie *dc,
	struct berval *in,
	struct berval *ndn )
{
	int		rc;
	struct berval	mdn = BER_BVNULL;
	
	/* massage and normalize a DN */
	rc = rwm_dn_massage( dc, in, &mdn );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	if ( mdn.bv_val == in->bv_val && !BER_BVISNULL( ndn ) ) {
		return rc;
	}

	rc = dnNormalize( 0, NULL, NULL, &mdn, ndn, NULL );

	if ( mdn.bv_val != in->bv_val ) {
		ch_free( mdn.bv_val );
	}

	return rc;
}

/*
 * massages "in" and prettifies it into "pdn"
 *
 * "pdn" may be untouched if no massaging occurred and its value was not null
 */
int
rwm_dn_massage_pretty(
	dncookie *dc,
	struct berval *in,
	struct berval *pdn )
{
	int		rc;
	struct berval	mdn = BER_BVNULL;
	
	/* massage and pretty a DN */
	rc = rwm_dn_massage( dc, in, &mdn );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	if ( mdn.bv_val == in->bv_val && !BER_BVISNULL( pdn ) ) {
		return rc;
	}

	rc = dnPretty( NULL, &mdn, pdn, NULL );

	if ( mdn.bv_val != in->bv_val ) {
		ch_free( mdn.bv_val );
	}

	return rc;
}

/*
 * massages "in" and prettifies and normalizes it into "pdn" and "ndn"
 *
 * "pdn" may be untouched if no massaging occurred and its value was not null;
 * "ndn" may be untouched if no massaging occurred and its value was not null;
 * if no massage occurred and "ndn" value was not null, it is filled
 * with the normaized value of "pdn", much like ndn = dnNormalize( pdn )
 */
int
rwm_dn_massage_pretty_normalize(
	dncookie *dc,
	struct berval *in,
	struct berval *pdn,
	struct berval *ndn )
{
	int		rc;
	struct berval	mdn = BER_BVNULL;
	
	/* massage, pretty and normalize a DN */
	rc = rwm_dn_massage( dc, in, &mdn );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	if ( mdn.bv_val == in->bv_val && !BER_BVISNULL( pdn ) ) {
		if ( BER_BVISNULL( ndn ) ) {
			rc = dnNormalize( 0, NULL, NULL, &mdn, ndn, NULL );
		}
		return rc;
	}

	rc = dnPrettyNormal( NULL, &mdn, pdn, ndn, NULL );

	if ( mdn.bv_val != in->bv_val ) {
		ch_free( mdn.bv_val );
	}

	return rc;
}

#ifdef ENABLE_REWRITE
/*
 * massages "in" into "dn"
 * 
 * "dn" may contain the value of "in" if no massage occurred
 */
int
rwm_dn_massage(
	dncookie *dc,
	struct berval *in,
	struct berval *dn
)
{
	int		rc = 0;
	struct berval	mdn;
	static char	*dmy = "";

	assert( dc != NULL );
	assert( in != NULL );
	assert( dn != NULL );

	rc = rewrite_session( dc->rwmap->rwm_rw, dc->ctx,
			( in->bv_val ? in->bv_val : dmy ), 
			dc->conn, &mdn.bv_val );
	switch ( rc ) {
	case REWRITE_REGEXEC_OK:
		if ( !BER_BVISNULL( &mdn ) && mdn.bv_val != in->bv_val ) {
			mdn.bv_len = strlen( mdn.bv_val );
			*dn = mdn;
		} else {
			*dn = *in;
		}
		rc = LDAP_SUCCESS;

		Debug( LDAP_DEBUG_ARGS,
			"[rw] %s: \"%s\" -> \"%s\"\n",
			dc->ctx, in->bv_val, dn->bv_val );
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

	if ( mdn.bv_val == dmy ) {
		BER_BVZERO( &mdn );
	}

	if ( dn->bv_val == dmy ) {
		BER_BVZERO( dn );
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
	struct berval *in,
	struct berval *dn
)
{
	int     	i, src, dst;
	struct berval	tmpin;

	assert( dc != NULL );
	assert( in != NULL );
	assert( dn != NULL );

	BER_BVZERO( dn );

	if ( BER_BVISNULL( in ) ) {
		return LDAP_SUCCESS;
	}

	if ( dc->rwmap == NULL || dc->rwmap->rwm_suffix_massage == NULL ) {
		*dn = *in;
		return LDAP_SUCCESS;
	}

	if ( dc->tofrom ) {
		src = 0 + dc->normalized;
		dst = 2 + dc->normalized;

		tmpin = *in;

	} else {
		int	rc;

		src = 2 + dc->normalized;
		dst = 0 + dc->normalized;

		/* DN from remote server may be in arbitrary form.
		 * Pretty it so we can parse reliably.
		 */
		if ( dc->normalized ) {
			rc = dnNormalize( 0, NULL, NULL, in, &tmpin, NULL );

		} else {
			rc = dnPretty( NULL, in, &tmpin, NULL );
		}

		if ( rc != LDAP_SUCCESS ) {
			return rc;
		}
	}

	for ( i = 0;
			!BER_BVISNULL( &dc->rwmap->rwm_suffix_massage[i] );
			i += 4 )
	{
		int aliasLength = dc->rwmap->rwm_suffix_massage[i+src].bv_len;
		int diff = tmpin.bv_len - aliasLength;

		if ( diff < 0 ) {
			/* alias is longer than dn */
			continue;

		} else if ( diff > 0 && ( !DN_SEPARATOR(tmpin.bv_val[diff-1])))
		{
			/* FIXME: DN_SEPARATOR() is intended to work
			 * on a normalized/pretty DN, so that ';'
			 * is never used as a DN separator */
			continue;
			/* At a DN Separator */
		}

		if ( !strcmp( dc->rwmap->rwm_suffix_massage[i+src].bv_val,
					&tmpin.bv_val[diff] ) )
		{
			dn->bv_len = diff + dc->rwmap->rwm_suffix_massage[i+dst].bv_len;
			dn->bv_val = ch_malloc( dn->bv_len + 1 );
			strncpy( dn->bv_val, tmpin.bv_val, diff );
			strcpy( &dn->bv_val[diff], dc->rwmap->rwm_suffix_massage[i+dst].bv_val );
			Debug( LDAP_DEBUG_ARGS,
				"rwm_dn_massage:"
				" converted \"%s\" to \"%s\"\n",
				in->bv_val, dn->bv_val, 0 );

			break;
		}
	}

	if ( tmpin.bv_val != in->bv_val ) {
		ch_free( tmpin.bv_val );
	}

	/* Nothing matched, just return the original DN */
	if ( BER_BVISNULL( dn ) ) {
		*dn = *in;
	}

	return LDAP_SUCCESS;
}
#endif /* ! ENABLE_REWRITE */

#endif /* SLAPD_OVER_RWM */

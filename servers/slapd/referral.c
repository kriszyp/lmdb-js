/* referral.c - muck with referrals */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <ldap_pvt.h>

#include "slap.h"

/*
 * This routine generates the DN appropriate to return in
 * an LDAP referral.
 */
static char * referral_dn_muck(
	const char * refDN,
	const char * baseDN,
	const char * targetDN )
{
	int rc;
	struct berval bvin;
	struct berval nrefDN = { 0, NULL };
	struct berval nbaseDN = { 0, NULL };
	struct berval ntargetDN = { 0, NULL };

	if( !baseDN ) {
		/* no base, return target */
		return targetDN ? ch_strdup( targetDN ) : NULL;
	}

	if( refDN ) {
		bvin.bv_val = (char *)refDN;
		bvin.bv_len = strlen( refDN );

		rc = dnPretty2( NULL, &bvin, &nrefDN );
		if( rc != LDAP_SUCCESS ) {
			/* Invalid refDN */
			return NULL;
		}
	}

	if( !targetDN ) {
		/* continuation reference
		 *	if refDN present return refDN
		 *  else return baseDN
		 */
		return nrefDN.bv_len ? nrefDN.bv_val : ch_strdup( baseDN );
	}

	bvin.bv_val = (char *)targetDN;
	bvin.bv_len = strlen( targetDN );

	rc = dnPretty2( NULL, &bvin, &ntargetDN );
	if( rc != LDAP_SUCCESS ) {
		/* Invalid targetDN */
		ch_free( nrefDN.bv_val );
		return NULL;
	}

	if( nrefDN.bv_len ) {
		bvin.bv_val = (char *)baseDN;
		bvin.bv_len = strlen( baseDN );

		rc = dnPretty2( NULL, &bvin, &nbaseDN );
		if( rc != LDAP_SUCCESS ) {
			/* Invalid baseDN */
			ch_free( nrefDN.bv_val );
			ch_free( ntargetDN.bv_val );
			return NULL;
		}

		if( dn_match( &nbaseDN, &nrefDN ) ) {
			ch_free( nrefDN.bv_val );
			ch_free( nbaseDN.bv_val );
			return ntargetDN.bv_val;
		}

		{
			struct berval muck;

			if( ntargetDN.bv_len < nbaseDN.bv_len ) {
				ch_free( nrefDN.bv_val );
				ch_free( nbaseDN.bv_val );
				return ntargetDN.bv_val;
			}

			rc = strcasecmp(
				&ntargetDN.bv_val[ntargetDN.bv_len-nbaseDN.bv_len],
				nbaseDN.bv_val );
			if( rc ) {
				/* target not subordinate to base */
				ch_free( nrefDN.bv_val );
				ch_free( nbaseDN.bv_val );
				return ntargetDN.bv_val;
			}

			muck.bv_len = ntargetDN.bv_len + nrefDN.bv_len - nbaseDN.bv_len;
			muck.bv_val = ch_malloc( muck.bv_len + 1 );

			strncpy( muck.bv_val, ntargetDN.bv_val,
				ntargetDN.bv_len-nbaseDN.bv_len );
			strcpy( &muck.bv_val[ntargetDN.bv_len-nbaseDN.bv_len],
				nrefDN.bv_val );

			ch_free( nrefDN.bv_val );
			ch_free( nbaseDN.bv_val );
			ch_free( ntargetDN.bv_val );

			return muck.bv_val;
		}
	}

	ch_free( nrefDN.bv_val );
	return ntargetDN.bv_val;
}


/* validate URL for global referral use
 *   LDAP URLs must not have:
 *     DN, attrs, scope, nor filter
 *   Any non-LDAP URL is okay
 *
 *   XXYYZ: should return an error string
 */
int validate_global_referral( const char *url )
{
	int rc;
	LDAPURLDesc *lurl;

	rc = ldap_url_parse_ext( url, &lurl );

	switch( rc ) {
	case LDAP_URL_SUCCESS:
		break;

	case LDAP_URL_ERR_BADSCHEME:
		/* not LDAP hence valid */
		return 0;

	default:
		/* other error, bail */
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, CRIT, 
			"referral: invalid URL (%s): %s (%d)\n",
			url, "" /* ldap_url_error2str(rc) */, rc );
#else
		Debug( LDAP_DEBUG_ANY,
			"referral: invalid URL (%s): %s (%d)\n",
			url, "" /* ldap_url_error2str(rc) */, rc );
#endif
		return 1;
	}

	rc = 0;

	if( lurl->lud_dn && *lurl->lud_dn ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, CRIT, "referral: URL (%s): contains DN\n", url, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"referral: URL (%s): contains DN\n",
			url, 0, 0 );
#endif
		rc = 1;

	} else if( lurl->lud_attrs ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, CRIT, 
			"referral: URL (%s): requests attributes\n", url, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"referral: URL (%s): requests attributes\n",
			url, 0, 0 );
#endif
		rc = 1;

	} else if( lurl->lud_scope != LDAP_SCOPE_DEFAULT ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, CRIT, 
			"referral: URL (%s): contains explicit scope\n", url, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"referral: URL (%s): contains explicit scope\n",
			url, 0, 0 );
#endif
		rc = 1;

	} else if( lurl->lud_filter ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, CRIT, 
			"referral: URL (%s): contains explicit filter\n", url, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"referral: URL (%s): contains explicit filter\n",
			url, 0, 0 );
#endif
		rc = 1;
	}

	ldap_free_urldesc( lurl );
	return rc;
}

BerVarray referral_rewrite(
	BerVarray in,
	struct berval *base,
	struct berval *target,
	int scope )
{
	int i;
	BerVarray refs;
	struct berval *iv, *jv;

	if( in == NULL ) return NULL;

	for( i=0; in[i].bv_val != NULL ; i++ ) {
		/* just count them */
	}

	if( i < 1 ) return NULL;

	refs = ch_malloc( (i+1) * sizeof( struct berval ) );

	for( iv=in,jv=refs; iv->bv_val != NULL ; iv++ ) {
		LDAPURLDesc *url;
		int rc = ldap_url_parse_ext( iv->bv_val, &url );

		if( rc == LDAP_URL_ERR_BADSCHEME ) {
			ber_dupbv( jv++, iv );
			continue;

		} else if( rc != LDAP_URL_SUCCESS ) {
			continue;
		}

		{
			char *dn = url->lud_dn;
			url->lud_dn = referral_dn_muck(
				( dn && *dn ) ? dn : NULL,
				base ? base->bv_val : NULL,
				target ? target->bv_val : NULL ); 

			ldap_memfree( dn );
		}

		if( url->lud_scope == LDAP_SCOPE_DEFAULT ) {
			url->lud_scope = scope;
		}

		jv->bv_val = ldap_url_desc2str( url );
		jv->bv_len = strlen( jv->bv_val );

		ldap_free_urldesc( url );
		jv++;
	}

	if( jv == refs ) {
		ch_free( refs );
		refs = NULL;

	} else {
		jv->bv_val = NULL;
	}

	return refs;
}


BerVarray get_entry_referrals(
	Backend *be,
	Connection *conn,
	Operation *op,
	Entry *e )
{
	Attribute *attr;
	BerVarray refs;
	unsigned i;
	struct berval *iv, *jv;

	AttributeDescription *ad_ref = slap_schema.si_ad_ref;

	attr = attr_find( e->e_attrs, ad_ref );

	if( attr == NULL ) return NULL;

	for( i=0; attr->a_vals[i].bv_val != NULL; i++ ) {
		/* count references */
	}

	if( i < 1 ) return NULL;

	refs = ch_malloc( (i + 1) * sizeof(struct berval));

	for( iv=attr->a_vals, jv=refs; iv->bv_val != NULL; iv++ ) {
		unsigned k;
		ber_dupbv( jv, iv );

		/* trim the label */
		for( k=0; k<jv->bv_len; k++ ) {
			if( isspace( (unsigned char) jv->bv_val[k] ) ) {
				jv->bv_val[k] = '\0';
				jv->bv_len = k;
				break;
			}
		}

		if(	jv->bv_len > 0 ) {
			jv++;
		} else {
			free( jv->bv_val );
		}
	}

	if( jv == refs ) {
		free( refs );
		refs = NULL;

	} else {
		jv->bv_val = NULL;
	}

	/* we should check that a referral value exists... */
	return refs;
}


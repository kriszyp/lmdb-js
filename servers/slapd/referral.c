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
#include <ac/signal.h>
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
	char *tmp;
	char *nrefDN = NULL;
	char *nbaseDN = NULL;
	char *ntargetDN = NULL;

	if( !baseDN ) {
		/* no base, return target */
		return targetDN ? ch_strdup( targetDN ) : NULL;
	}

	if( refDN ) {
		nrefDN = dn_validate( tmp = ch_strdup( refDN ) );
		if( !nrefDN ) {
			/* Invalid refDN */
			ch_free( tmp );
			return NULL;
		}
	}

	if( !targetDN ) {
		/* continuation reference
		 *	if refDN present return refDN
		 *  else return baseDN
		 */
		return nrefDN ? nrefDN : ch_strdup( baseDN );
	}

	ntargetDN = dn_validate( tmp = ch_strdup( targetDN ) );
	if( !ntargetDN ) {
		ch_free( tmp );
		ch_free( nrefDN );
		return NULL;
	}

	if( nrefDN ) {
		nbaseDN = dn_validate( tmp = ch_strdup( baseDN ) );
		if( !nbaseDN ) {
			/* Invalid baseDN */
			ch_free( ntargetDN );
			ch_free( nrefDN );
			ch_free( tmp );
			return NULL;
		}

		if( strcasecmp( nbaseDN, nrefDN ) == 0 ) {
			ch_free( nrefDN );
			ch_free( nbaseDN );
			return ntargetDN;
		}

		{
			/*
			 * FIXME: string based mucking
			 */
			char *muck;
			size_t reflen, baselen, targetlen, mucklen;

			reflen = strlen( nrefDN );
			baselen = strlen( nbaseDN );
			targetlen = strlen( ntargetDN );

			if( targetlen < baselen ) {
				ch_free( nrefDN );
				ch_free( nbaseDN );
				return ntargetDN;
			}

			if( strcasecmp( &ntargetDN[targetlen-baselen], nbaseDN ) ) {
				/* target not subordinate to base */
				ch_free( nrefDN );
				ch_free( nbaseDN );
				return ntargetDN;
			}

			mucklen = targetlen + reflen - baselen;
			muck = ch_malloc( 1 + mucklen );

			strncpy( muck, ntargetDN, targetlen-baselen );
			strcpy( &muck[targetlen-baselen], nrefDN );

			ch_free( nrefDN );
			ch_free( nbaseDN );
			ch_free( ntargetDN );

			return muck;
		}
	}

	return ntargetDN;
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
		LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
			"referral: invalid URL (%s): %s (%d)\n",
			url, "" /* ldap_url_error2str(rc) */, rc ));
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
		LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
			"referral: URL (%s): contains DN\n",
			url ));
#else
		Debug( LDAP_DEBUG_ANY,
			"referral: URL (%s): contains DN\n",
			url, 0, 0 );
#endif
		rc = 1;

	} else if( lurl->lud_attrs ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
			"referral: URL (%s): requests attributes\n",
			url ));
#else
		Debug( LDAP_DEBUG_ANY,
			"referral: URL (%s): requests attributes\n",
			url, 0, 0 );
#endif
		rc = 1;

	} else if( lurl->lud_scope != LDAP_SCOPE_DEFAULT ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
			"referral: URL (%s): contains explicit scope\n",
			url ));
#else
		Debug( LDAP_DEBUG_ANY,
			"referral: URL (%s): contains explicit scope\n",
			url, 0, 0 );
#endif
		rc = 1;

	} else if( lurl->lud_filter ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
			"referral: URL (%s): contains explicit filter\n",
			url ));
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

BVarray referral_rewrite(
	BVarray in,
	struct berval *base,
	struct berval *target,
	int scope )
{
	int i;
	BVarray refs;
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


BVarray get_entry_referrals(
	Backend *be,
	Connection *conn,
	Operation *op,
	Entry *e )
{
	Attribute *attr;
	BVarray refs;
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
			if( isspace(jv->bv_val[k]) ) {
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


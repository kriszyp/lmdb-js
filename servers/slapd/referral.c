/* referral.c - muck with referrals */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2001 The OpenLDAP Foundation, All Rights Reserved.
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

struct berval ** referral_rewrite(
	struct berval **in,
	struct berval *base,
	struct berval *target,
	int scope )
{
	int i, j;
	struct berval **refs;

	if( in == NULL ) return NULL;

	for( i=0; in[i] != NULL ; i++ ) {
		/* just count them */
	}

	if( i < 1 ) return NULL;

	refs = ch_malloc( (i+1) * sizeof( struct berval * ) );

	for( i=0,j=0; in[i] != NULL ; i++ ) {
		LDAPURLDesc *url;
		int rc = ldap_url_parse_ext( in[i]->bv_val, &url );

		if( rc == LDAP_URL_ERR_BADSCHEME ) {
			refs[j++] = ber_bvdup( in[i] );
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

		refs[j] = ch_malloc( sizeof( struct berval ) );

		refs[j]->bv_val = ldap_url_desc2str( url );
		refs[j]->bv_len = strlen( refs[j]->bv_val );

		ldap_free_urldesc( url );
		j++;
	}

	if( j == 0 ) {
		ch_free( refs );
		refs = NULL;

	} else {
		refs[j] = NULL;
	}

	return refs;
}


struct berval **get_entry_referrals(
	Backend *be,
	Connection *conn,
	Operation *op,
	Entry *e )
{
	Attribute *attr;
	struct berval **refs;
	unsigned i, j;

	AttributeDescription *ad_ref = slap_schema.si_ad_ref;

	attr = attr_find( e->e_attrs, ad_ref );

	if( attr == NULL ) return NULL;

	for( i=0; attr->a_vals[i] != NULL; i++ ) {
		/* count references */
	}

	if( i < 1 ) return NULL;

	refs = ch_malloc( (i + 1) * sizeof(struct berval *));

	for( i=0, j=0; attr->a_vals[i] != NULL; i++ ) {
		unsigned k;
		struct berval *ref = ber_bvdup( attr->a_vals[i] );

		/* trim the label */
		for( k=0; k<ref->bv_len; k++ ) {
			if( isspace(ref->bv_val[k]) ) {
				ref->bv_val[k] = '\0';
				ref->bv_len = k;
				break;
			}
		}

		if(	ref->bv_len > 0 ) {
			refs[j++] = ref;

		} else {
			ber_bvfree( ref );
		}
	}

	if( j == 0 ) {
		ber_bvecfree( refs );
		refs = NULL;

	} else {
		refs[j] = NULL;
	}

	/* we should check that a referral value exists... */
	return refs;
}


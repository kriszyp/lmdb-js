/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/socket.h>
#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"


static int get_alias_dn(
	Entry *e,
	struct berval *al,
	int *err,
	const char **errmsg );

static void new_superior(
	struct berval *dn,
	struct berval *oldSup,
	struct berval *newSup,
	struct berval *res );

static int dnlist_subordinate(
	BerVarray dnlist,
	struct berval *dn );

Entry *deref_internal_r(
	Backend*	be,
	Entry*		alias,
	struct berval*	dn_in,
	int*		err,
	Entry**		matched,
	const char**		text )
{
	struct berval dn;
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	Entry *entry;
	Entry *sup;
	unsigned depth;
	BerVarray dnlist;

	assert( ( alias != NULL && dn_in == NULL )
		|| ( alias == NULL && dn_in != NULL ) );

	*matched = NULL;
	*err = LDAP_NO_SUCH_OBJECT;
	*text = NULL;

	if( alias == NULL ) {
		ber_dupbv( &dn, dn_in );
		entry = dn2entry_r( be, &dn, &sup );

	} else {
		ber_dupbv( &dn, &alias->e_nname );
		entry = alias;
		sup = NULL;
	}

	dnlist = NULL;
	ber_bvarray_add( &dnlist, &dn );

	for( depth=0 ; ; depth++ ) {
		if( entry != NULL ) {
			Entry *newe;
			struct berval aliasDN;

			/* have entry, may be an alias */

			if( !is_entry_alias( entry ) ) {
				/* entry is not an alias */
				break;
			}

			/* entry is alias */
			if( depth > be->be_max_deref_depth ) {
				*matched = entry;
				entry = NULL;
				*err = LDAP_ALIAS_DEREF_PROBLEM;
				*text = "maximum deref depth exceeded";
				break;
			}

			/* deref entry */
			if( get_alias_dn( entry, &aliasDN, err, text )) {
				*matched = entry;
				entry = NULL;
				break;
			}

			/* check if aliasDN is a subordinate of any DN in our list */
			if( dnlist_subordinate( dnlist, &aliasDN ) ) {
				ch_free( aliasDN.bv_val );
				*matched = entry;
				entry = NULL;
				*err = LDAP_ALIAS_PROBLEM;
				*text = "circular alias";
				break;
			}

			/* attempt to dereference alias */

			newe = dn2entry_r( be, &aliasDN, &sup );
			ch_free( aliasDN.bv_val );

			if( newe != NULL ) {
				cache_return_entry_r(&li->li_cache, entry );
				entry = newe;
				ber_dupbv( &dn, &entry->e_nname );
				ber_bvarray_add( &dnlist, &dn );
				continue;
			}
			
			if ( sup != NULL ) {
				cache_return_entry_r(&li->li_cache, entry );
				entry = NULL;
				continue;
			}

			/* no newe and no superior, we're done */
			break;

		} else if( sup != NULL ) {
			/* have superior, may be an alias */
			Entry *newe;
			Entry *newSup;
			struct berval supDN;
			struct berval aliasDN;

			if( !is_entry_alias( sup ) ) {
				/* entry is not an alias */
				*matched = sup;
				sup = NULL;
				break;
			}

			/* entry is alias */
			if( depth > be->be_max_deref_depth ) {
				*matched = sup;
				entry = NULL;
				*err = LDAP_ALIAS_DEREF_PROBLEM;
				*text = "maximum deref depth exceeded";
				break;
			}

			/* deref entry */
			if( get_alias_dn( sup, &supDN, err, text )) {
				*matched = sup;
				break;
			}

			new_superior( &dn, &sup->e_nname, &supDN, &aliasDN );
			free(supDN.bv_val);

			/* check if aliasDN is a subordinate of any DN in our list */
			if( dnlist_subordinate( dnlist, &aliasDN ) ) {
				free(aliasDN.bv_val);
				*matched = entry;
				entry = NULL;
				*err = LDAP_ALIAS_PROBLEM;
				*text = "subordinate circular alias";
				break;
			}

			/* attempt to dereference alias */
			newe = dn2entry_r( be, &aliasDN, &newSup );

			if( newe != NULL ) {
				free(aliasDN.bv_val);
				cache_return_entry_r(&li->li_cache, sup );
				entry = newe;
				ber_dupbv( &dn, &entry->e_nname );
				ber_bvarray_add( &dnlist, &dn );
				continue;
			}
			
			if ( newSup != NULL ) {
				cache_return_entry_r(&li->li_cache, sup );
				sup = newSup;
				ber_dupbv( &dn, &aliasDN );
				continue;
			}

			break;

		} else {
			/* no newe and no superior, we're done */
			break;
		}
	}

	ber_bvarray_free( dnlist );
	return entry;
}


static int get_alias_dn(
	Entry *e,
	struct berval *ndn,
	int *err,
	const char **errmsg )
{	
	int rc;
	Attribute *a;
	AttributeDescription *aliasedObjectName
		= slap_schema.si_ad_aliasedObjectName;

	a = attr_find( e->e_attrs, aliasedObjectName );

	if( a == NULL ) {
		/*
		 * there was an aliasedobjectname defined but no data.
		 */
		*err = LDAP_ALIAS_PROBLEM;
		*errmsg = "alias missing aliasedObjectName attribute";
		return -1;
	}

	/* 
	 * aliasedObjectName should be SINGLE-VALUED with a single value. 
	 */			
	if ( a->a_vals[0].bv_val == NULL ) {
		/*
		 * there was an aliasedobjectname defined but no data.
		 */
		*err = LDAP_ALIAS_PROBLEM;
		*errmsg = "alias missing aliasedObjectName value";
		return -1;
	}

	if( a->a_vals[1].bv_val != NULL ) {
		*err = LDAP_ALIAS_PROBLEM;
		*errmsg = "alias has multivalued aliasedObjectName";
		return -1;
	}

	rc = dnNormalize2( NULL, &a->a_vals[0], ndn );
	if( rc != LDAP_SUCCESS ) {
		*err = LDAP_ALIAS_PROBLEM;
		*errmsg = "alias aliasedObjectName value is invalid";
		return -1;
	}

	return 0;
}

static void new_superior(
	struct berval *dn,
	struct berval *oldSup,
	struct berval *newSup,
	struct berval *newDN )
{
	size_t dnlen, olen, nlen;
	assert( dn && oldSup && newSup && newDN );

	dnlen = dn->bv_len;
	olen = oldSup->bv_len;
	nlen = newSup->bv_len;

	newDN->bv_val = ch_malloc( dnlen - olen + nlen + 1 );

	AC_MEMCPY( newDN->bv_val, dn->bv_val, dnlen - olen );
	AC_MEMCPY( &newDN->bv_val[dnlen - olen], newSup->bv_val, nlen );
	newDN->bv_val[dnlen - olen + nlen] = '\0';

	return;
}

static int dnlist_subordinate(
	BerVarray dnlist,
	struct berval *dn )
{
	assert( dnlist );

	for( ; dnlist->bv_val != NULL; dnlist++ ) {
		if( dnIsSuffix( dnlist, dn ) ) {
			return 1;
		}
	}

	return 0;
}

/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/socket.h>
#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"


static char* get_alias_dn(
	Entry *e,
	int *err,
	char **errmsg );

static char* new_superior(
	char *dn,
	char *oldSup,
	char *newSup );

static int dnlist_subordinate(
	char** dnlist,
	char *dn );

Entry *deref_internal_r(
	Backend*	be,
	Entry*		alias,
	char*		dn,
	int*		err,
	Entry**		matched,
	char**		text )
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	Entry *entry;
	Entry *sup;
	unsigned depth;
	char **dnlist;

	assert( ( alias != NULL && dn == NULL ) || ( alias == NULL && dn != NULL ) );

	*matched = NULL;
	*err = LDAP_SUCCESS;
	*text = NULL;

	if( alias == NULL ) {
		dn = ch_strdup( dn );
		entry = dn2entry_r( be, dn, &sup );

	} else {
		dn = ch_strdup( alias->e_ndn );
		entry = alias;
		sup = NULL;
	}

	dnlist = NULL;
	charray_add( &dnlist, dn );

	for( depth=0 ; ; depth++ ) {
		if( entry != NULL ) {
			Entry *newe;
			char *aliasDN;

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
			aliasDN = get_alias_dn( entry, err, text );

			if( aliasDN == NULL ) {
				*matched = entry;
				entry = NULL;
				break;
			}

			/* check if aliasDN is a subordinate of any DN in our list */
			if( dnlist_subordinate( dnlist, aliasDN ) ) {
				*matched = entry;
				entry = NULL;
				*err = LDAP_ALIAS_PROBLEM;
				*text = "circular alias";
				break;
			}

			/* attempt to dereference alias */

			newe = dn2entry_r( be, aliasDN, &sup );

			if( newe != NULL ) {
				free( dn );
				cache_return_entry_r(&li->li_cache, entry );
				entry = newe;
				dn = ch_strdup( entry->e_ndn );
				charray_add( &dnlist, dn );
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
			char *supDN;
			char *aliasDN;

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
			supDN = get_alias_dn( sup, err, text );

			if( supDN == NULL ) {
				*matched = sup;
				break;
			}

			aliasDN = new_superior( dn, sup->e_ndn, supDN );

			if( aliasDN == NULL ) {
				free(aliasDN);
				*matched = sup;
				*err = LDAP_ALIAS_PROBLEM;
				*text = "superior alias problem";
				break;
			}

			/* check if aliasDN is a subordinate of any DN in our list */
			if( dnlist_subordinate( dnlist, aliasDN ) ) {
				free(aliasDN);
				*matched = entry;
				entry = NULL;
				*err = LDAP_ALIAS_PROBLEM;
				*text = "subordinate circular alias";
				break;
			}

			/* attempt to dereference alias */
			newe = dn2entry_r( be, aliasDN, &newSup );

			if( newe != NULL ) {
				free(aliasDN);
				free( dn );
				cache_return_entry_r(&li->li_cache, sup );
				entry = newe;
				dn = ch_strdup( entry->e_ndn );
				charray_add( &dnlist, dn );
				continue;

			}
			
			if ( newSup != NULL ) {
				free( dn );
				cache_return_entry_r(&li->li_cache, sup );
				sup = newSup;
				dn = aliasDN;
				continue;
			}

			break;

		} else {
			/* no newe and no superior, we're done */
			break;
		}
	}

	free( dn );
	charray_free( dnlist );
	return entry;
}


static char* get_alias_dn(
	Entry *e,
	int *err,
	char **errmsg )
{	
	Attribute *a;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	static AttributeDescription *aliasedObjectName = NULL;
#else
	static const char *aliasedObjectName = NULL;
#endif

	a = attr_find( e->e_attrs, aliasedObjectName );

	if( a == NULL ) {
		/*
		 * there was an aliasedobjectname defined but no data.
		 */
		*err = LDAP_ALIAS_PROBLEM;
		*errmsg = "alias missing aliasedObjectName attribute";
		return NULL;
	}

	/* 
	 * aliasedObjectName should be SINGLE-VALUED with a single value. 
	 */			
	if ( a->a_vals[0] == NULL || a->a_vals[0]->bv_val == NULL ) {
		/*
		 * there was an aliasedobjectname defined but no data.
		 */
		*err = LDAP_ALIAS_PROBLEM;
		*errmsg = "alias missing aliasedObjectName value";
		return NULL;
	}

	if( a->a_vals[1] != NULL ) {
		*err = LDAP_ALIAS_PROBLEM;
		*errmsg = "alias has multivalued aliasedObjectName";
		return NULL;
	}

	return a->a_vals[0]->bv_val;
}

char* new_superior(
	char *dn,
	char *oldSup,
	char *newSup )
{
	char *newDN;
	size_t dnlen, olen, nlen;
	assert( dn && oldSup && newSup );

	dnlen = strlen( dn );
	olen = strlen( oldSup );
	nlen = strlen( newSup );

	newDN = ch_malloc( dnlen - olen + nlen + 1 );

	memcpy( newDN, dn, dnlen - olen );
	memcpy( &newDN[dnlen - olen], newSup, nlen );
	newDN[dnlen - olen + nlen] = '\0';

	return newDN;
}

static int dnlist_subordinate(
	char** dnlist,
	char *dn )
{
	int i;
	assert( dnlist );

	for( i = 0; dnlist[i] != NULL; i++ ) {
		if( dn_issuffix( dnlist[i], dn ) ) {
			return 1;
		}
	}

	return 0;
}


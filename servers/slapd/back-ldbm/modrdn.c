/* modrdn.c - ldbm backend modrdn routine */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * LDAP v3 newSuperior support. Add new rdn as an attribute.
 * (Full support for v2 also used software/ideas contributed
 * by Roy Hooper rhooper@cyberus.ca, thanks to him for his
 * submission!.)
 *
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_modrdn(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*newrdn,
    int		deleteoldrdn,
    char	*newSuperior
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*p_dn = NULL, *p_ndn = NULL;
	char		*new_dn = NULL, *new_ndn = NULL;
	Entry		*e, *p = NULL;
	Entry		*matched = NULL;
	int			rootlock = 0;
	int			rc = -1;
	/* Added to support LDAP v2 correctly (deleteoldrdn thing) */
	char		*new_rdn_val = NULL;	/* Val of new rdn */
	char		*new_rdn_type = NULL;	/* Type of new rdn */
	char		*old_rdn = NULL;    	/* Old rdn's attr type & val */
	char		*old_rdn_type = NULL;	/* Type of old rdn attr. */
	char		*old_rdn_val = NULL;	/* Old rdn attribute value */
	/* Added to support newSuperior */ 
	Entry		*np = NULL;	/* newSuperior Entry */
	char		*np_dn = NULL;  /* newSuperior dn */
	char		*np_ndn = NULL; /* newSuperior ndn */
	char		*new_parent_dn = NULL;	/* np_dn, p_dn, or NULL */
	/* Used to interface with ldbm_modify_internal() */
	struct berval	add_bv;			/* Stores new rdn att */
	struct berval	*add_bvals[2];		/* Stores new rdn att */
	struct berval	del_bv;			/* Stores old rdn att */
	struct berval	*del_bvals[2];		/* Stores old rdn att */
	LDAPModList	mod[2];			/* Used to delete old rdn */
	int		manageDSAit = get_manageDSAit( op );

	Debug( LDAP_DEBUG_TRACE, "==>ldbm_back_modrdn(newSuperior=%s)\n",
	       (newSuperior ? newSuperior : "NULL"),
	       0, 0 );

	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, dn, &matched )) == NULL ) {
		char* matched_dn = NULL;
		struct berval** refs = NULL;

		if( matched != NULL ) {
			matched_dn = strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return( -1 );
	}

#ifdef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
	if ( ! access_allowed( be, conn, op, e,
		"entry", NULL, ACL_WRITE ) )
	{
		Debug( LDAP_DEBUG_TRACE, "no access to entry\n", 0,
			0, 0 );
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}
#endif

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );

		goto return_results;
	}

	if ( (p_ndn = dn_parent( be, e->e_ndn )) != NULL ) {

		/* Make sure parent entry exist and we can write its 
		 * children.
		 */

		if( (p = dn2entry_w( be, p_ndn, &matched )) == NULL) {
			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0);
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

		/* check parent for "children" acl */
		if ( ! access_allowed( be, conn, op, p,
			"children", NULL, ACL_WRITE ) )
		{
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
				0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: wr to children of entry %s OK\n",
		       p_ndn, 0, 0 );
		
		p_dn = dn_parent( be, e->e_dn );
	

		Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: parent dn=%s\n",
		       p_dn, 0, 0 );

	} else {
		/* no parent, modrdn entry directly under root */
		if( ! be_isroot( be, op->o_ndn ) ) {
			Debug( LDAP_DEBUG_TRACE, "no parent & not root\n",
				0, 0, 0);
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

		ldap_pvt_thread_mutex_lock(&li->li_root_mutex);
		rootlock = 1;
		
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: no parent, locked root\n",
		       0, 0, 0 );

	}

	new_parent_dn = p_dn;	/* New Parent unless newSuperior given */

	if ( (np_dn = newSuperior) != NULL) {
		Debug( LDAP_DEBUG_TRACE, 
		       "ldbm_back_modrdn: new parent requested...\n",
		       0, 0, 0 );

		np_ndn = ch_strdup( np_dn );
		(void) dn_normalize_case( np_ndn );

		/* newSuperior == oldParent?, if so ==> ERROR */
		/* newSuperior == entry being moved?, if so ==> ERROR */
		/* Get Entry with dn=newSuperior. Does newSuperior exist? */

		if( (np = dn2entry_w( be, np_ndn, &matched )) == NULL) {
			Debug( LDAP_DEBUG_TRACE,
			       "ldbm_back_modrdn: newSup(ndn=%s) not here!\n",
			       np_ndn, 0, 0);
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: wr to new parent OK np=%p, id=%d\n",
		       np, np->e_id, 0 );
	    
		/* check newSuperior for "children" acl */
		if ( !access_allowed( be, conn, op, np, "children", NULL,
				      ACL_WRITE ) )
		{
			Debug( LDAP_DEBUG_TRACE,
			       "ldbm_back_modrdn: no wr to newSup children\n",
			       0, 0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

		if ( is_entry_alias( np ) ) {
			/* entry is an alias, don't allow bind */
			Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0,
			    0, 0 );

			send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM,
			    NULL, NULL, NULL, NULL );

			goto return_results;
		}

		if ( is_entry_referral( np ) ) {
			/* parent is a referral, don't allow add */
			/* parent is an alias, don't allow add */
			Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
				0, 0 );

			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			    NULL, NULL, NULL, NULL );

			goto return_results;
		}

		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: wr to new parent's children OK\n",
		       0, 0 , 0 );

		new_parent_dn = np_dn;
	}
	
	/* Build target dn and make sure target entry doesn't exist already. */

	build_new_dn( &new_dn, e->e_dn, new_parent_dn, newrdn ); 


	new_ndn = ch_strdup(new_dn);
	(void) dn_normalize_case( new_ndn );

	Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: new ndn=%s\n",
	       new_ndn, 0, 0 );

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto return_results;
	}

	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
	if (dn2id ( be, new_ndn ) != NOID) {
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

	Debug( LDAP_DEBUG_TRACE,
	       "ldbm_back_modrdn: new ndn=%s does not exist\n",
	       new_ndn, 0, 0 );

	/* Get attribute type and attribute value of our new rdn, we will
	 * need to add that to our new entry
	 */

	if ( (new_rdn_type = rdn_attr_type( newrdn )) == NULL ) {
	    
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: can't figure out type of newrdn\n",
		       0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;		

	}

	if ( (new_rdn_val = rdn_attr_value( newrdn )) == NULL ) {
	    
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: can't figure out val of newrdn\n",
		       0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;		

	}

	Debug( LDAP_DEBUG_TRACE,
	       "ldbm_back_modrdn: new_rdn_val=\"%s\", new_rdn_type=\"%s\"\n",
	       new_rdn_val, new_rdn_type, 0 );

	/* Retrieve the old rdn from the entry's dn */

	if ( (old_rdn = dn_rdn( be, dn )) == NULL ) {

		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: can't figure out old_rdn from dn\n",
		       0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;		

	}

	if ( (old_rdn_type = rdn_attr_type( old_rdn )) == NULL ) {
	    
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: can't figure out the old_rdn type\n",
		       0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;		
		
	}
	
	if ( strcasecmp( old_rdn_type, new_rdn_type ) != 0 ) {

	    /* Not a big deal but we may say something */
	    Debug( LDAP_DEBUG_TRACE,
		   "ldbm_back_modrdn: old_rdn_type=%s, new_rdn_type=%s!\n",
		   old_rdn_type, new_rdn_type, 0 );
	    
	}		

#ifdef DNS_DN
	if ( dn_type( old_rdn ) == DN_X500 ) {
#endif

		Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: DN_X500\n",
		       0, 0, 0 );
		
		/* Add new attribute value to the entry.
		 */

		add_bvals[0] = &add_bv;		/* Array of bervals */
		add_bvals[1] = NULL;

		add_bv.bv_val = new_rdn_val;
		add_bv.bv_len = strlen(new_rdn_val);
		
		mod[0].ml_type = new_rdn_type;	
		mod[0].ml_bvalues = add_bvals;
		mod[0].ml_op = LDAP_MOD_SOFTADD;
		mod[0].ml_next = NULL;

		/* Remove old rdn value if required */

		if (deleteoldrdn) {
			/* Get value of old rdn */
	
			if ((old_rdn_val = rdn_attr_value( old_rdn ))
			    == NULL) {
			    
				Debug( LDAP_DEBUG_TRACE,
				       "ldbm_back_modrdn: can't figure out old_rdn_val from old_rdn\n",
				       0, 0, 0 );
				send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
					NULL, NULL, NULL, NULL );
				goto return_results;		
			}

			del_bvals[0] = &del_bv;		/* Array of bervals */
			del_bvals[1] = NULL;

			/* Remove old value of rdn as an attribute. */
		    
			del_bv.bv_val = old_rdn_val;
			del_bv.bv_len = strlen(old_rdn_val);

			/* No need to normalize old_rdn_type, delete_values()
			 * does that for us
			 */
			mod[0].ml_next = &mod[1];
			mod[1].ml_type = old_rdn_type;	
			mod[1].ml_bvalues = del_bvals;
			mod[1].ml_op = LDAP_MOD_DELETE;
			mod[1].ml_next = NULL;

			Debug( LDAP_DEBUG_TRACE,
			       "ldbm_back_modrdn: removing old_rdn_val=%s\n",
			       old_rdn_val, 0, 0 );
		}
	
#ifdef DNS_DN
	} else {
		Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: DNS DN\n",
		       0, 0, 0 );
		/* XXXV3: not sure of what to do here */
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: not fully implemented...\n",
		       0, 0, 0 );
  
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;

	}
#endif

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto return_results;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* delete old one */
	if ( dn2id_delete( be, e->e_ndn, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

	(void) cache_delete_entry( &li->li_cache, e );

	/* XXX: there is no going back! */

	free( e->e_dn );
	free( e->e_ndn );
	e->e_dn = new_dn;
	e->e_ndn = new_ndn;
	new_dn = NULL;
	new_ndn = NULL;

	/* add new one */
	if ( dn2id_add( be, e->e_ndn, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

	/* modify memory copy of entry */
	if ( ldbm_modify_internal( be, conn, op, dn, &mod[0], e )
	     != 0 ) {
	    
	    goto return_results;
	}
	
	(void) cache_update_entry( &li->li_cache, e );

	/* NOTE: after this you must not free new_dn or new_ndn!
	 * They are used by cache.
	 */

	/* id2entry index */
	if ( id2entry_add( be, e ) != 0 ) {
		entry_free( e );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );
	rc = 0;

return_results:
	if( new_dn != NULL ) free( new_dn );
	if( new_ndn != NULL ) free( new_ndn );

	if( p_dn != NULL ) free( p_dn );
	if( p_ndn != NULL ) free( p_ndn );

	if( matched != NULL ) free( matched );

	/* LDAP v2 supporting correct attribute handling. */
	if( new_rdn_type != NULL ) free(new_rdn_type);
	if( new_rdn_val != NULL ) free(new_rdn_val);
	if( old_rdn != NULL ) free(old_rdn);
	if( old_rdn_type != NULL ) free(old_rdn_type);
	if( old_rdn_val != NULL ) free(old_rdn_val);


	/* LDAP v3 Support */
	if ( np_dn != NULL ) free( np_dn );
	if ( np_ndn != NULL ) free( np_ndn );

	if( np != NULL ) {
		/* free new parent and writer lock */
		cache_return_entry_w( &li->li_cache, np );
	}

	if( p != NULL ) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p );
	}

	if ( rootlock ) {
		/* release root writer lock */
		ldap_pvt_thread_mutex_unlock(&li->li_root_mutex);
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );
	return( rc );
}

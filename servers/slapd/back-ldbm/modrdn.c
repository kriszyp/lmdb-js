/* modrdn.c - ldbm backend modrdn routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
    struct berval	*dn,
    struct berval	*ndn,
    struct berval	*newrdn,
    struct berval	*nnewrdn,
    int		deleteoldrdn,
    struct berval	*newSuperior,
    struct berval	*nnewSuperior
)
{
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct berval	p_dn, p_ndn;
	struct berval	new_dn = { 0, NULL}, new_ndn = { 0, NULL };
	Entry		*e, *p = NULL;
	Entry		*matched;
	/* LDAP v2 supporting correct attribute handling. */
	LDAPRDN		*new_rdn = NULL;
	LDAPRDN		*old_rdn = NULL;
	int		isroot = -1;
#define CAN_ROLLBACK	-1
#define MUST_DESTROY	1
	int		rc = CAN_ROLLBACK;
	int 		rc_id = 0;
	ID              id = NOID;
	const char *text = NULL;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	/* Added to support newSuperior */ 
	Entry		*np = NULL;	/* newSuperior Entry */
	struct berval	*np_ndn = NULL; /* newSuperior ndn */
	struct berval	*new_parent_dn = NULL;	/* np_dn, p_dn, or NULL */
	/* Used to interface with ldbm_modify_internal() */
	Modifications	*mod = NULL;		/* Used to delete old/add new rdn */
	int		manageDSAit = get_manageDSAit( op );

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, 
		"ldbm_back_modrdn: dn: %s newSuperior=%s\n", 
		dn->bv_len ? dn->bv_val : "NULL",
		( newSuperior && newSuperior->bv_len ) ? newSuperior->bv_val : "NULL",0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"==>ldbm_back_modrdn: dn: %s newSuperior=%s\n", 
		dn->bv_len ? dn->bv_val : "NULL",
		( newSuperior && newSuperior->bv_len )
			? newSuperior->bv_val : "NULL", 0 );
#endif

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, ndn, &matched )) == NULL ) {
		char* matched_dn = NULL;
		BerVarray refs;

		if( matched != NULL ) {
			matched_dn = strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( refs ) ber_bvarray_free( refs );
		free( matched_dn );

		return( -1 );
	}

	/* check entry for "entry" acl */
	if ( ! access_allowed( be, conn, op, e,
		entry, NULL, ACL_WRITE, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_modrdn: no write access to entry of (%s)\n", 
			dn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"<=- ldbm_back_modrdn: no write access to entry\n", 0,
			0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			NULL, "no write access to entry", NULL, NULL );

		goto return_results;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		BerVarray refs = get_entry_referrals( be,
			conn, op, e );

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_modrdn: entry %s is a referral\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry %s is referral\n", e->e_dn,
		    0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		if ( refs ) ber_bvarray_free( refs );
		goto return_results;
	}

	if ( has_children( be, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_modrdn: entry %s has children\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry %s has children\n", e->e_dn,
		    0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF,
		    NULL, "subtree rename not supported", NULL, NULL );
		goto return_results;
	}

	if ( be_issuffix( be, &e->e_nname ) ) {
		p_ndn = slap_empty_bv ;
	} else {
		dnParent( &e->e_nname, &p_ndn );
	}

	if ( p_ndn.bv_len != 0 ) {
		/* Make sure parent entry exist and we can write its 
		 * children.
		 */

		if( (p = dn2entry_w( be, &p_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, 
				"ldbm_back_modrdn: parent of %s does not exist\n", 
				e->e_ndn, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0);
#endif

			send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "parent entry does not exist", NULL, NULL );

			goto return_results;
		}

		/* check parent for "children" acl */
		if ( ! access_allowed( be, conn, op, p,
			children, NULL, ACL_WRITE, NULL ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, 
				"ldbm_back_modrdn: no access to parent of (%s)\n", 
				e->e_dn, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
				0, 0 );
#endif

			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_modrdn: wr to children of entry %s OK\n", 
			p_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: wr to children of entry %s OK\n",
		       p_ndn.bv_val, 0, 0 );
#endif

		if ( p_ndn.bv_val == slap_empty_bv.bv_val ) {
			p_dn = slap_empty_bv;
		} else {
			dnParent( &e->e_name, &p_dn );
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			   "ldbm_back_modrdn: parent dn=%s\n", p_dn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: parent dn=%s\n",
		       p_dn.bv_val, 0, 0 );
#endif

	} else {
		/* no parent, must be root to modify rdn */
		isroot = be_isroot( be, &op->o_ndn );
		if ( ! isroot ) {
			if ( be_issuffix( be, (struct berval *)&slap_empty_bv ) || be_isupdate( be, &op->o_ndn ) ) {
				p = (Entry *)&slap_entry_root;
				
				rc = access_allowed( be, conn, op, p,
						children, NULL, ACL_WRITE, NULL );
				p = NULL;
								
				/* check parent for "children" acl */
				if ( ! rc ) {
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_LDBM, ERR,
						"ldbm_back_modrdn: no access to parent \"\"\n", 0,0,0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"<=- ldbm_back_modrdn: no "
						"access to parent\n", 0, 0, 0 );
#endif

					send_ldap_result( conn, op, 
						LDAP_INSUFFICIENT_ACCESS,
						NULL, NULL, NULL, NULL );
					goto return_results;
				}

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR, 
					"ldbm_back_modrdn: (%s) has no parent & not a root.\n", 
					dn, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"<=- ldbm_back_modrdn: no parent & "
					"not root\n", 0, 0, 0);
#endif

				send_ldap_result( conn, op, 
					LDAP_INSUFFICIENT_ACCESS,
					NULL, NULL, NULL, NULL );
				goto return_results;
			}
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
		   "ldbm_back_modrdn: (%s) no parent, locked root.\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: no parent, locked root\n",
		       0, 0, 0 );
#endif
	}

	new_parent_dn = &p_dn;	/* New Parent unless newSuperior given */

	if ( newSuperior != NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_modrdn: new parent \"%s\" requested\n",
			newSuperior->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, 
			"ldbm_back_modrdn: new parent \"%s\" requested...\n",
			newSuperior->bv_val, 0, 0 );
#endif

		np_ndn = nnewSuperior;

		/* newSuperior == oldParent? */
		if ( dn_match( &p_ndn, np_ndn ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, "ldbm_back_modrdn: "
				"new parent\"%s\" seems to be the same as the "
				"old parent \"%s\"\n", newSuperior->bv_val, p_dn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: "
				"new parent\"%s\" seems to be the same as the "
				"old parent \"%s\"\n",
				newSuperior->bv_val, p_dn.bv_val, 0 );
#endif

			newSuperior = NULL; /* ignore newSuperior */
		}
	}

	if ( newSuperior != NULL ) {
		/* newSuperior == entry being moved?, if so ==> ERROR */
		/* Get Entry with dn=newSuperior. Does newSuperior exist? */

		if ( nnewSuperior->bv_len ) {
			if( (np = dn2entry_w( be, np_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR, 
					"ldbm_back_modrdn: newSup(ndn=%s) not found.\n", 
					np_ndn->bv_val, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
				    "ldbm_back_modrdn: newSup(ndn=%s) not here!\n",
				    np_ndn->bv_val, 0, 0);
#endif

				send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "newSuperior not found", NULL, NULL );
				goto return_results;
			}

#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, DETAIL1,
				"ldbm_back_modrdn: wr to new parent OK np=%p, id=%ld\n",
				np, np->e_id, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_back_modrdn: wr to new parent OK np=%p, id=%ld\n",
				np, np->e_id, 0 );
#endif

			/* check newSuperior for "children" acl */
			if ( !access_allowed( be, conn, op, np, children, NULL,
					      ACL_WRITE, NULL ) )
			{
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO,
				   "ldbm_back_modrdn: no wr to newSup children.\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
				       "ldbm_back_modrdn: no wr to newSup children\n",
				       0, 0, 0 );
#endif

				send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
					NULL, NULL, NULL, NULL );
				goto return_results;
			}

			if ( is_entry_alias( np ) ) {
				/* parent is an alias, don't allow add */
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO,
				   "ldbm_back_modrdn: entry (%s) is an alias.\n", np->e_dn,0,0);
#else
				Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0, 0, 0 );
#endif


				send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM,
				    NULL, "newSuperior is an alias", NULL, NULL );

				goto return_results;
			}

			if ( is_entry_referral( np ) ) {
				/* parent is a referral, don't allow add */
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO,
					"ldbm_back_modrdn: entry (%s) is a referral\n",
					np->e_dn, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE, "entry (%s) is referral\n",
					np->e_dn, 0, 0 );
#endif

				send_ldap_result( conn, op, LDAP_OTHER,
				    NULL, "newSuperior is a referral", NULL, NULL );

				goto return_results;
			}

		} else {

			/* no parent, must be root to modify newSuperior */
			if ( isroot == -1 ) {
				isroot = be_isroot( be, &op->o_ndn );
			}

			if ( ! isroot ) {
				if ( be_issuffix( be, (struct berval *)&slap_empty_bv ) || be_isupdate( be, &op->o_ndn ) ) {
					np = (Entry *)&slap_entry_root;
				
					rc = access_allowed( be, conn, op, np,
							children, NULL, ACL_WRITE, NULL );
					np = NULL;
								
					/* check parent for "children" acl */
					if ( ! rc ) {
#ifdef NEW_LOGGING
						LDAP_LOG( BACK_LDBM, ERR,
							"ldbm_back_modrdn: no access "
							"to new superior \"\"\n", 0, 0, 0 );
#else
						Debug( LDAP_DEBUG_TRACE,
							"<=- ldbm_back_modrdn: no "
							"access to new superior\n", 0, 0, 0 );
#endif

						send_ldap_result( conn, op, 
							LDAP_INSUFFICIENT_ACCESS,
							NULL, NULL, NULL, NULL );
						goto return_results;
					}

				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_LDBM, ERR,
						"ldbm_back_modrdn: \"\" not allowed as new superior\n",
						0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"<=- ldbm_back_modrdn: \"\" "
						"not allowed as new superior\n", 
						0, 0, 0);
#endif

					send_ldap_result( conn, op, 
						LDAP_INSUFFICIENT_ACCESS,
						NULL, NULL, NULL, NULL );
					goto return_results;
				}
			}
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1,
			"ldbm_back_modrdn: wr to new parent's children OK.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
		    "ldbm_back_modrdn: wr to new parent's children OK\n",
		    0, 0, 0 );
#endif

		new_parent_dn = newSuperior;
	}
	
	/* Build target dn and make sure target entry doesn't exist already. */
	build_new_dn( &new_dn, new_parent_dn, newrdn ); 
	dnNormalize2( NULL, &new_dn, &new_ndn );

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, DETAIL1, "ldbm_back_modrdn: new ndn=%s\n", 
		new_ndn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: new ndn=%s\n",
	    new_ndn.bv_val, 0, 0 );
#endif

	/* check for abandon */
	if ( op->o_abandon ) {
		goto return_results;
	}

	if ( ( rc_id = dn2id ( be, &new_ndn, &id ) ) || id != NOID ) {
		/* if (rc_id) something bad happened to ldbm cache */
		send_ldap_result( conn, op, 
			rc_id ? LDAP_OTHER : LDAP_ALREADY_EXISTS,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, INFO, "ldbm_back_modrdn: new ndn (%s) does not exist\n",
		new_ndn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	    "ldbm_back_modrdn: new ndn=%s does not exist\n",
	    new_ndn.bv_val, 0, 0 );
#endif

	/* Get attribute type and attribute value of our new rdn, we will
	 * need to add that to our new entry
	 */
	if ( ldap_bv2rdn( newrdn, &new_rdn, (char **)&text,
		LDAP_DN_FORMAT_LDAP ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"ldbm_back_modrdn: can't figure out "
			"type(s)/values(s) of newrdn\n", 
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"ldbm_back_modrdn: can't figure out "
			"type(s)/values(s) of newrdn\n", 
			0, 0, 0 );
#endif
		rc = LDAP_INVALID_DN_SYNTAX;
		text = "unknown type(s) used in RDN";
		goto return_results;		
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, RESULTS, 
		"ldbm_back_modrdn: new_rdn_type=\"%s\", "
		"new_rdn_val=\"%s\"\n",
		new_rdn[ 0 ][ 0 ]->la_attr.bv_val, 
		new_rdn[ 0 ][ 0 ]->la_value.bv_val, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"ldbm_back_modrdn: new_rdn_type=\"%s\", "
		"new_rdn_val=\"%s\"\n",
		new_rdn[ 0 ][ 0 ]->la_attr.bv_val,
		new_rdn[ 0 ][ 0 ]->la_value.bv_val, 0 );
#endif

	if ( deleteoldrdn ) {
		if ( ldap_bv2rdn( dn, &old_rdn, (char **)&text,
			LDAP_DN_FORMAT_LDAP ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"ldbm_back_modrdn: can't figure out "
				"type(s)/values(s) of old_rdn\n", 
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_back_modrdn: can't figure out "
				"the old_rdn type(s)/value(s)\n", 
				0, 0, 0 );
#endif
			rc = LDAP_OTHER;
			text = "cannot parse RDN from old DN";
			goto return_results;		
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, DETAIL1, "ldbm_back_modrdn:  DN_X500\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: DN_X500\n",
	       0, 0, 0 );
#endif
	
	rc = slap_modrdn2mods( be, conn, op, e, old_rdn, new_rdn, 
			deleteoldrdn, &mod );
	if ( rc != LDAP_SUCCESS ) {
		goto return_results;
	}


	/* check for abandon */
	if ( op->o_abandon ) {
		goto return_results;
	}

	/* delete old one */
	if ( dn2id_delete( be, &e->e_nname, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DN index delete fail", NULL, NULL );
		goto return_results;
	}

	(void) cache_delete_entry( &li->li_cache, e );
	rc = MUST_DESTROY;

	/* XXX: there is no going back! */

	free( e->e_dn );
	free( e->e_ndn );
	e->e_name = new_dn;
	e->e_nname = new_ndn;
	new_dn.bv_val = NULL;
	new_ndn.bv_val = NULL;

	/* add new one */
	if ( dn2id_add( be, &e->e_nname, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DN index add failed", NULL, NULL );
		goto return_results;
	}

	/* modify memory copy of entry */
	rc = ldbm_modify_internal( be, conn, op, dn->bv_val, &mod[0], e,
		&text, textbuf, textlen );

	if( rc != LDAP_SUCCESS ) {
		if( rc != SLAPD_ABANDON ) {
			send_ldap_result( conn, op, rc,
				NULL, text, NULL, NULL );
		}

		/* here we may try to delete the newly added dn */
		if ( dn2id_delete( be, &e->e_nname, e->e_id ) != 0 ) {
			/* we already are in trouble ... */
			;
		}
	    
    		goto return_results;
	}
	
	(void) cache_update_entry( &li->li_cache, e );

	/* NOTE: after this you must not free new_dn or new_ndn!
	 * They are used by cache.
	 */

	/* id2entry index */
	if ( id2entry_add( be, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "entry update failed", NULL, NULL );
		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );
	rc = 0;
	cache_entry_commit( e );

return_results:
	if( new_dn.bv_val != NULL ) free( new_dn.bv_val );
	if( new_ndn.bv_val != NULL ) free( new_ndn.bv_val );

	/* LDAP v2 supporting correct attribute handling. */
	if ( new_rdn != NULL ) {
		ldap_rdnfree( new_rdn );
	}
	if ( old_rdn != NULL ) {
		ldap_rdnfree( old_rdn );
	}
	if ( mod != NULL ) {
		Modifications *tmp;
		for (; mod; mod = tmp ) {
			tmp = mod->sml_next;
			free( mod );
		}
	}

	/* LDAP v3 Support */
	if( np != NULL ) {
		/* free new parent and writer lock */
		cache_return_entry_w( &li->li_cache, np );
	}

	if( p != NULL ) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p );
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );
	if ( rc == MUST_DESTROY ) {
		/* if rc == MUST_DESTROY the entry is uncached 
		 * and its private data is destroyed; 
		 * the entry must be freed */
		entry_free( e );
	}
	ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
	return( rc );
}

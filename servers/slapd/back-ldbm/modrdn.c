/* modrdn.c - ldbm backend modrdn routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
    const char	*dn,
    const char	*ndn,
    const char	*newrdn,
    int		deleteoldrdn,
    const char	*newSuperior
)
{
	AttributeDescription *children = slap_schema.si_ad_children;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*p_dn = NULL, *p_ndn = NULL;
	char		*new_dn = NULL, *new_ndn = NULL;
	Entry		*e, *p = NULL;
	Entry		*matched;
	int		isroot = -1;
	int		rootlock = 0;
#define CAN_ROLLBACK	-1
#define MUST_DESTROY	1
	int		rc = CAN_ROLLBACK;
	int 		rc_id = 0;
	ID              id = NOID;
	const char *text = NULL;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	/* Added to support LDAP v2 correctly (deleteoldrdn thing) */
	char            **new_rdn_vals = NULL;  /* Vals of new rdn */
	char		**new_rdn_types = NULL;	/* Types of new rdn */
	int             a_cnt, d_cnt;
	char		*old_rdn = NULL;	/* Old rdn's attr type & val */
	char		**old_rdn_types = NULL;	/* Types of old rdn attrs. */
	char		**old_rdn_vals = NULL;	/* Old rdn attribute values */
	/* Added to support newSuperior */ 
	Entry		*np = NULL;	/* newSuperior Entry */
	char		*np_dn = NULL;	/* newSuperior dn */
	char		*np_ndn = NULL; /* newSuperior ndn */
	char		*new_parent_dn = NULL;	/* np_dn, p_dn, or NULL */
	/* Used to interface with ldbm_modify_internal() */
	Modifications	*mod = NULL;		/* Used to delete old/add new rdn */
	int		manageDSAit = get_manageDSAit( op );

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		"ldbm_back_modrdn: dn: %s newSuperior=%s\n", 
		dn ? dn : "NULL", newSuperior ? newSuperior : "NULL" ));
#else
	Debug( LDAP_DEBUG_TRACE, "==>ldbm_back_modrdn(newSuperior=%s)\n",
	    (newSuperior ? newSuperior : "NULL"),
	    0, 0 );
#endif

	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, ndn, &matched )) == NULL ) {
		char* matched_dn = NULL;
		struct berval** refs;

		if( matched != NULL ) {
			matched_dn = strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched,
					dn, LDAP_SCOPE_DEFAULT )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		ber_bvecfree( refs );
		free( matched_dn );

		return( -1 );
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e, dn, LDAP_SCOPE_DEFAULT );

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			"ldbm_back_modrdn: entry %s is a referral\n", e->e_dn ));
#else
		Debug( LDAP_DEBUG_TRACE, "entry %s is referral\n", e->e_dn,
		    0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );
		goto return_results;
	}

	if ( has_children( be, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			"ldbm_back_modrdn: entry %s has children\n", e->e_dn ));
#else
		Debug( LDAP_DEBUG_TRACE, "entry %s has children\n", e->e_dn,
		    0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF,
		    NULL, "subtree rename not supported", NULL, NULL );
		goto return_results;
	}

	if ( (p_ndn = dn_parent( be, e->e_ndn )) != NULL && p_ndn[0] != '\0' ) {
		/* Make sure parent entry exist and we can write its 
		 * children.
		 */

		if( (p = dn2entry_w( be, p_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				"ldbm_back_modrdn: parent of %s does not exist\n", e->e_ndn ));
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
			children, NULL, ACL_WRITE ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				   "ldbm_back_modrdn: no access to parent of (%s)\n", e->e_dn ));
#else
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
				0, 0 );
#endif

			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
			   "ldbm_back_modrdn: wr to children of entry %s OK\n",
			   p_ndn ));
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: wr to children of entry %s OK\n",
		       p_ndn, 0, 0 );
#endif

		p_dn = dn_parent( be, e->e_dn );

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
			   "ldbm_back_modrdn: parent dn=%s\n", p_dn ));
#else
		Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: parent dn=%s\n",
		       p_dn, 0, 0 );
#endif

	} else {
		/* no parent, must be root to modify rdn */
		isroot = be_isroot( be, op->o_ndn );
		if ( ! be_isroot ) {
			if ( be_issuffix( be, "" )
					|| be_isupdate( be, op->o_ndn ) ) {
				p = (Entry *)&slap_entry_root;
				
				rc = access_allowed( be, conn, op, p,
						children, NULL, ACL_WRITE );
				p = NULL;
								
				/* check parent for "children" acl */
				if ( ! rc ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
						"ldbm_back_modrdn: no access "
						"to parent \"\"\n" ));
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
				LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
					   "ldbm_back_modrdn: (%s) has no "
					   "parent & not a root.\n", dn ));
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

		ldap_pvt_thread_mutex_lock(&li->li_root_mutex);
		rootlock = 1;
		
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_modrdn: (%s) no parent, locked root.\n", e->e_dn ));
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: no parent, locked root\n",
		       0, 0, 0 );
#endif
	}

	new_parent_dn = p_dn;	/* New Parent unless newSuperior given */

	if ( newSuperior != NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
			   "ldbm_back_modrdn: new parent \"%s\" requested\n", newSuperior ));
#else
		Debug( LDAP_DEBUG_TRACE, 
			"ldbm_back_modrdn: new parent \"%s\" requested...\n",
			newSuperior, 0, 0 );
#endif

		np_dn = ch_strdup( newSuperior );
		np_ndn = ch_strdup( np_dn );
		(void) dn_normalize( np_ndn );

		/* newSuperior == oldParent? */
		if ( strcmp( p_ndn, np_ndn ) == 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				   "ldbm_back_modrdn: new parent\"%s\" seems to be the same as the old parent \"%s\"\n",
				   newSuperior, p_dn ));
#else
			Debug( LDAP_DEBUG_TRACE, 
			       "ldbm_back_modrdn: new parent \"%s\" seems to be the same as old parent \"%s\"...\n",
			       newSuperior, p_dn, 0 );
#endif

			newSuperior = NULL; /* ignore newSuperior */
		}
	}

	if ( newSuperior != NULL ) {
		/* newSuperior == entry being moved?, if so ==> ERROR */
		/* Get Entry with dn=newSuperior. Does newSuperior exist? */

		if ( newSuperior[ 0 ] != '\0' ) {

			if( (np = dn2entry_w( be, np_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
					   "ldbm_back_modrdn: newSup(ndn=%s) not found.\n", np_ndn ));
#else
				Debug( LDAP_DEBUG_TRACE,
				       "ldbm_back_modrdn: newSup(ndn=%s) not here!\n",
				       np_ndn, 0, 0);
#endif

				send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "newSuperior not found", NULL, NULL );
				goto return_results;
			}

#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				   "ldbm_back_modrdn: wr to new parent OK np=%p, id=%ld\n",
				   np, np->e_id ));
#else
			Debug( LDAP_DEBUG_TRACE,
			       "ldbm_back_modrdn: wr to new parent OK np=%p, id=%ld\n",
			       np, np->e_id, 0 );
#endif

			/* check newSuperior for "children" acl */
			if ( !access_allowed( be, conn, op, np, children, NULL,
					      ACL_WRITE ) )
			{
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					   "ldbm_back_modrdn: no wr to newSup children.\n" ));
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
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					   "ldbm_back_modrdn: entry (%s) is an alias.\n", np->e_dn ));
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
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					"ldbm_back_modrdn: entry (%s) is a referral\n",
				np->e_dn ));
#else
				Debug( LDAP_DEBUG_TRACE, "entry (%s) is referral\n",
					np->e_dn, 0, 0 );
#endif

				send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				    NULL, "newSuperior is a referral", NULL, NULL );

				goto return_results;
			}

		} else {

			/* no parent, must be root to modify newSuperior */
			if ( isroot == -1 ) {
				isroot = be_isroot( be, op->o_ndn );
			}

			if ( ! be_isroot ) {
				if ( be_issuffix( be, "" )
						|| be_isupdate( be, op->o_ndn ) ) {
					np = (Entry *)&slap_entry_root;
				
					rc = access_allowed( be, conn, op, np,
							children, NULL, ACL_WRITE );
					np = NULL;
								
					/* check parent for "children" acl */
					if ( ! rc ) {
#ifdef NEW_LOGGING
						LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
							"ldbm_back_modrdn: no access "
							"to new superior \"\"\n" ));
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
					LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
						   "ldbm_back_modrdn: \"\" "
						   "not allowed as new superior\n" ));
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
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
			"ldbm_back_modrdn: wr to new parent's children OK.\n" ));
#else
		Debug( LDAP_DEBUG_TRACE,
		    "ldbm_back_modrdn: wr to new parent's children OK\n",
		    0, 0, 0 );
#endif

		new_parent_dn = np_dn;
	}
	
	/* Build target dn and make sure target entry doesn't exist already. */
	build_new_dn( &new_dn, e->e_dn, new_parent_dn, newrdn ); 

	new_ndn = ch_strdup(new_dn);
	(void) dn_normalize( new_ndn );

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
		"ldbm_back_modrdn: new ndn=%s\n", new_ndn ));
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: new ndn=%s\n",
	    new_ndn, 0, 0 );
#endif

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto return_results;
	}

	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
	if ( ( rc_id = dn2id ( be, new_ndn, &id ) ) || id != NOID ) {
		/* if (rc_id) something bad happened to ldbm cache */
		send_ldap_result( conn, op, 
			rc_id ? LDAP_OPERATIONS_ERROR : LDAP_ALREADY_EXISTS,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
		   "ldbm_back_modrdn: new ndn (%s) does not exist\n", new_ndn ));
#else
	Debug( LDAP_DEBUG_TRACE,
	       "ldbm_back_modrdn: new ndn=%s does not exist\n",
	       new_ndn, 0, 0 );
#endif


	/* Get attribute types and values of our new rdn, we will
	 * need to add that to our new entry
	 */
	if ( rdn_attrs( newrdn, &new_rdn_types, &new_rdn_vals ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_modrdn: can't figure out type(s)/value(s) of newrdn\n" ));
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: can't figure out type(s)/value(s) of newrdn\n",
		       0, 0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, "unable to parse type(s)/value(s) used in RDN", NULL, NULL );
		goto return_results;		
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
		   "ldbm_back_modrdn: new_rdn_val=\"%s\", new_rdn_type=\"%s\"\n",
		   new_rdn_vals[0], new_rdn_types[0] ));
#else
	Debug( LDAP_DEBUG_TRACE,
	       "ldbm_back_modrdn: new_rdn_val=\"%s\", new_rdn_type=\"%s\"\n",
	       new_rdn_vals[0], new_rdn_types[0], 0 );
#endif

	/* Retrieve the old rdn from the entry's dn */
	if ( (old_rdn = dn_rdn( be, dn )) == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_modrdn: can't figure out old_rdn from dn (%s)\n",
			   dn ));
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: can't figure out old_rdn from dn\n",
		       0, 0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "could not parse old DN", NULL, NULL );
		goto return_results;		
	}

	if ( rdn_attrs( old_rdn, &old_rdn_types, &old_rdn_vals ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_modrdn: can't figure out the old_rdn type(s)/value(s).\n" ));
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: can't figure out the old_rdn type(s)/value(s)\n",
		       0, 0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "unable to parse type(s)/value(s) used in RDN from old DN", NULL, NULL );
		goto return_results;		
	}
	
	if ( newSuperior == NULL
		&& charray_strcasecmp( (const char **)old_rdn_types, (const char **)new_rdn_types ) != 0 )
	{
	    /* Not a big deal but we may say something */
#ifdef NEW_LOGGING
	    LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
		       "ldbm_back_modrdn: old_rdn_type=%s new_rdn_type=%s\n",
		       old_rdn_types[0], new_rdn_types[0] ));
#else
	    Debug( LDAP_DEBUG_TRACE,
		   "ldbm_back_modrdn: old_rdn_type=%s, new_rdn_type=%s!\n",
		   old_rdn_types[0], new_rdn_types[0], 0 );
#endif
	}		

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
		   "ldbm_back_modrdn:  DN_X500\n" ));
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: DN_X500\n",
	       0, 0, 0 );
#endif

	mod = NULL;
	for ( a_cnt = 0; new_rdn_types[a_cnt]; a_cnt++ ) {
		int 			rc;
		AttributeDescription	*desc = NULL;
		Modifications 		*mod_tmp;
		struct berval 		val;


		rc = slap_str2ad( new_rdn_types[a_cnt], &desc, &text );

		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				   "ldbm_back_modrdn: slap_str2ad error: %s (%s)\n",
				   text, new_rdn_types[a_cnt] ));
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_back_modrdn: %s: %s (new)\n",
				text, new_rdn_types[a_cnt], 0 );
#endif

			send_ldap_result( conn, op, rc,
				NULL, text, NULL, NULL );

			goto return_results;		
		}

		val.bv_val = new_rdn_vals[a_cnt];
		val.bv_len = strlen( val.bv_val );
		if ( ! access_allowed( be, conn, op, e, 
				desc, &val, ACL_WRITE ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				   "ldbm_back_modrdn: access "
				   "not allowed to attr \"%s\"\n",
				   new_rdn_types[a_cnt] ));
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_back_modrdn: access not allowed "
				"to attr \"%s\"\n%s%s",
				new_rdn_types[a_cnt], "", "" );
#endif
			send_ldap_result( conn, op, 
				LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );

			goto return_results;
		}

		mod_tmp = (Modifications *)ch_malloc( sizeof( Modifications ) );
		mod_tmp->sml_desc = desc;
		mod_tmp->sml_bvalues = (struct berval **)ch_malloc( 2 * sizeof(struct berval *) );
		mod_tmp->sml_bvalues[0] = ber_bvstrdup( new_rdn_vals[a_cnt] );
		mod_tmp->sml_bvalues[1] = NULL;
		mod_tmp->sml_op = SLAP_MOD_SOFTADD;
		mod_tmp->sml_next = mod;
		mod = mod_tmp;
	}

	/* Remove old rdn value if required */
	if ( deleteoldrdn ) {
		/* Get value of old rdn */
		if ( old_rdn_vals == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				   "ldbm_back_modrdn: can't figure out old RDN value(s) from old RDN\n" ));
#else
			Debug( LDAP_DEBUG_TRACE,
			       "ldbm_back_modrdn: can't figure out oldRDN value(s) from old RDN\n",
			       0, 0, 0 );
#endif

			send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "could not parse value(s) from old RDN", NULL, NULL );
			goto return_results;		
		}

		for ( d_cnt = 0; old_rdn_types[d_cnt]; d_cnt++ ) {    
			int 			rc;
			AttributeDescription	*desc = NULL;
			Modifications 		*mod_tmp;
			struct berval 		val;


			rc = slap_str2ad( old_rdn_types[d_cnt], &desc, &text );

			if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					   "ldbm_back_modrdn: %s: %s (old)\n",
					   text, old_rdn_types[d_cnt] ));
#else
				Debug( LDAP_DEBUG_TRACE,
					"ldbm_back_modrdn: %s: %s (old)\n",
					text, old_rdn_types[d_cnt], 0 );
#endif

				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );

				goto return_results;
			}

			val.bv_val = old_rdn_vals[d_cnt];
			val.bv_len = strlen( val.bv_val );
			if ( ! access_allowed( be, conn, op, e, 
					desc, &val, ACL_WRITE ) ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					   "ldbm_back_modrdn: access "
					   "not allowed to attr \"%s\"\n",
					   old_rdn_types[d_cnt] ));
#else
				Debug( LDAP_DEBUG_TRACE,
					"ldbm_back_modrdn: access not allowed "
					"to attr \"%s\"\n%s%s",
					old_rdn_types[d_cnt], "", "" );
#endif
				send_ldap_result( conn, op, 
					LDAP_INSUFFICIENT_ACCESS,
					NULL, NULL, NULL, NULL );

				goto return_results;
			}

			/* Remove old value of rdn as an attribute. */
			mod_tmp = (Modifications *)ch_malloc( sizeof( Modifications ) );
			mod_tmp->sml_desc = desc;
			mod_tmp->sml_bvalues = (struct berval **)ch_malloc( 2 * sizeof(struct berval *) );
			mod_tmp->sml_bvalues[0] = ber_bvstrdup( old_rdn_vals[d_cnt] );
			mod_tmp->sml_bvalues[1] = NULL;
			mod_tmp->sml_op = LDAP_MOD_DELETE;
			mod_tmp->sml_next = mod;
			mod = mod_tmp;

#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				   "ldbm_back_modrdn: removing old_rdn_val=%s\n", old_rdn_vals[0] ));
#else
			Debug( LDAP_DEBUG_TRACE,
			       "ldbm_back_modrdn: removing old_rdn_val=%s\n",
			       old_rdn_vals[0], 0, 0 );
#endif
		}
	}

	
	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto return_results;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* delete old one */
	if ( dn2id_delete( be, e->e_ndn, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DN index delete fail", NULL, NULL );
		goto return_results;
	}

	(void) cache_delete_entry( &li->li_cache, e );
	rc = MUST_DESTROY;

	/* XXX: there is no going back! */

	free( e->e_dn );
	free( e->e_ndn );
	e->e_dn = new_dn;
	e->e_ndn = new_ndn;
	new_dn = NULL;
	new_ndn = NULL;

	/* add new one */
	if ( dn2id_add( be, e->e_ndn, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DN index add failed", NULL, NULL );
		goto return_results;
	}

	/* modify memory copy of entry */
	rc = ldbm_modify_internal( be, conn, op, dn, &mod[0], e,
		&text, textbuf, textlen );

	if( rc != LDAP_SUCCESS ) {
		if( rc != SLAPD_ABANDON ) {
			send_ldap_result( conn, op, rc,
				NULL, text, NULL, NULL );
		}

		/* here we may try to delete the newly added dn */
		if ( dn2id_delete( be, e->e_ndn, e->e_id ) != 0 ) {
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
	if( new_dn != NULL ) free( new_dn );
	if( new_ndn != NULL ) free( new_ndn );

	if( p_dn != NULL ) free( p_dn );
	if( p_ndn != NULL ) free( p_ndn );

	/* LDAP v2 supporting correct attribute handling. */
	if( new_rdn_types != NULL ) charray_free( new_rdn_types );
	if( new_rdn_vals != NULL ) charray_free( new_rdn_vals );
	if( old_rdn != NULL ) free(old_rdn);
	if( old_rdn_types != NULL ) charray_free( old_rdn_types );
	if( old_rdn_vals != NULL ) charray_free( old_rdn_vals );

	if ( mod != NULL ) {
		slap_mods_free( mod );
	}

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
	if ( rc == MUST_DESTROY ) {
		/* if rc == MUST_DESTROY the entry is uncached 
		 * and its private data is destroyed; 
		 * the entry must be freed */
		entry_free( e );
	}
	return( rc );
}

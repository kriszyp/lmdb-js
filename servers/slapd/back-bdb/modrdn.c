/* modrdn.c - bdb backend modrdn routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

int
bdb_modrdn(
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
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	AttributeDescription *children = slap_schema.si_ad_children;
	char		*p_dn = NULL, *p_ndn = NULL;
	char		*new_dn = NULL, *new_ndn = NULL;
	int		isroot = -1;
	const static Entry roote = { NOID, "", "", NULL, NULL };
	Entry		*e, *p = NULL;
	Entry		*matched;
	int			rc;
	const char *text;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	DB_TXN *	ltid = NULL;
	struct bdb_op_info opinfo;

	ID			id;
	char		**new_rdn_vals = NULL;	/* Vals of new rdn */
	char		**new_rdn_types = NULL;	/* Types of new rdn */
	int		a_cnt, d_cnt;
	char		*old_rdn = NULL;	/* Old rdn's attr type & val */
	char		**old_rdn_types = NULL;	/* Types of old rdn attr. */
	char		**old_rdn_vals = NULL;	/* Old rdn attribute values */

	Entry		*np = NULL;				/* newSuperior Entry */
	char		*np_dn = NULL;			/* newSuperior dn */
	char		*np_ndn = NULL;			/* newSuperior ndn */
	char		*new_parent_dn = NULL;	/* np_dn, p_dn, or NULL */

	/* Used to interface with bdb_modify_internal() */
	Modifications	*mod = NULL;		/* Used to delete old rdn */

	int		manageDSAit = get_manageDSAit( op );

	Debug( LDAP_DEBUG_TRACE, "==>bdb_modrdn(%s,%s,%s)\n",
		dn, newrdn, (newSuperior ? newSuperior : "NULL") );

#if 0
	if( newSuperior != NULL ) {
		rc = LDAP_UNWILLING_TO_PERFORM;
		text = "newSuperior not implemented (yet)";
		goto return_results;
	}
#endif

	if (0) {
retry:	/* transaction retry */
		Debug( LDAP_DEBUG_TRACE, "==>bdb_modrdn: retrying...\n", 0, 0, 0 );
		rc = txn_abort( ltid );
		ltid = NULL;
		op->o_private = NULL;
		if( rc != 0 ) {
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}
	}


	/* begin transaction */
	rc = txn_begin( bdb->bi_dbenv, NULL, &ltid, 0 );
	text = NULL;
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	opinfo.boi_bdb = be;
	opinfo.boi_txn = ltid;
	opinfo.boi_err = 0;
	op->o_private = &opinfo;

	/* get entry */
	rc = bdb_dn2entry( be, ltid, ndn, &e, &matched, 0 );

	switch( rc ) {
	case 0:
	case DB_NOTFOUND:
		break;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	default:
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	if ( e == NULL ) {
		char* matched_dn = NULL;
		struct berval** refs;

		if( matched != NULL ) {
			matched_dn = strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched,
					dn, LDAP_SCOPE_DEFAULT )
				: NULL;
			bdb_entry_return( be, matched );
			matched = NULL;

		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		ber_bvecfree( refs );
		free( matched_dn );

		goto done;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e, dn, LDAP_SCOPE_DEFAULT );

		Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry %s is referral\n",
			e->e_dn, 0, 0 );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );
		goto done;
	}

	p_ndn = dn_parent( be, e->e_ndn );
	if ( p_ndn != NULL && p_ndn[ 0 ] != '\0' ) {
		/* Make sure parent entry exist and we can write its 
		 * children.
		 */

		rc = bdb_dn2entry( be, ltid, p_ndn, &p, NULL, 0 );

		switch( rc ) {
		case 0:
		case DB_NOTFOUND:
			break;
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		default:
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}

		if( p == NULL) {
			Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: parent does not exist\n",
				0, 0, 0);
			rc = LDAP_OTHER;
			goto return_results;
		}

		/* check parent for "children" acl */
		if ( ! access_allowed( be, conn, op, p,
			children, NULL, ACL_WRITE ) )
		{
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
				0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: wr to children of entry %s OK\n",
			p_ndn, 0, 0 );
		
		p_dn = dn_parent( be, e->e_dn );

		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: parent dn=%s\n",
			p_dn, 0, 0 );

	} else {
		/* no parent, modrdn entry directly under root */
		isroot =  be_isroot( be, op->o_ndn );
		if ( ! isroot ) {
			if ( be_issuffix( be, "" ) || be_isupdate( be, op->o_ndn ) ) {

				p = (Entry *)&roote;

				/* check parent for "children" acl */
				rc = access_allowed( be, conn, op, p,
					children, NULL, ACL_WRITE );

				p = NULL;

				if ( ! rc )
				{
					Debug( LDAP_DEBUG_TRACE, 
						"no access to parent\n", 
						0, 0, 0 );
					send_ldap_result( conn, op, 
						LDAP_INSUFFICIENT_ACCESS,
						NULL, NULL, NULL, NULL );
					goto return_results;
				}

				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: wr to children of entry \"\" OK\n",
					0, 0, 0 );
		
				p_dn = ch_strdup( "" );

				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: parent dn=\"\"\n",
					0, 0, 0 );

			} else {
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: no parent, not root "
					"& \"\" is not suffix\n",
					0, 0, 0);
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}
		}
	}

	new_parent_dn = p_dn;	/* New Parent unless newSuperior given */

	if ( newSuperior != NULL ) {
		Debug( LDAP_DEBUG_TRACE, 
			"bdb_modrdn: new parent \"%s\" requested...\n",
			newSuperior, 0, 0 );

		if ( newSuperior[ 0 ] != '\0' ) {
			np_dn = ch_strdup( newSuperior );
			np_ndn = ch_strdup( np_dn );
			(void) dn_normalize( np_ndn );

			/* newSuperior == oldParent?, if so ==> ERROR */
			/* newSuperior == entry being moved?, if so ==> ERROR */
			/* Get Entry with dn=newSuperior. Does newSuperior exist? */

			rc = bdb_dn2entry( be, ltid, np_ndn, &np, NULL, 0 );

			switch( rc ) {
			case 0:
			case DB_NOTFOUND:
				break;
			case DB_LOCK_DEADLOCK:
			case DB_LOCK_NOTGRANTED:
				goto retry;
			default:
				rc = LDAP_OTHER;
				text = "internal error";
				goto return_results;
			}

			if( np == NULL) {
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: newSup(ndn=%s) not here!\n",
					np_ndn, 0, 0);
				rc = LDAP_OTHER;
				goto return_results;
			}

			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: wr to new parent OK np=%p, id=%ld\n",
				np, (long) np->e_id, 0 );

			/* check newSuperior for "children" acl */
			if ( !access_allowed( be, conn, op, np, children, NULL, ACL_WRITE ) ) {
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: no wr to newSup children\n",
					0, 0, 0 );
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}

			if ( is_entry_alias( np ) ) {
				/* parent is an alias, don't allow add */
				Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry is alias\n",
					0, 0, 0 );

				rc = LDAP_ALIAS_PROBLEM;
				goto return_results;
			}

			if ( is_entry_referral( np ) ) {
				/* parent is a referral, don't allow add */
				Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry is referral\n",
					0, 0, 0 );

				rc = LDAP_OPERATIONS_ERROR;
				goto return_results;
			}

		} else {
			if ( isroot == -1 ) {
				isroot =  be_isroot( be, op->o_ndn );
			}
			
			np_dn = ch_strdup( "" );

			/* no parent, modrdn entry directly under root */
			if ( ! isroot ) {
				if ( be_issuffix( be, "" ) || be_isupdate( be, op->o_ndn ) ) {

					np = (Entry *)&roote;

					/* check parent for "children" acl */
					rc = access_allowed( be, conn, op, np,
						children, NULL, ACL_WRITE );

					np = NULL;

					if ( ! rc )
					{
						Debug( LDAP_DEBUG_TRACE, 
							"no access to new superior\n", 
							0, 0, 0 );
						send_ldap_result( conn, op, 
							LDAP_INSUFFICIENT_ACCESS,
							NULL, NULL, NULL, NULL );
						goto return_results;
					}

					Debug( LDAP_DEBUG_TRACE,
						"bdb_modrdn: wr to children of entry \"\" OK\n",
						0, 0, 0 );
		
				} else {
					Debug( LDAP_DEBUG_TRACE,
						"bdb_modrdn: new superior=\"\", not root "
						"& \"\" is not suffix\n",
						0, 0, 0);
					rc = LDAP_INSUFFICIENT_ACCESS;
					goto return_results;
				}
			}

			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: new superior=\"\"\n",
				0, 0, 0 );
		}

		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: wr to new parent's children OK\n",
			0, 0, 0 );

		new_parent_dn = np_dn;
	}
	
	/* Build target dn and make sure target entry doesn't exist already. */
	build_new_dn( &new_dn, e->e_dn, new_parent_dn, newrdn ); 

	new_ndn = ch_strdup(new_dn);
	(void) dn_normalize( new_ndn );

	Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: new ndn=%s\n",
		new_ndn, 0, 0 );

	rc = bdb_dn2id ( be, ltid, new_ndn, &id );
	switch( rc ) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	case DB_NOTFOUND:
		break;
	case 0:
		rc = LDAP_ALREADY_EXISTS;
		goto return_results;
	default:
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	Debug( LDAP_DEBUG_TRACE,
		"bdb_modrdn: new ndn=%s does not exist\n",
		new_ndn, 0, 0 );

	/* Get attribute type and attribute value of our new rdn, we will
	 * need to add that to our new entry
	 */

	if ( rdn_attrs( newrdn, &new_rdn_types, &new_rdn_vals ) ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: can't figure out type(s)/values(s) "
			"of newrdn\n", 0, 0, 0 );
		rc = LDAP_OPERATIONS_ERROR;
		text = "unknown type(s) used in RDN";
		goto return_results;		
	}

	Debug( LDAP_DEBUG_TRACE,
		"bdb_modrdn: new_rdn_val=\"%s\", new_rdn_type=\"%s\"\n",
		new_rdn_vals[ 0 ], new_rdn_types[ 0 ], 0 );

	/* Retrieve the old rdn from the entry's dn */
	if ( ( old_rdn = dn_rdn( be, dn ) ) == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: can't figure out old_rdn from dn\n",
			0, 0, 0 );
		rc = LDAP_OTHER;
		text = "could not parse old DN";
		goto return_results;		
	}

	if ( rdn_attrs( old_rdn, &old_rdn_types, &old_rdn_vals ) ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_back_modrdn: can't figure out the old_rdn "
			"type(s)/value(s)\n", 0, 0, 0 );
		rc = LDAP_OTHER;
		text = "cannot parse RDN from old DN";
		goto return_results;		
	}
	
	if ( newSuperior == NULL
		&& charray_strcasecmp( ( const char ** )old_rdn_types, 
				( const char ** )new_rdn_types ) != 0 ) {
		/* Not a big deal but we may say something */
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: old_rdn_type(s)=%s, new_rdn_type(s)=%s "
			"do not match\n", 
			old_rdn_types[ 0 ], new_rdn_types[ 0 ], 0 );
	}		

	/* Add new attribute values to the entry */
	for ( a_cnt = 0; new_rdn_types[ a_cnt ]; a_cnt++ ) {
		int 			rc;
		AttributeDescription	*desc = NULL;
		Modifications 		*mod_tmp;
		struct berval 		val;

		rc = slap_str2ad( new_rdn_types[ a_cnt ], &desc, &text );

		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: %s: %s (new)\n",
				text, new_rdn_types[ a_cnt ], 0 );
			goto return_results;		
		}

		/* ACL check of newly added attrs */
		val.bv_val = new_rdn_vals[ a_cnt ];
		val.bv_len = strlen( val.bv_val );
		if ( !access_allowed( be, conn, op, e, 
				desc, &val, ACL_WRITE ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: access to attr \"%s\" "
				"(new) not allowed\n", 
				new_rdn_types[ a_cnt ], 0, 0 );
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		/* Apply modification */
		mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications ) );
		mod_tmp->sml_desc = desc;
		mod_tmp->sml_bvalues = ( struct berval ** )ch_malloc( 2*sizeof( struct berval * ) );
		mod_tmp->sml_bvalues[ 0 ] = ber_bvstrdup( new_rdn_vals[ a_cnt ] );
		mod_tmp->sml_bvalues[ 1 ] = NULL;
		mod_tmp->sml_op = SLAP_MOD_SOFTADD;
		mod_tmp->sml_next = mod;
		mod = mod_tmp;
	}

	/* Remove old rdn value if required */
	if ( deleteoldrdn ) {
		/* Get value of old rdn */
		if ( old_rdn_vals == NULL) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: can't figure out old RDN value(s) "
				"from old RDN\n", 0, 0, 0 );
			rc = LDAP_OTHER;
			text = "could not parse value(s) from old RDN";
			goto return_results;		
		}

		for ( d_cnt = 0; old_rdn_types[ d_cnt ]; d_cnt++ ) {
			int 			rc;
			AttributeDescription	*desc = NULL;
			Modifications 		*mod_tmp;
			struct berval 		val;

			rc = slap_str2ad( old_rdn_types[ d_cnt ],
					&desc, &text );

			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: %s: %s (old)\n",
					text, old_rdn_types[ d_cnt ], 0 );
				goto return_results;		
			}

			/* ACL check of newly added attrs */
			val.bv_val = new_rdn_vals[ d_cnt ];
			val.bv_len = strlen( val.bv_val );
			if ( !access_allowed( be, conn, op, e, 
					desc, &val, ACL_WRITE ) ) {
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: access to attr \"%s\" "
					"(old) not allowed\n", 
					old_rdn_types[ d_cnt ], 0, 0 );
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}

			/* Apply modification */
			mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications ) );
			mod_tmp->sml_desc = desc;
			mod_tmp->sml_bvalues = ( struct berval ** )ch_malloc( 2*sizeof( struct berval * ) );
			mod_tmp->sml_bvalues[ 0 ] = ber_bvstrdup( old_rdn_vals[ d_cnt ] );
			mod_tmp->sml_bvalues[ 1 ] = NULL;
			mod_tmp->sml_op = LDAP_MOD_DELETE;
			mod_tmp->sml_next = mod;
			mod = mod_tmp;
		}
	}
	
	/* delete old one */
	rc = bdb_dn2id_delete( be, ltid, e->e_ndn, e->e_id );
	if ( rc != 0 ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		rc = LDAP_OTHER;
		text = "DN index delete fail";
		goto return_results;
	}

	/* Binary format uses a single contiguous block, cannot
	 * free individual fields. Leave new_dn/new_ndn set so
	 * they can be individually freed later.
	 */
	e->e_dn = new_dn;
	e->e_ndn = new_ndn;

	/* add new one */
	rc = bdb_dn2id_add( be, ltid, e->e_ndn, e->e_id );
	if ( rc != 0 ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		rc = LDAP_OTHER;
		text = "DN index add failed";
		goto return_results;
	}

	/* modify entry */
	rc = bdb_modify_internal( be, conn, op, ltid, &mod[0], e,
		&text, textbuf, textlen );

	if( rc != LDAP_SUCCESS ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		goto return_results;
	}
	
	/* id2entry index */
	rc = bdb_id2entry_update( be, ltid, e );
	if ( rc != 0 ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		rc = LDAP_OTHER;
		text = "entry update failed";
		goto return_results;
	}

	rc = txn_commit( ltid, 0 );
	ltid = NULL;
	op->o_private = NULL;

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: txn_commit failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		rc = LDAP_OTHER;
		text = "commit failed";
	} else {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: added id=%08lx dn=\"%s\"\n",
			e->e_id, e->e_dn, 0 );
		rc = LDAP_SUCCESS;
		text = NULL;
	}

return_results:
	send_ldap_result( conn, op, rc,
		NULL, text, NULL, NULL );

	if(rc == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		txn_checkpoint( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

done:
	if( new_dn != NULL ) free( new_dn );
	if( new_ndn != NULL ) free( new_ndn );

	if( p_dn != NULL ) free( p_dn );
	if( p_ndn != NULL ) free( p_ndn );

	/* LDAP v2 supporting correct attribute handling. */
	if( new_rdn_types != NULL ) charray_free(new_rdn_types);
	if( new_rdn_vals != NULL ) charray_free(new_rdn_vals);
	if( old_rdn != NULL ) free(old_rdn);
	if( old_rdn_types != NULL ) charray_free(old_rdn_types);
	if( old_rdn_vals != NULL ) charray_free(old_rdn_vals);
	if( mod != NULL ) slap_mods_free(mod);

	/* LDAP v3 Support */
	if ( np_dn != NULL ) free( np_dn );
	if ( np_ndn != NULL ) free( np_ndn );

	if( np != NULL ) {
		/* free new parent and writer lock */
		bdb_entry_return( be, np );
	}

	if( p != NULL ) {
		/* free parent and writer lock */
		bdb_entry_return( be, p );
	}

	/* free entry */
	if( e != NULL ) {
		bdb_entry_return( be, e );
	}

	if( ltid != NULL ) {
		txn_abort( ltid );
		op->o_private = NULL;
	}

	return rc;
}

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
    struct berval	*dn,
    struct berval	*ndn,
    struct berval	*newrdn,
    struct berval	*nnewrdn,
    int		deleteoldrdn,
    struct berval	*newSuperior,
    struct berval	*nnewSuperior
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	AttributeDescription *children = slap_schema.si_ad_children;
	struct berval	p_dn, p_ndn;
	struct berval	new_dn = {0, NULL}, new_ndn = {0, NULL};
	int		isroot = -1;
	Entry		*e, *p = NULL;
	Entry		*matched;
	int			rc;
	const char *text;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	DB_TXN *	ltid = NULL;
	struct bdb_op_info opinfo;

	ID			id;
	int		a_cnt, d_cnt;
	LDAPRDN		*new_rdn = NULL;
	LDAPRDN		*old_rdn = NULL;

	Entry		*np = NULL;				/* newSuperior Entry */
	struct berval	*np_dn = NULL;			/* newSuperior dn */
	struct berval	*np_ndn = NULL;			/* newSuperior ndn */
	struct berval	*new_parent_dn = NULL;	/* np_dn, p_dn, or NULL */

	/* Used to interface with bdb_modify_internal() */
	Modifications	*mod = NULL;		/* Used to delete old rdn */

	int		manageDSAit = get_manageDSAit( op );

	Debug( LDAP_DEBUG_TRACE, "==>bdb_modrdn(%s,%s,%s)\n",
		dn->bv_val, newrdn->bv_val,
		newSuperior ? newSuperior->bv_val : "NULL" );

#if 0
	if( newSuperior != NULL ) {
		rc = LDAP_UNWILLING_TO_PERFORM;
		text = "newSuperior not implemented (yet)";
		goto return_results;
	}
#endif

	if( 0 ) {
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

	if( bdb->bi_txn ) {
		/* begin transaction */
		rc = txn_begin( bdb->bi_dbenv, NULL, &ltid, 
			bdb->bi_db_opflags );
		text = NULL;
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_delete: txn_begin failed: %s (%d)\n",
				db_strerror(rc), rc, 0 );
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}
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
				? get_entry_referrals( be, conn, op, matched )
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
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry %s is referral\n",
			e->e_dn, 0, 0 );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );
		goto done;
	}

	p_ndn.bv_val = dn_parent( be, e->e_ndn );
	if (p_ndn.bv_val)
		p_ndn.bv_len = e->e_nname.bv_len - (p_ndn.bv_val - e->e_ndn);
	else
		p_ndn.bv_len = 0;
	np_ndn = &p_ndn;
	if ( p_ndn.bv_len != 0 ) {
		/* Make sure parent entry exist and we can write its 
		 * children.
		 */
		rc = bdb_dn2entry( be, ltid, &p_ndn, &p, NULL, 0 );

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
			p_ndn.bv_val, 0, 0 );
		
		p_dn.bv_val = dn_parent( be, e->e_dn );
		if (p_dn.bv_val)
			p_dn.bv_len = e->e_name.bv_len - (p_dn.bv_val - e->e_dn);
		else
			p_dn.bv_len = 0;

		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: parent dn=%s\n",
			p_dn.bv_val, 0, 0 );

	} else {
		/* no parent, modrdn entry directly under root */
		isroot = be_isroot( be, &op->o_ndn );
		if ( ! isroot ) {
			if ( be_issuffix( be, "" ) || be_isupdate( be, &op->o_ndn ) ) {

				p = (Entry *)&slap_entry_root;

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
		
				p_dn.bv_val = "";
				p_dn.bv_len = 0;

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

	new_parent_dn = &p_dn;	/* New Parent unless newSuperior given */

	if ( newSuperior != NULL ) {
		Debug( LDAP_DEBUG_TRACE, 
			"bdb_modrdn: new parent \"%s\" requested...\n",
			newSuperior->bv_val, 0, 0 );

		if ( newSuperior->bv_len ) {
			np_dn = newSuperior;
			np_ndn = nnewSuperior;

			/* newSuperior == oldParent?, if so ==> ERROR */
			/* newSuperior == entry being moved?, if so ==> ERROR */
			/* Get Entry with dn=newSuperior. Does newSuperior exist? */

			rc = bdb_dn2entry( be, ltid, nnewSuperior, &np, NULL, 0 );

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
					np_ndn->bv_val, 0, 0);
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
				isroot = be_isroot( be, &op->o_ndn );
			}
			
			np_dn = NULL;

			/* no parent, modrdn entry directly under root */
			if ( ! isroot ) {
				if ( be_issuffix( be, "" ) || be_isupdate( be, &op->o_ndn ) ) {
					np = (Entry *)&slap_entry_root;

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
	build_new_dn( &new_dn, new_parent_dn, newrdn ); 

	dnNormalize2( NULL, &new_dn, &new_ndn );

	Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: new ndn=%s\n",
		new_ndn.bv_val, 0, 0 );

	rc = bdb_dn2id ( be, ltid, &new_ndn, &id );
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
		new_ndn.bv_val, 0, 0 );

	/* Get attribute type and attribute value of our new rdn, we will
	 * need to add that to our new entry
	 */
	if ( ldap_str2rdn( newrdn->bv_val, &new_rdn, &text, LDAP_DN_FORMAT_LDAP ) ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: can't figure out type(s)/values(s) "
			"of newrdn\n", 0, 0, 0 );
		rc = LDAP_OPERATIONS_ERROR;
		text = "unknown type(s) used in RDN";
		goto return_results;		
	}

	Debug( LDAP_DEBUG_TRACE,
		"bdb_modrdn: new_rdn_type=\"%s\", new_rdn_val=\"%s\"\n",
		new_rdn[0][0]->la_attr.bv_val, new_rdn[0][0]->la_value.bv_val, 0 );

	if ( ldap_str2rdn( dn->bv_val, &old_rdn, &text, LDAP_DN_FORMAT_LDAP ) ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_back_modrdn: can't figure out the old_rdn "
			"type(s)/value(s)\n", 0, 0, 0 );
		rc = LDAP_OTHER;
		text = "cannot parse RDN from old DN";
		goto return_results;		
	}

#if 0
	if ( newSuperior == NULL
		&& charray_strcasecmp( ( const char ** )old_rdn_types, 
				( const char ** )new_rdn_types ) != 0 ) {
		/* Not a big deal but we may say something */
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: old_rdn_type(s)=%s, new_rdn_type(s)=%s "
			"do not match\n", 
			old_rdn_types[ 0 ], new_rdn_types[ 0 ], 0 );
	}		
#endif

	/* Add new attribute values to the entry */
	for ( a_cnt = 0; new_rdn[0][ a_cnt ]; a_cnt++ ) {
		int 			rc;
		AttributeDescription	*desc = NULL;
		Modifications 		*mod_tmp;

		rc = slap_bv2ad( &new_rdn[0][ a_cnt ]->la_attr, &desc, &text );

		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: %s: %s (new)\n",
				text, new_rdn[0][ a_cnt ]->la_attr.bv_val, 0 );
			goto return_results;		
		}

		/* ACL check of newly added attrs */
		if ( !access_allowed( be, conn, op, e, desc,
			&new_rdn[0][ a_cnt ]->la_value, ACL_WRITE ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: access to attr \"%s\" "
				"(new) not allowed\n", 
				new_rdn[0][ a_cnt ]->la_attr.bv_val, 0, 0 );
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		/* Apply modification */
		mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications )
			+ 2 * sizeof( struct berval * ) );
		mod_tmp->sml_desc = desc;
		mod_tmp->sml_bvalues = ( struct berval ** )( mod_tmp + 1 );
		mod_tmp->sml_bvalues[ 0 ] = &new_rdn[0][ a_cnt ]->la_value;
		mod_tmp->sml_bvalues[ 1 ] = NULL;
		mod_tmp->sml_op = SLAP_MOD_SOFTADD;
		mod_tmp->sml_next = mod;
		mod = mod_tmp;
	}

	/* Remove old rdn value if required */
	if ( deleteoldrdn ) {
		/* Get value of old rdn */
		if ( old_rdn == NULL) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: can't figure out old RDN value(s) "
				"from old RDN\n", 0, 0, 0 );
			rc = LDAP_OTHER;
			text = "could not parse value(s) from old RDN";
			goto return_results;		
		}

		for ( d_cnt = 0; old_rdn[0][ d_cnt ]; d_cnt++ ) {
			int 			rc;
			AttributeDescription	*desc = NULL;
			Modifications 		*mod_tmp;

			rc = slap_bv2ad( &old_rdn[0][ d_cnt ]->la_attr,
					&desc, &text );

			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: %s: %s (old)\n",
					text, old_rdn[0][ d_cnt ]->la_attr.bv_val, 0 );
				goto return_results;		
			}

			/* ACL check of newly added attrs */
			if ( !access_allowed( be, conn, op, e, desc,
				&old_rdn[0][d_cnt]->la_value, ACL_WRITE ) ) {
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: access to attr \"%s\" "
					"(old) not allowed\n", 
					old_rdn[0][ d_cnt ]->la_attr.bv_val, 0, 0 );
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}

			/* Apply modification */
			mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications )
				+ 2 * sizeof ( struct berval * ) );
			mod_tmp->sml_desc = desc;
			mod_tmp->sml_bvalues = ( struct berval ** )(mod_tmp+1);
			mod_tmp->sml_bvalues[ 0 ] = &old_rdn[0][ d_cnt ]->la_value;
			mod_tmp->sml_bvalues[ 1 ] = NULL;
			mod_tmp->sml_op = LDAP_MOD_DELETE;
			mod_tmp->sml_next = mod;
			mod = mod_tmp;
		}
	}
	
	/* delete old one */
	rc = bdb_dn2id_delete( be, ltid, p_ndn.bv_val, e );
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
	e->e_name = new_dn;
	e->e_nname = new_ndn;

	/* add new one */
	rc = bdb_dn2id_add( be, ltid, np_ndn, e );
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

	if( bdb->bi_txn ) {
		rc = txn_commit( ltid, 0 );
	}
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

	if( rc == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		TXN_CHECKPOINT( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

done:
	if( new_dn.bv_val != NULL ) free( new_dn.bv_val );
	if( new_ndn.bv_val != NULL ) free( new_ndn.bv_val );

	/* LDAP v2 supporting correct attribute handling. */
	if( new_rdn != NULL ) ldap_rdnfree( new_rdn );
	if( old_rdn != NULL ) ldap_rdnfree( old_rdn );
	if( mod != NULL ) {
		Modifications *tmp;
		for (; mod; mod=tmp ) {
			tmp = mod->sml_next;
			free( mod );
		}
	}

	/* LDAP v3 Support */
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

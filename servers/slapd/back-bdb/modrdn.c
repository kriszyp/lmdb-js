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
	Entry		*e, *p = NULL;
	Entry		*matched;
	int			rc;
	const char *text = NULL;
	DB_TXN *	ltid;
	struct bdb_op_info opinfo;

	ID			id;
	char		*new_rdn_val = NULL;	/* Val of new rdn */
	char		*new_rdn_type = NULL;	/* Type of new rdn */
	char		*old_rdn = NULL;		/* Old rdn's attr type & val */
	char		*old_rdn_type = NULL;	/* Type of old rdn attr. */
	char		*old_rdn_val = NULL;	/* Old rdn attribute value */

	Entry		*np = NULL;				/* newSuperior Entry */
	char		*np_dn = NULL;			/* newSuperior dn */
	char		*np_ndn = NULL;			/* newSuperior ndn */
	char		*new_parent_dn = NULL;	/* np_dn, p_dn, or NULL */

	/* Used to interface with bdb_modify_internal() */
	struct berval	add_bv;				/* Stores new rdn att */
	struct berval	*add_bvals[2];		/* Stores new rdn att */
	struct berval	del_bv;				/* Stores old rdn att */
	struct berval	*del_bvals[2];		/* Stores old rdn att */
	Modifications	mod[2];				/* Used to delete old rdn */

	int		manageDSAit = get_manageDSAit( op );

	Debug( LDAP_DEBUG_TRACE, "==>bdb_modrdn(%s,%s,%s)\n",
		dn, newrdn, (newSuperior ? newSuperior : "NULL") );

	if (0) {
		/* transaction retry */
retry:	rc = txn_abort( ltid );
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
		struct berval** refs = NULL;

		if( matched != NULL ) {
			matched_dn = strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb_entry_return( be, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		goto done;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry is referral\n",
			0, 0, 0 );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );
		goto done;
	}

	p_ndn = dn_parent( be, e->e_ndn );
	if ( p_ndn != NULL ) {
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
		if( ! be_isroot( be, op->o_ndn ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: no parent & not root\n",
				0, 0, 0);
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: no parent, locked root\n",
			0, 0, 0 );
	}

	new_parent_dn = p_dn;	/* New Parent unless newSuperior given */

	if ( newSuperior != NULL ) {
		Debug( LDAP_DEBUG_TRACE, 
			"bdb_modrdn: new parent \"%s\" requested...\n",
			newSuperior, 0, 0 );

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
			np, np->e_id, 0 );

		/* check newSuperior for "children" acl */
		if ( !access_allowed( be, conn, op, np, children, NULL, ACL_WRITE ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: no wr to newSup children\n",
				0, 0, 0 );
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		if ( is_entry_alias( np ) ) {
			/* entry is an alias, don't allow bind */
			Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry is alias\n",
				0, 0, 0 );

			rc = LDAP_ALIAS_PROBLEM;
			goto return_results;
		}

		if ( is_entry_referral( np ) ) {
			/* parent is a referral, don't allow add */
			/* parent is an alias, don't allow add */
			Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry is referral\n",
				0, 0, 0 );

			rc = LDAP_OPERATIONS_ERROR;
			goto return_results;
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
	if( rc != 0 ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		default:
			rc = LDAP_OTHER;
			text = "internal error";
		}

		goto return_results;
	}

	Debug( LDAP_DEBUG_TRACE,
		"bdb_modrdn: new ndn=%s does not exist\n",
		new_ndn, 0, 0 );

	/* Get attribute type and attribute value of our new rdn, we will
	 * need to add that to our new entry
	 */

	new_rdn_type = rdn_attr_type( newrdn );
	if ( new_rdn_type == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: can't figure out type of newrdn\n",
			0, 0, 0 );
		rc = LDAP_OPERATIONS_ERROR;
		text = "unknown type used in RDN";
		goto return_results;		
	}

	new_rdn_val = rdn_attr_value( newrdn );
	if ( new_rdn_val == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: could not figure out val of newrdn\n",
			0, 0, 0 );
		rc = LDAP_OPERATIONS_ERROR;
		text = "could not parse RDN value";
		goto return_results;		
	}

	Debug( LDAP_DEBUG_TRACE,
		"bdb_modrdn: new_rdn_val=\"%s\", new_rdn_type=\"%s\"\n",
		new_rdn_val, new_rdn_type, 0 );

	/* Retrieve the old rdn from the entry's dn */

	if ( (old_rdn = dn_rdn( be, dn )) == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: can't figure out old_rdn from dn\n",
			0, 0, 0 );
		rc = LDAP_OTHER;
		text = "could not parse old DN";
		goto return_results;		
	}

	if ( (old_rdn_type = rdn_attr_type( old_rdn )) == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_back_modrdn: can't figure out the old_rdn type\n",
			0, 0, 0 );
		rc = LDAP_OTHER;
		text = "cannot parse RDN from old DN";
		goto return_results;		
	}
	
	if ( strcasecmp( old_rdn_type, new_rdn_type ) != 0 ) {
		/* Not a big deal but we may say something */
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: old_rdn_type=%s, new_rdn_type=%s!\n",
			old_rdn_type, new_rdn_type, 0 );
	}		

	/* Add new attribute value to the entry */
	add_bvals[0] = &add_bv;		/* Array of bervals */
	add_bvals[1] = NULL;

	add_bv.bv_val = new_rdn_val;
	add_bv.bv_len = strlen(new_rdn_val);
		
	mod[0].sml_desc = NULL;
	rc = slap_str2ad( new_rdn_type, &mod[0].sml_desc, &text );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: %s: %s (new)\n",
			text, new_rdn_type, 0 );
		goto return_results;		
	}
	mod[0].sml_bvalues = add_bvals;
	mod[0].sml_op = SLAP_MOD_SOFTADD;
	mod[0].sml_next = NULL;

	/* Remove old rdn value if required */

	if (deleteoldrdn) {
		/* Get value of old rdn */
		old_rdn_val = rdn_attr_value( old_rdn );
		if ( old_rdn_val == NULL) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: can't figure out old_rdn_val from old_rdn\n",
				0, 0, 0 );
			rc = LDAP_OTHER;
			text = "could not parse value from old RDN";
			goto return_results;		
		}

		del_bvals[0] = &del_bv;		/* Array of bervals */
		del_bvals[1] = NULL;

		/* Remove old value of rdn as an attribute. */
		del_bv.bv_val = old_rdn_val;
		del_bv.bv_len = strlen(old_rdn_val);

		mod[1].sml_desc = NULL;
		rc = slap_str2ad( old_rdn_type, &mod[1].sml_desc, &text );

		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: %s: %s (old)\n",
				text, old_rdn_type, 0 );
			goto return_results;		
		}

		mod[0].sml_next = &mod[1];
		mod[1].sml_bvalues = del_bvals;
		mod[1].sml_op = LDAP_MOD_DELETE;
		mod[1].sml_next = NULL;
	}
	
	/* delete old one */
	rc = bdb_dn2id_delete( be, ltid, e->e_ndn, e->e_id );
	if ( rc != 0 ) {
		rc = LDAP_OTHER;
		text = "DN index delete fail";
		goto return_results;
	}

	free( e->e_dn );
	free( e->e_ndn );
	e->e_dn = new_dn;
	e->e_ndn = new_ndn;
	new_dn = NULL;
	new_ndn = NULL;

	/* add new one */
	rc = bdb_dn2id_add( be, ltid, e->e_ndn, e->e_id );
	if ( rc != 0 ) {
		rc = LDAP_OTHER;
		text = "DN index add failed";
		goto return_results;
	}

	/* modify entry */
	rc = bdb_modify_internal( be, conn, op, ltid, &mod[0], e, &text );

	if( rc != LDAP_SUCCESS ) {
		goto return_results;
	}
	
	/* NOTE: after this you must not free new_dn or new_ndn!
	 * They are used by cache.
	 */

	/* id2entry index */
	rc = bdb_id2entry_add( be, ltid, e );
	if ( rc != 0 ) {
		rc = LDAP_OTHER;
		text = "entry update failed";
		goto return_results;
	}

	rc = LDAP_SUCCESS;

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
			"bdb_modrdn: added id=%08x dn=\"%s\"\n",
			e->e_id, e->e_dn, 0 );
		rc = LDAP_SUCCESS;
		text = NULL;
	}

return_results:
	send_ldap_result( conn, op, rc,
		NULL, text, NULL, NULL );

done:
	if( new_dn != NULL ) free( new_dn );
	if( new_ndn != NULL ) free( new_ndn );

	if( p_dn != NULL ) free( p_dn );
	if( p_ndn != NULL ) free( p_ndn );

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

/* modrdn.c - bdb backend modrdn routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
	struct berval	*nnewSuperior )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	struct berval	p_dn, p_ndn;
	struct berval	new_dn = {0, NULL}, new_ndn = {0, NULL};
	int		isroot = -1;
	Entry		*e = NULL;
	Entry		*p = NULL;
	Entry		*matched;
	/* LDAP v2 supporting correct attribute handling. */
	LDAPRDN		*new_rdn = NULL;
	LDAPRDN		*old_rdn = NULL;
	int		rc;
	const char *text;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	DB_TXN *	ltid = NULL;
	struct bdb_op_info opinfo;

	ID			id;

	Entry		*np = NULL;			/* newSuperior Entry */
	struct berval	*np_dn = NULL;			/* newSuperior dn */
	struct berval	*np_ndn = NULL;			/* newSuperior ndn */
	struct berval	*new_parent_dn = NULL;	/* np_dn, p_dn, or NULL */

	/* Used to interface with bdb_modify_internal() */
	Modifications	*mod = NULL;		/* Used to delete old rdn */

	int		manageDSAit = get_manageDSAit( op );

	u_int32_t	locker;
	DB_LOCK		lock;

	int		noop = 0;

#ifdef LDAP_CLIENT_UPDATE
        Operation* ps_list;
        struct psid_entry* pm_list;
        struct psid_entry* pm_prev;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "==>bdb_modrdn(%s,%s,%s)\n", 
		dn->bv_val,newrdn->bv_val, newSuperior ? newSuperior->bv_val : "NULL" );
#else
	Debug( LDAP_DEBUG_TRACE, "==>bdb_modrdn(%s,%s,%s)\n",
		dn->bv_val, newrdn->bv_val,
		newSuperior ? newSuperior->bv_val : "NULL" );
#endif

	if( 0 ) {
retry:	/* transaction retry */
		if (e != NULL) {
			bdb_cache_delete_entry(&bdb->bi_cache, e);
			bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
		}
		if (p != NULL) {
			bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, p);
		}
		if (np != NULL) {
			bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, np);
		}
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, "==>bdb_modrdn: retrying...\n", 0, 0, 0);
#else
		Debug( LDAP_DEBUG_TRACE, "==>bdb_modrdn: retrying...\n", 0, 0, 0 );
#endif

#ifdef LDAP_CLIENT_UPDATE
                pm_list = LDAP_LIST_FIRST(&op->premodify_list);
                while ( pm_list != NULL ) {
                        LDAP_LIST_REMOVE ( pm_list, link );
                        pm_prev = pm_list;
                        pm_list = LDAP_LIST_NEXT ( pm_list, link );
                        free (pm_prev);
                }
#endif

		rc = TXN_ABORT( ltid );
		ltid = NULL;
		op->o_private = NULL;
		if( rc != 0 ) {
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}
		ldap_pvt_thread_yield();
	}

	/* begin transaction */
	rc = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, 
		bdb->bi_db_opflags );
	text = NULL;
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"==>bdb_modrdn: txn_begin failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#endif
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	locker = TXN_ID ( ltid );

	opinfo.boi_bdb = be;
	opinfo.boi_txn = ltid;
	opinfo.boi_err = 0;
	op->o_private = &opinfo;

	/* get entry */
	rc = bdb_dn2entry_w( be, ltid, ndn, &e, &matched, DB_RMW, locker, &lock );

	switch( rc ) {
	case 0:
	case DB_NOTFOUND:
		break;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	case LDAP_BUSY:
		text = "ldap server busy";
		goto return_results;
	default:
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	if ( e == NULL ) {
		char* matched_dn = NULL;
		BerVarray refs;

		if( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb_unlocked_cache_return_entry_r( &bdb->bi_cache, matched);
			matched = NULL;

		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		ber_bvarray_free( refs );
		free( matched_dn );

		goto done;
	}

	/* check write on old entry */
	rc = access_allowed( be, conn, op, e, entry, NULL, ACL_WRITE, NULL );

	switch( opinfo.boi_err ) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	}

	if ( ! rc ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"==>bdb_modrdn: no access to entry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "no access to entry\n", 0,
			0, 0 );
#endif
		text = "no write access to old entry";
		rc = LDAP_INSUFFICIENT_ACCESS;
		goto return_results;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		BerVarray refs = get_entry_referrals( be,
			conn, op, e );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"==>bdb_modrdn: entry %s is referral \n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry %s is referral\n",
			e->e_dn, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvarray_free( refs );
		goto done;
	}

	if ( be_issuffix( be, &e->e_nname ) ) {
		p_ndn = slap_empty_bv;
	} else {
		dnParent( &e->e_nname, &p_ndn );
	}
	np_ndn = &p_ndn;
	if ( p_ndn.bv_len != 0 ) {
		/* Make sure parent entry exist and we can write its 
		 * children.
		 */
		rc = bdb_dn2entry_r( be, ltid, &p_ndn, &p, NULL, 0, locker, &lock );

		switch( rc ) {
		case 0:
		case DB_NOTFOUND:
			break;
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case LDAP_BUSY:
			text = "ldap server busy";
			goto return_results;
		default:
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}

		if( p == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"==>bdb_modrdn: parent does not exist\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: parent does not exist\n",
				0, 0, 0);
#endif
			rc = LDAP_OTHER;
			text = "old entry's parent does not exist";
			goto return_results;
		}

		/* check parent for "children" acl */
		rc = access_allowed( be, conn, op, p,
			children, NULL, ACL_WRITE, NULL );

		if ( ! rc ) {
			rc = LDAP_INSUFFICIENT_ACCESS;
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"==>bdb_modrdn: no access to parent\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
				0, 0 );
#endif
			text = "no write access to old parent's children";
			goto return_results;
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"==>bdb_modrdn: wr to children %s is OK\n", p_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: wr to children of entry %s OK\n",
			p_ndn.bv_val, 0, 0 );
#endif
		
		if ( p_ndn.bv_val == slap_empty_bv.bv_val ) {
			p_dn = slap_empty_bv;
		} else {
			dnParent( &e->e_name, &p_dn );
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"==>bdb_modrdn: parent dn=%s\n", p_dn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: parent dn=%s\n",
			p_dn.bv_val, 0, 0 );
#endif

	} else {
		/* no parent, modrdn entry directly under root */
		isroot = be_isroot( be, &op->o_ndn );
		if ( ! isroot ) {
			if ( be_issuffix( be, (struct berval *)&slap_empty_bv )
				|| be_isupdate( be, &op->o_ndn ) ) {

				p = (Entry *)&slap_entry_root;

				/* check parent for "children" acl */
				rc = access_allowed( be, conn, op, p,
					children, NULL, ACL_WRITE, NULL );

				p = NULL;

				if ( ! rc ) {
					rc = LDAP_INSUFFICIENT_ACCESS;
#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, ERR, 
						"==>bdb_modrdn: no access to parent\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE, 
						"no access to parent\n", 
						0, 0, 0 );
#endif
					text = "no write access to old parent";
					goto return_results;
				}

#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"==>bdb_modrdn: wr to children of entry \"%s\" OK\n", 
					p_dn.bv_val, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: wr to children of entry \"\" OK\n",
					0, 0, 0 );
#endif
		
				p_dn.bv_val = "";
				p_dn.bv_len = 0;

#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"==>bdb_modrdn: parent dn=\"\" \n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: parent dn=\"\"\n",
					0, 0, 0 );
#endif

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"==>bdb_modrdn: no parent, not root &\"\" is not "
					"suffix\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: no parent, not root "
					"& \"\" is not suffix\n",
					0, 0, 0);
#endif
				text = "no write access to old parent";
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}
		}
	}

	new_parent_dn = &p_dn;	/* New Parent unless newSuperior given */

	if ( newSuperior != NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"==>bdb_modrdn: new parent \"%s\" requested...\n", 
			newSuperior->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, 
			"bdb_modrdn: new parent \"%s\" requested...\n",
			newSuperior->bv_val, 0, 0 );
#endif

		/*  newSuperior == oldParent? */
		if( dn_match( &p_ndn, nnewSuperior ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, "bdb_back_modrdn: "
				"new parent \"%s\" same as the old parent \"%s\"\n",
				newSuperior->bv_val, p_dn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "bdb_back_modrdn: "
				"new parent \"%s\" same as the old parent \"%s\"\n",
				newSuperior->bv_val, p_dn.bv_val, 0 );
#endif      
			newSuperior = NULL; /* ignore newSuperior */
		}
	}

	if ( newSuperior != NULL ) {
		if ( newSuperior->bv_len ) {
			np_dn = newSuperior;
			np_ndn = nnewSuperior;

			/* newSuperior == oldParent?, if so ==> ERROR */
			/* newSuperior == entry being moved?, if so ==> ERROR */
			/* Get Entry with dn=newSuperior. Does newSuperior exist? */

			rc = bdb_dn2entry_r( be,
				ltid, nnewSuperior, &np, NULL, 0, locker, &lock );

			switch( rc ) {
			case 0:
			case DB_NOTFOUND:
				break;
			case DB_LOCK_DEADLOCK:
			case DB_LOCK_NOTGRANTED:
				goto retry;
			case LDAP_BUSY:
				text = "ldap server busy";
				goto return_results;
			default:
				rc = LDAP_OTHER;
				text = "internal error";
				goto return_results;
			}

			if( np == NULL) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"==>bdb_modrdn: newSup(ndn=%s) not here!\n", 
					np_ndn->bv_val, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: newSup(ndn=%s) not here!\n",
					np_ndn->bv_val, 0, 0);
#endif
				text = "new superior not found";
				rc = LDAP_OTHER;
				goto return_results;
			}

#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"==>bdb_modrdn: wr to new parent OK np=%p, id=%ld\n", 
				np, (long) np->e_id, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: wr to new parent OK np=%p, id=%ld\n",
				np, (long) np->e_id, 0 );
#endif

			/* check newSuperior for "children" acl */
			rc = access_allowed( be, conn, op, np, children,
				NULL, ACL_WRITE, NULL );

			if( ! rc ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"==>bdb_modrdn: no wr to newSup children\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"bdb_modrdn: no wr to newSup children\n",
					0, 0, 0 );
#endif
				text = "no write access to new superior's children";
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}

#ifdef BDB_ALIASES
			if ( is_entry_alias( np ) ) {
				/* parent is an alias, don't allow add */
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"==>bdb_modrdn: entry is alias\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry is alias\n",
					0, 0, 0 );
#endif
				text = "new superior is an alias";
				rc = LDAP_ALIAS_PROBLEM;
				goto return_results;
			}
#endif

			if ( is_entry_referral( np ) ) {
				/* parent is a referral, don't allow add */
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"==>bdb_modrdn: entry is referral\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: entry is referral\n",
					0, 0, 0 );
#endif
				text = "new superior is a referral";
				rc = LDAP_OTHER;
				goto return_results;
			}

		} else {
			if ( isroot == -1 ) {
				isroot = be_isroot( be, &op->o_ndn );
			}
			
			np_dn = NULL;

			/* no parent, modrdn entry directly under root */
			if ( ! isroot ) {
				if ( be_issuffix( be, (struct berval *)&slap_empty_bv )
					|| be_isupdate( be, &op->o_ndn ) ) {
					np = (Entry *)&slap_entry_root;

					/* check parent for "children" acl */
					rc = access_allowed( be, conn, op, np,
						children, NULL, ACL_WRITE, NULL );

					np = NULL;

					if ( ! rc ) {
						rc = LDAP_INSUFFICIENT_ACCESS;
#ifdef NEW_LOGGING
						LDAP_LOG ( OPERATION, ERR, 
							"==>bdb_modrdn: no access to superior\n", 0, 0, 0 );
#else
						Debug( LDAP_DEBUG_TRACE, 
							"no access to new superior\n", 
							0, 0, 0 );
#endif
						text = "no write access to new superior's children";
						goto return_results;
					}

#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, DETAIL1, 
						"bdb_modrdn: wr to children entry \"\" OK\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"bdb_modrdn: wr to children of entry \"\" OK\n",
						0, 0, 0 );
#endif
		
				} else {
#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, ERR, 
						"bdb_modrdn: new superior=\"\", not root & \"\" "
						"is not suffix\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"bdb_modrdn: new superior=\"\", not root "
						"& \"\" is not suffix\n",
						0, 0, 0);
#endif
					text = "no write access to new superior's children";
					rc = LDAP_INSUFFICIENT_ACCESS;
					goto return_results;
				}
			}

#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_modrdn: new superior=\"\"\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: new superior=\"\"\n",
				0, 0, 0 );
#endif
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_modrdn: wr to new parent's children OK\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: wr to new parent's children OK\n",
			0, 0, 0 );
#endif

		new_parent_dn = np_dn;
	}

	/* Build target dn and make sure target entry doesn't exist already. */
	build_new_dn( &new_dn, new_parent_dn, newrdn ); 

	dnNormalize2( NULL, &new_dn, &new_ndn );

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, RESULTS, 
		"bdb_modrdn: new ndn=%s\n", new_ndn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "bdb_modrdn: new ndn=%s\n",
		new_ndn.bv_val, 0, 0 );
#endif

	rc = bdb_dn2id ( be, ltid, &new_ndn, &id, 0 );
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

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ERR, 
		"bdb_modrdn: new ndn=%s does not exist\n", new_ndn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"bdb_modrdn: new ndn=%s does not exist\n",
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
			"bdb_modrdn: can't figure out "
			"type(s)/values(s) of newrdn\n", 
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modrdn: can't figure out "
			"type(s)/values(s) of newrdn\n", 
			0, 0, 0 );
#endif
		rc = LDAP_INVALID_DN_SYNTAX;
		text = "unknown type(s) used in RDN";
		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, RESULTS, 
		"bdb_modrdn: new_rdn_type=\"%s\", "
		"new_rdn_val=\"%s\"\n",
		new_rdn[ 0 ][ 0 ]->la_attr.bv_val, 
		new_rdn[ 0 ][ 0 ]->la_value.bv_val, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"bdb_modrdn: new_rdn_type=\"%s\", "
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
				"bdb_modrdn: can't figure out "
				"type(s)/values(s) of old_rdn\n", 
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modrdn: can't figure out "
				"the old_rdn type(s)/value(s)\n", 
				0, 0, 0 );
#endif
			rc = LDAP_OTHER;
			text = "cannot parse RDN from old DN";
			goto return_results;		
		}
	}

	/* prepare modlist of modifications from old/new rdn */
	rc = slap_modrdn2mods( be, conn, op, e, old_rdn, new_rdn, 
			deleteoldrdn, &mod );
	if ( rc != LDAP_SUCCESS ) {
		goto return_results;
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

	(void) bdb_cache_delete_entry(&bdb->bi_cache, e);

	/* Binary format uses a single contiguous block, cannot
	 * free individual fields. Leave new_dn/new_ndn set so
	 * they can be individually freed later.
	 */
	e->e_name = new_dn;
	e->e_nname = new_ndn;

	new_dn.bv_val = NULL;
	new_ndn.bv_val = NULL;

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

#ifdef LDAP_CLIENT_UPDATE
	if ( rc == LDAP_SUCCESS && !op->o_noop ) {
		LDAP_LIST_FOREACH ( ps_list, &bdb->psearch_list, link ) {
			bdb_psearch(be, conn, op, ps_list, e, LCUP_PSEARCH_BY_PREMODIFY );
		}
	}
#endif /* LDAP_CLIENT_UPDATE */

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

	if( op->o_noop ) {
		if(( rc=TXN_ABORT( ltid )) != 0 ) {
			text = "txn_abort (no-op) failed";
		} else {
			noop = 1;
			rc = LDAP_SUCCESS;
		}

	} else {
		char gid[DB_XIDDATASIZE];

		snprintf( gid, sizeof( gid ), "%s-%08lx-%08lx",
			bdb_uuid.bv_val, (long) op->o_connid, (long) op->o_opid );

		if(( rc=TXN_PREPARE( ltid, gid )) != 0 ) {
			text = "txn_prepare failed";
		} else {
			if( bdb_cache_update_entry(&bdb->bi_cache, e) == -1 ) {
				if(( rc=TXN_ABORT( ltid )) != 0 ) {
					text ="cache update & txn_abort failed";
				} else {
					rc = LDAP_OTHER;
					text = "cache update failed";
				}

			} else {
				if(( rc=TXN_COMMIT( ltid, 0 )) != 0 ) {
					text = "txn_commit failed";
				} else {
					rc = LDAP_SUCCESS;
				}
			}
		}
	}
 
	ltid = NULL;
	op->o_private = NULL;
 
	if( rc == LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_modrdn: rdn modified%s id=%08lx dn=\"%s\"\n", 
			op->o_noop ? " (no-op)" : "", e->e_id, e->e_dn );
#else
		Debug(LDAP_DEBUG_TRACE,
			"bdb_modrdn: rdn modified%s id=%08lx dn=\"%s\"\n",
			op->o_noop ? " (no-op)" : "", e->e_id, e->e_dn );
#endif
		text = NULL;
		if ( !noop ) {
			bdb_cache_entry_commit( e );
		}

	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, "bdb_modrdn: %s : %s (%d)\n", 
			text, db_strerror(rc), rc );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_add: %s : %s (%d)\n",
			text, db_strerror(rc), rc );
#endif
		rc = LDAP_OTHER;
	}

return_results:
	send_ldap_result( conn, op, rc,
		NULL, text, NULL, NULL );

#ifdef LDAP_CLIENT_UPDATE
	if ( rc == LDAP_SUCCESS && !op->o_noop ) {
		/* Loop through in-scope entries for each psearch spec */
		LDAP_LIST_FOREACH ( ps_list, &bdb->psearch_list, link ) {
			bdb_psearch( be, conn, op, ps_list, e, LCUP_PSEARCH_BY_MODIFY );
		}
		pm_list = LDAP_LIST_FIRST(&op->premodify_list);
		while ( pm_list != NULL ) {
			bdb_psearch(be, conn, op, pm_list->ps->op,
						e, LCUP_PSEARCH_BY_SCOPEOUT);
			LDAP_LIST_REMOVE ( pm_list, link );
			pm_prev = pm_list;
			pm_list = LDAP_LIST_NEXT ( pm_list, link );
                        free (pm_prev);
		}
	}
#endif /* LDAP_CLIENT_UPDATE */

	if( rc == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		TXN_CHECKPOINT( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

done:
	if( new_dn.bv_val != NULL ) free( new_dn.bv_val );
	if( new_ndn.bv_val != NULL ) free( new_ndn.bv_val );

	/* LDAP v2 supporting correct attribute handling. */
	if ( new_rdn != NULL ) {
		ldap_rdnfree( new_rdn );
	}
	if ( old_rdn != NULL ) {
		ldap_rdnfree( old_rdn );
	}
	if( mod != NULL ) {
		Modifications *tmp;
		for (; mod; mod=tmp ) {
			tmp = mod->sml_next;
			free( mod );
		}
	}

	/* LDAP v3 Support */
	if( np != NULL ) {
		/* free new parent and reader lock */
		bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, np);
	}

	if( p != NULL ) {
		/* free parent and reader lock */
		bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, p);
	}

	/* free entry */
	if( e != NULL ) {
		bdb_unlocked_cache_return_entry_w( &bdb->bi_cache, e);
	}

	if( ltid != NULL ) {
#ifdef LDAP_CLIENT_UPDATE
                pm_list = LDAP_LIST_FIRST(&op->premodify_list);
                while ( pm_list != NULL ) {
                        LDAP_LIST_REMOVE ( pm_list, link );
                        pm_prev = pm_list;
                        pm_list = LDAP_LIST_NEXT ( pm_list, link );
                        free (pm_prev);
                }
#endif
		TXN_ABORT( ltid );
		op->o_private = NULL;
	}

	return ( ( rc == LDAP_SUCCESS ) ? noop : rc );
}

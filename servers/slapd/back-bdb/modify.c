/* modify.c - bdb backend modify routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/time.h>

#include "back-bdb.h"
#include "external.h"

int bdb_modify_internal(
	BackendDB *be,
	Connection *conn,
	Operation *op,
	DB_TXN *tid,
	Modifications *modlist,
	Entry *e,
	const char **text,
	char *textbuf,
	size_t textlen )
{
	int rc, err;
	Modification	*mod;
	Modifications	*ml;
	Attribute	*save_attrs;
	Attribute 	*ap;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "bdb_modify_internal: 0x%08lx: %s\n", 
		e->e_id, e->e_dn, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "bdb_modify_internal: 0x%08lx: %s\n",
		e->e_id, e->e_dn, 0);
#endif

	if ( !acl_check_modlist( be, conn, op, e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, "bdb_modify_internal: add\n", 0,0,0);
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: add\n", 0, 0, 0);
#endif
			err = modify_add_values( e, mod, text, textbuf, textlen );
			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_DELETE:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_modify_internal: delete\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: delete\n", 0, 0, 0);
#endif
			err = modify_delete_values( e, mod, text, textbuf, textlen );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_REPLACE:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_modify_internal: replace\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: replace\n", 0, 0, 0);
#endif
			err = modify_replace_values( e, mod, text, textbuf, textlen );
			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case SLAP_MOD_SOFTADD:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_modify_internal: softadd\n",0,0,0 );
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: softadd\n", 0, 0, 0);
#endif
 			/* Avoid problems in index_add_mods()
 			 * We need to add index if necessary.
 			 */
 			mod->sm_op = LDAP_MOD_ADD;

			err = modify_add_values( e, mod, text, textbuf, textlen );
 			if ( err == LDAP_TYPE_OR_VALUE_EXISTS ) {
 				err = LDAP_SUCCESS;
 			}

			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
 			break;

		default:
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: invalid op %d\n", mod->sm_op, 0, 0 );
#else
			Debug(LDAP_DEBUG_ANY, "bdb_modify_internal: invalid op %d\n",
				mod->sm_op, 0, 0);
#endif
			*text = "Invalid modify operation";
			err = LDAP_OTHER;
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
				err, *text, 0);
#endif
		}

		if ( err != LDAP_SUCCESS ) {
			attrs_free( e->e_attrs );
			e->e_attrs = save_attrs;
			/* unlock entry, delete from cache */
			return err; 
		}

		/* If objectClass was modified, reset the flags */
		if ( mod->sm_desc == slap_schema.si_ad_objectClass ) {
			e->e_ocflags = 0;
		}

		/* check if modified attribute was indexed
		 * but not in case of NOOP... */
		err = bdb_index_is_indexed( be, mod->sm_desc );
		if ( err == LDAP_SUCCESS && !op->o_noop ) {
			ap = attr_find( save_attrs, mod->sm_desc );
			if ( ap ) ap->a_flags |= SLAP_ATTR_IXDEL;

			ap = attr_find( e->e_attrs, mod->sm_desc );
			if ( ap ) ap->a_flags |= SLAP_ATTR_IXADD;
		}
	}

	/* check that the entry still obeys the schema */
	rc = entry_schema_check( be, e, save_attrs, text, textbuf, textlen );
	if ( rc != LDAP_SUCCESS || op->o_noop ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;

		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "bdb_modify_internal: "
				"entry failed schema check %s\n", 
				*text, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"entry failed schema check: %s\n",
				*text, 0, 0 );
#endif
		}

		/* if NOOP then silently revert to saved attrs */
		return rc;
	}

	/* update the indices of the modified attributes */

	/* start with deleting the old index entries */
	for ( ap = save_attrs; ap != NULL; ap = ap->a_next ) {
		if ( ap->a_flags & SLAP_ATTR_IXDEL ) {
			rc = bdb_index_values( be, tid, ap->a_desc, ap->a_vals,
					       e->e_id, SLAP_INDEX_DELETE_OP );
			if ( rc != LDAP_SUCCESS ) {
				attrs_free( e->e_attrs );
				e->e_attrs = save_attrs;
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: attribute index delete failure\n",
					0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
				       "Attribute index delete failure",
				       0, 0, 0 );
#endif
				return rc;
			}
			ap->a_flags &= ~SLAP_ATTR_IXDEL;
		}
	}

	/* add the new index entries */
	for ( ap = e->e_attrs; ap != NULL; ap = ap->a_next ) {
		if (ap->a_flags & SLAP_ATTR_IXADD) {
			rc = bdb_index_values( be, tid, ap->a_desc, ap->a_vals,
					       e->e_id, SLAP_INDEX_ADD_OP );
			if ( rc != LDAP_SUCCESS ) {
				attrs_free( e->e_attrs );
				e->e_attrs = save_attrs;
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: attribute index add failure\n", 
					0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
				       "Attribute index add failure",
				       0, 0, 0 );
#endif
				return rc;
			}
			ap->a_flags &= ~SLAP_ATTR_IXADD;
		}
	}

	return rc;
}


int
bdb_modify(
	BackendDB	*be,
	Connection	*conn,
	Operation	*op,
	struct berval	*dn,
	struct berval	*ndn,
	Modifications	*modlist )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	Entry		*matched = NULL;
	Entry		*e = NULL;
	int		manageDSAit = get_manageDSAit( op );
	const char *text = NULL;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	DB_TXN	*ltid = NULL;
	struct bdb_op_info opinfo;

	u_int32_t	locker;
	DB_LOCK		lock;

	int		noop = 0;

#ifdef LDAP_CLIENT_UPDATE
	Operation* ps_list;
	struct psid_entry* pm_list;
	struct psid_entry* pm_prev;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "bdb_modify: %s\n", dn->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "bdb_modify: %s\n", dn->bv_val, 0, 0 );
#endif

	if( 0 ) {
retry:	/* transaction retry */
		if( e != NULL ) {
			bdb_cache_delete_entry(&bdb->bi_cache, e);
			bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
		}
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, "bdb_modify: retrying...\n", 0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE,
			"bdb_modify: retrying...\n", 0, 0, 0);
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
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_modify: txn_begin failed: %s (%d)\n", db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: txn_begin failed: %s (%d)\n",
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
	rc = bdb_dn2entry_w( be, ltid, ndn, &e, &matched, 0, locker, &lock );

	if ( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_modify: dn2entry failed: (%d)\n", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: dn2entry failed (%d)\n",
			rc, 0, 0 );
#endif
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case DB_NOTFOUND:
			break;
		case LDAP_BUSY:
			text = "ldap server busy";
			goto return_results;
		default:
			rc = LDAP_OTHER;
		}
		text = "internal error";
		goto return_results;
	}

	/* acquire and lock entry */
	if ( e == NULL ) {
		char* matched_dn = NULL;
		BerVarray refs;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb_unlocked_cache_return_entry_r (&bdb->bi_cache, matched);
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

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow modify */
		BerVarray refs = get_entry_referrals( be,
			conn, op, e );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, "bdb_modify: entry is referral\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: entry is referral\n",
			0, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvarray_free( refs );
		goto done;
	}

#ifdef LDAP_CLIENT_UPDATE
	if ( rc == LDAP_SUCCESS && !op->o_noop ) {
		LDAP_LIST_FOREACH ( ps_list, &bdb->psearch_list, link ) {
			bdb_psearch(be, conn, op, ps_list, e, LCUP_PSEARCH_BY_PREMODIFY );
		}
	}
#endif /* LDAP_CLIENT_UPDATE */
	
	/* Modify the entry */
	rc = bdb_modify_internal( be, conn, op, ltid, modlist, e,
		&text, textbuf, textlen );

	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_modify: modify failed (%d)\n", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: modify failed (%d)\n",
			rc, 0, 0 );
#endif
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		goto return_results;
	}

	/* change the entry itself */
	rc = bdb_id2entry_update( be, ltid, e );
	if ( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_modify: id2entry update failed (%d)\n", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: id2entry update failed (%d)\n",
			rc, 0, 0 );
#endif
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		text = "entry update failed";
		goto return_results;
	}

	if( op->o_noop ) {
		if ( ( rc = TXN_ABORT( ltid ) ) != 0 ) {
			text = "txn_abort (no-op) failed";
		} else {
			noop = 1;
			rc = LDAP_SUCCESS;
		}
	} else {
		rc = TXN_COMMIT( ltid, 0 );
	}
	ltid = NULL;
	op->o_private = NULL;

	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_modify: txn_%s failed %s (%d)\n", 
			op->o_noop ? "abort (no_op)" : "commit", db_strerror(rc), rc );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: txn_%s failed: %s (%d)\n",
			op->o_noop ? "abort (no-op)" : "commit",
			db_strerror(rc), rc );
#endif
		rc = LDAP_OTHER;
		text = "commit failed";

	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_modify: updated%s id=%08lx dn=\"%s\"\n", 
			op->o_noop ? " (no_op)" : "", e->e_id, e->e_dn );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: updated%s id=%08lx dn=\"%s\"\n",
			op->o_noop ? " (no-op)" : "",
			e->e_id, e->e_dn );
#endif
		rc = LDAP_SUCCESS;
		text = NULL;
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

	if( e != NULL ) {
		bdb_unlocked_cache_return_entry_w (&bdb->bi_cache, e);
	}
	return ( ( rc == LDAP_SUCCESS ) ? noop : rc );
}

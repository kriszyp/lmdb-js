/* passwd.c - bdb backend password routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"
#include "lber_pvt.h"

int
bdb_exop_passwd( Operation *op, SlapReply *rs )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	int rc;
	Entry *e = NULL;
	EntryInfo *ei;
	struct berval hash = { 0, NULL };
	DB_TXN *ltid = NULL, *lt2;
	struct bdb_op_info opinfo;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;

	struct berval id = { 0, NULL };
	struct berval new = { 0, NULL };

	struct berval dn = { 0, NULL };
	struct berval ndn = { 0, NULL };

	u_int32_t	locker = 0;
	DB_LOCK		lock;

	int		num_retries = 0;

	assert( ber_bvcmp( &slap_EXOP_MODIFY_PASSWD, &op->oq_extended.rs_reqoid ) == 0 );

	rc = slap_passwd_parse( op->oq_extended.rs_reqdata,
		&id, NULL, &new, &rs->sr_text );

#ifdef NEW_LOGGING
	LDAP_LOG ( ACL, ENTRY, 
		"==>bdb_exop_passwd: \"%s\"\n", id.bv_val ? id.bv_val : "", 0, 0  );
#else
	Debug( LDAP_DEBUG_ARGS, "==> bdb_exop_passwd: \"%s\"\n",
		id.bv_val ? id.bv_val : "", 0, 0 );
#endif

	if( rc != LDAP_SUCCESS ) {
		goto done;
	}

	if( new.bv_len == 0 ) {
		slap_passwd_generate(&new);

		if( new.bv_len == 0 ) {
			rs->sr_text = "password generation failed.";
			rc = LDAP_OTHER;
			goto done;
		}
		
		rs->sr_rspdata = slap_passwd_return( &new );
	}

	slap_passwd_hash( &new, &hash, &rs->sr_text );

	if( hash.bv_len == 0 ) {
		if( !rs->sr_text ) rs->sr_text = "password hash failed";
		rc = LDAP_OTHER;
		goto done;
	}

	if( id.bv_len ) {
		dn = id;
	} else {
		dn = op->o_dn;
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( ACL, DETAIL1, "bdb_exop_passwd: \"%s\"%s\"\n",
		dn.bv_val, id.bv_len ? " (proxy)" : "", 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "bdb_exop_passwd: \"%s\"%s\n",
		dn.bv_val, id.bv_len ? " (proxy)" : "", 0 );
#endif

	if( dn.bv_len == 0 ) {
		rs->sr_text = "No password is associated with the Root DSE";
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto done;
	}

	rc = dnNormalize( 0, NULL, NULL, &dn, &ndn, op->o_tmpmemctx );
	if( rc != LDAP_SUCCESS ) {
		rs->sr_text = "Invalid DN";
		goto done;
	}

	if( 0 ) {
retry:	/* transaction retry */
		if ( e != NULL ) {
			bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
		}
#ifdef NEW_LOGGING
		LDAP_LOG ( ACL, DETAIL1, "bdb_exop_passwd: retrying...\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_exop_passwd: retrying...\n", 0, 0, 0 );
#endif
		rc = TXN_ABORT( ltid );
		ltid = NULL;
		op->o_private = NULL;
		op->o_do_not_cache = opinfo.boi_acl_cache;
		if( rc != 0 ) {
			rc = LDAP_OTHER;
			rs->sr_text = "internal error";
			goto done;
		}
		ldap_pvt_thread_yield();
		bdb_trans_backoff( ++num_retries );
	}

	/* begin transaction */
	rc = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, 
		bdb->bi_db_opflags );
	rs->sr_text = NULL;
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( ACL, ERR, 
			"bdb_exop_passwd: txn_begin failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_exop_passwd: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#endif
		rc = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto done;
	}

	locker = TXN_ID ( ltid );

	opinfo.boi_bdb = op->o_bd;
	opinfo.boi_txn = ltid;
	opinfo.boi_locker = locker;
	opinfo.boi_err = 0;
	opinfo.boi_acl_cache = op->o_do_not_cache;
	op->o_private = &opinfo;

	/* get entry */
	rc = bdb_dn2entry( op, ltid, &ndn, &ei, 0 , locker, &lock );

	switch(rc) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	case DB_NOTFOUND:
	case 0:
		break;
	case LDAP_BUSY:
		rs->sr_text = "ldap server busy";
		goto done;
	default:
		rc = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto done;
	}

	if ( ei ) e = ei->bei_e;

	if ( e == NULL || is_entry_glue( e )) {
			/* FIXME: dn2entry() should return non-glue entry */
		rs->sr_text = "could not locate authorization entry";
		rc = LDAP_NO_SUCH_OBJECT;
		goto done;
	}

#ifdef BDB_SUBENTRIES
	if( is_entry_subentry( e ) ) {
		/* entry is a subentry, don't allow operation */
		rs->sr_text = "authorization entry is subentry";
		rc = LDAP_OTHER;
		goto done;
	}
#endif

#ifdef BDB_ALIASES
	if( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow operation */
		rs->sr_text = "authorization entry is alias";
		rc = LDAP_ALIAS_PROBLEM;
		goto done;
	}
#endif

	if( is_entry_referral( e ) ) {
		/* entry is an referral, don't allow operation */
		rs->sr_text = "authorization entry is referral";
		rc = LDAP_OTHER;
		goto done;
	}

	/* nested transaction */
	rc = TXN_BEGIN( bdb->bi_dbenv, ltid, &lt2, 
		bdb->bi_db_opflags );
	rs->sr_text = NULL;
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_exop_passwd: txn_begin(2) failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_exop_passwd: txn_begin(2) failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#endif
		rc = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto done;
	}

	{
		Modifications ml;
		struct berval vals[2];
		Entry dummy, *save;

		save = e;
		dummy = *e;
		e = &dummy;

		vals[0] = hash;
		vals[1].bv_val = NULL;

		ml.sml_desc = slap_schema.si_ad_userPassword;
		ml.sml_values = vals;
		ml.sml_nvalues = NULL;
		ml.sml_op = LDAP_MOD_REPLACE;
		ml.sml_next = NULL;

		rc = bdb_modify_internal( op, lt2,
			&ml, e, &rs->sr_text, textbuf, textlen );

		if ( (rc == LDAP_INSUFFICIENT_ACCESS) && opinfo.boi_err ) {
			rc = opinfo.boi_err;
		}
		switch(rc) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			rs->sr_text = NULL;
			goto retry;
		case 0:
			rs->sr_text = NULL;
			break;
		default:
			rc = LDAP_OTHER;
			rs->sr_text = "entry modify failed";
			goto done;
		}

		/* change the entry itself */
		rc = bdb_id2entry_update( op->o_bd, lt2, e );
		if( rc != 0 ) {
			switch(rc) {
			case DB_LOCK_DEADLOCK:
			case DB_LOCK_NOTGRANTED:
				goto retry;
			}
			rs->sr_text = "entry update failed";
			rc = LDAP_OTHER;
		}
		if ( TXN_COMMIT( lt2, 0 ) != 0 ) {
			rc = LDAP_OTHER;
			rs->sr_text = "txn_commit(2) failed";
		}

		if( rc == 0 ) {
			if( op->o_noop ) {
				rc = TXN_ABORT( ltid );
			} else {
				bdb_cache_modify( save, e->e_attrs,
					bdb->bi_dbenv, locker, &lock );
				rc = TXN_COMMIT( ltid, 0 );
			}
			ltid = NULL;
		}
		op->o_private = NULL;

		if( rc == LDAP_SUCCESS ) {
			op->o_req_dn = e->e_name;
			op->o_req_ndn = e->e_nname;
			op->oq_modify.rs_modlist = &ml;
			replog( op );
			op->oq_extended.rs_reqoid = slap_EXOP_MODIFY_PASSWD;
		}
	}

done:
	if( e != NULL ) {
		bdb_unlocked_cache_return_entry_w( &bdb->bi_cache, e );
	}
		
	if( hash.bv_val != NULL ) {
		free( hash.bv_val );
	}

	if( ndn.bv_val != NULL ) {
		op->o_tmpfree( ndn.bv_val, op->o_tmpmemctx );
	}

	if( ltid != NULL ) {
		TXN_ABORT( ltid );
		op->o_private = NULL;
	}

	return rc;
}

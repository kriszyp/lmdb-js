/* passwd.c - bdb backend password routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

int
bdb_exop_passwd(
	Backend		*be,
	Connection		*conn,
	Operation		*op,
	const char		*reqoid,
	struct berval	*reqdata,
	char			**rspoid,
	struct berval	**rspdata,
	LDAPControl		*** rspctrls,
	const char		**text,
	BerVarray *refs )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	Entry *e = NULL;
	struct berval hash = { 0, NULL };
	DB_TXN *ltid = NULL;
	struct bdb_op_info opinfo;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;

	struct berval id = { 0, NULL };
	struct berval new = { 0, NULL };

	struct berval dn;
	struct berval ndn;

	u_int32_t	locker = 0;
	DB_LOCK		lock;

	assert( reqoid != NULL );
	assert( strcmp( LDAP_EXOP_MODIFY_PASSWD, reqoid ) == 0 );

	rc = slap_passwd_parse( reqdata,
		&id, NULL, &new, text );

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
			*text = "password generation failed.";
			rc = LDAP_OTHER;
			goto done;
		}
		
		*rspdata = slap_passwd_return( &new );
	}

	slap_passwd_hash( &new, &hash );

	if( hash.bv_len == 0 ) {
		*text = "password hash failed";
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
		*text = "No password is associated with the Root DSE";
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto done;
	}

	rc = dnNormalize2( NULL, &dn, &ndn );
	if( rc != LDAP_SUCCESS ) {
		*text = "Invalid DN";
		goto done;
	}

	if( 0 ) {
retry:	/* transaction retry */
		if ( e != NULL ) {
			bdb_cache_delete_entry(&bdb->bi_cache, e);
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
		if( rc != 0 ) {
			rc = LDAP_OTHER;
			*text = "internal error";
			goto done;
		}
		ldap_pvt_thread_yield();
	}

	/* begin transaction */
	rc = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, 
		bdb->bi_db_opflags );
	*text = NULL;
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
		*text = "internal error";
		goto done;
	}

	locker = TXN_ID ( ltid );

	opinfo.boi_bdb = be;
	opinfo.boi_txn = ltid;
	opinfo.boi_locker = locker;
	opinfo.boi_err = 0;
	op->o_private = &opinfo;

	/* get entry */
	rc = bdb_dn2entry_w( be, ltid, &ndn, &e, NULL, 0 , locker, &lock);

	switch(rc) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	case DB_NOTFOUND:
	case 0:
		break;
	case LDAP_BUSY:
		*text = "ldap server busy";
		goto done;
	default:
		rc = LDAP_OTHER;
		*text = "internal error";
		goto done;
	}

	if( e == NULL ) {
		*text = "could not locate authorization entry";
		rc = LDAP_NO_SUCH_OBJECT;
		goto done;
	}

#ifdef BDB_SUBENTRIES
	if( is_entry_subentry( e ) ) {
		/* entry is an alias, don't allow operation */
		*text = "authorization entry is subentry";
		rc = LDAP_OTHER;
		goto done;
	}
#endif
#ifdef BDB_ALIASES
	if( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow operation */
		*text = "authorization entry is alias";
		rc = LDAP_ALIAS_PROBLEM;
		goto done;
	}
#endif

	if( is_entry_referral( e ) ) {
		/* entry is an referral, don't allow operation */
		*text = "authorization entry is referral";
		rc = LDAP_OTHER;
		goto done;
	}

	{
		Modifications ml;
		struct berval vals[2];

		vals[0] = hash;
		vals[1].bv_val = NULL;

		ml.sml_desc = slap_schema.si_ad_userPassword;
		ml.sml_bvalues = vals;
		ml.sml_op = LDAP_MOD_REPLACE;
		ml.sml_next = NULL;

		rc = bdb_modify_internal( be, conn, op, ltid,
			&ml, e, text, textbuf, textlen );

		switch(rc) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			*text = NULL;
			goto retry;
		case 0:
			*text = NULL;
			break;
		default:
			rc = LDAP_OTHER;
			*text = "entry modify failed";
			goto done;
		}

		/* change the entry itself */
		rc = bdb_id2entry_update( be, ltid, e );
		if( rc != 0 ) {
			switch(rc) {
			case DB_LOCK_DEADLOCK:
			case DB_LOCK_NOTGRANTED:
				goto retry;
			}
			*text = "entry update failed";
			rc = LDAP_OTHER;
		}

		if( rc == 0 ) {
			if( op->o_noop ) {
				rc = TXN_ABORT( ltid );
			} else {
				rc = TXN_COMMIT( ltid, 0 );
			}
			ltid = NULL;
		}
		op->o_private = NULL;

		if( rc == LDAP_SUCCESS ) {
			replog( be, op, &e->e_name, &e->e_nname, &ml );
		}
	}

done:
	if( e != NULL ) {
		bdb_unlocked_cache_return_entry_w( &bdb->bi_cache, e );
	}
		
	if( hash.bv_val != NULL ) {
		free( hash.bv_val );
	}

	if( ltid != NULL ) {
		TXN_ABORT( ltid );
		op->o_private = NULL;
	}

	return rc;
}

/* $OpenLDAP$ */
/*
 * back-bdb Context CSN Management Routines
 */
/* Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/time.h>

#include "back-bdb.h"
#include "external.h"

#ifdef LDAP_SYNC
int
bdb_csn_commit(
	Operation *op,
	SlapReply *rs,
	DB_TXN *tid,
	EntryInfo *ei,
	EntryInfo **suffix_ei,
	Entry **ctxcsn_e,
	int *ctxcsn_added,
	u_int32_t locker
)
{
	struct bdb_info	*bdb = (struct bdb_info *) op->o_bd->be_private;
	struct berval	ctxcsn_rdn = { 0, NULL };
	struct berval	ctxcsn_ndn = { 0, NULL };
	EntryInfo		*ctxcsn_ei = NULL;
	DB_LOCK			ctxcsn_lock;
	struct berval	*max_committed_csn = NULL;
	DB_LOCK			suffix_lock;
	int				rc, ret;
	ID				ctxcsn_id;
	Entry			*e;

	if ( ei ) {
		e = ei->bei_e;
	}

	ber_str2bv( "cn=ldapsync", strlen("cn=ldapsync"), 0, &ctxcsn_rdn );
	build_new_dn( &ctxcsn_ndn, &op->o_bd->be_nsuffix[0], &ctxcsn_rdn );

	rc = bdb_dn2entry( op, tid, &ctxcsn_ndn, &ctxcsn_ei,
							   0, locker, &ctxcsn_lock );

	if ( ctxcsn_ei ) {
		*ctxcsn_e = ctxcsn_ei->bei_e;
		bdb_cache_entry_db_relock( bdb->bi_dbenv, locker, ctxcsn_ei, 1, 0, &ctxcsn_lock );
	}

	max_committed_csn = slap_get_commit_csn( op );

	if ( max_committed_csn == NULL )
		return BDB_CSN_COMMIT;

	*ctxcsn_added = 0;

	switch( rc ) {
	case 0:
		if ( !*ctxcsn_e ) {
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "context csn not present";
			return BDB_CSN_ABORT;
		} else {
			attr_delete( &(*ctxcsn_e)->e_attrs, slap_schema.si_ad_contextCSN );
			attr_merge_normalize_one( *ctxcsn_e, slap_schema.si_ad_contextCSN,
							max_committed_csn, NULL );
			ret = bdb_id2entry_update( op->o_bd, tid, *ctxcsn_e );
			switch ( ret ) {
			case 0 :
				break;
			case DB_LOCK_DEADLOCK :
			case DB_LOCK_NOTGRANTED :
				goto rewind;
			default :
				rs->sr_err = ret;
				rs->sr_text = "context csn update failed";
				return BDB_CSN_ABORT;
			}
			ret = bdb_index_entry_add( op, tid, *ctxcsn_e );
			switch ( ret ) {
			case 0 :
				break;
			case DB_LOCK_DEADLOCK :
			case DB_LOCK_NOTGRANTED :
				goto rewind;
			default :
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "context csn indexing failed";
				return BDB_CSN_ABORT;
			}
		}
		break;
	case DB_NOTFOUND:
		if ( op->o_tag == LDAP_REQ_ADD && !be_issuffix( op->o_bd, &op->oq_add.rs_e->e_nname )) {
			rc = bdb_dn2entry( op, tid, &op->o_bd->be_nsuffix[0], suffix_ei,
									0, locker, &suffix_lock );
		} else if ( op->o_tag != LDAP_REQ_ADD && !be_issuffix( op->o_bd, &e->e_nname )) {
			rc = bdb_dn2entry( op, tid, &op->o_bd->be_nsuffix[0], suffix_ei,
									0, locker, &suffix_lock );
		} else {
			*suffix_ei = ei;
		}

		/* This serializes add. But this case is very rare : only once. */
		rs->sr_err = bdb_next_id( op->o_bd, tid, &ctxcsn_id );
		if ( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR,
				"bdb_add: next_id failed (%d)\n", rs->sr_err, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"bdb_add: next_id failed (%d)\n", rs->sr_err, 0, 0 );
#endif
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "internal error";
			return BDB_CSN_ABORT;
		}

		*ctxcsn_e = slap_create_context_csn_entry( op->o_bd, max_committed_csn );
		(*ctxcsn_e)->e_id = ctxcsn_id;
		*ctxcsn_added = 1;
		ret = bdb_dn2id_add( op, tid, *suffix_ei, *ctxcsn_e );
		switch ( ret ) {
		case 0 :
			break;
		case DB_LOCK_DEADLOCK :
		case DB_LOCK_NOTGRANTED :
			goto rewind;
		case DB_KEYEXIST :
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "context csn exists before contex prefix does";
			return BDB_CSN_ABORT;
		default :
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "context csn store failed";
			return BDB_CSN_ABORT;
		}
		ret = bdb_id2entry_add( op->o_bd, tid, *ctxcsn_e );
		switch ( ret ) {
		case 0 :
			break;
		case DB_LOCK_DEADLOCK :
		case DB_LOCK_NOTGRANTED :
			goto rewind;
		default :
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "context csn store failed";
			return BDB_CSN_ABORT;
		}
		ret = bdb_index_entry_add( op, tid, *ctxcsn_e );
		switch ( ret ) {
		case 0 :
			break;
		case DB_LOCK_DEADLOCK :
		case DB_LOCK_NOTGRANTED :
			goto rewind;
		default :
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "context csn indexing failed";
			return BDB_CSN_ABORT;
		}
		break;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto rewind;
	case LDAP_BUSY:
		rs->sr_err = rc;
		rs->sr_text = "ldap server busy";
		return BDB_CSN_ABORT;
	default:
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		return BDB_CSN_ABORT;
	}

	return BDB_CSN_COMMIT;

rewind :
	slap_rewind_commit_csn( op );
	return BDB_CSN_RETRY;
}
#endif

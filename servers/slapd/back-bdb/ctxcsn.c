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

#include "lutil.h"
#include "back-bdb.h"
#include "external.h"

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
	char			textbuf[SLAP_TEXT_BUFLEN];
	size_t			textlen = sizeof textbuf;
	Modifications	*ml, *mlnext, *mod, *modlist;
	Modifications	**modtail = &modlist;
	struct berval	*csnbva = NULL;
	EntryInfo		*eip = NULL;

	if ( ei ) {
		e = ei->bei_e;
	}

	ber_str2bv( "cn=ldapsync", strlen("cn=ldapsync"), 0, &ctxcsn_rdn );
	build_new_dn( &ctxcsn_ndn, &op->o_bd->be_nsuffix[0], &ctxcsn_rdn );

	rc = bdb_dn2entry( op, tid, &ctxcsn_ndn, &ctxcsn_ei,
							   1, locker, &ctxcsn_lock );

	*ctxcsn_e = ctxcsn_ei->bei_e;

	max_committed_csn = slap_get_commit_csn( op );

	if ( max_committed_csn == NULL ) {
		return BDB_CSN_COMMIT;
	}

	*ctxcsn_added = 0;

	switch( rc ) {
	case 0:
		if ( !*ctxcsn_e ) {
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "context csn not present";
			ber_bvfree( max_committed_csn );
			return BDB_CSN_ABORT;
		} else {
			csnbva = ( struct berval * ) ch_calloc( 2, sizeof( struct berval ));
			ber_dupbv( &csnbva[0], max_committed_csn );
			mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
			mod->sml_op = LDAP_MOD_REPLACE;
			ber_str2bv( "contextCSN", strlen("contextCSN"), 1, &mod->sml_type );
			mod->sml_bvalues = csnbva;
			*modtail = mod;
			modtail = &mod->sml_next;

			ret = slap_mods_check( modlist, 1, &rs->sr_text, textbuf, textlen, NULL );

			if ( ret != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR,
						"bdb_csn_commit: mods check (%s)\n", rs->sr_text, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
						"bdb_csn_commit: mods check (%s)\n", rs->sr_text, 0, 0 );
#endif
			}

			bdb_cache_entry_db_relock( bdb->bi_dbenv, locker, ctxcsn_ei, 1, 0, &ctxcsn_lock );

			ret = bdb_modify_internal( op, tid, modlist, *ctxcsn_e,
									&rs->sr_text, textbuf, textlen );								
			if ( ret != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR,
						"bdb_csn_commit: modify failed (%d)\n", rs->sr_err, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
						"bdb_csn_commit: modify failed (%d)\n", rs->sr_err, 0, 0 );
#endif
				switch( ret ) {
				case DB_LOCK_DEADLOCK:
				case DB_LOCK_NOTGRANTED:
					goto rewind;
				default:
					return BDB_CSN_ABORT;
				}
			}

			for ( ml = modlist; ml != NULL; ml = mlnext ) {
				mlnext = ml->sml_next;
				free( ml );
			}

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
		}
		break;
	case DB_NOTFOUND:
		if ( op->o_tag == LDAP_REQ_ADD &&
						be_issuffix( op->o_bd, &op->oq_add.rs_e->e_nname )) {
			*suffix_ei = NULL;
			eip = (EntryInfo *) ch_calloc( 1, sizeof( EntryInfo ));
			eip->bei_id = op->oq_add.rs_e->e_id;
		} else {
			eip = *suffix_ei = ctxcsn_ei;
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
		ber_bvfree( max_committed_csn );
		(*ctxcsn_e)->e_id = ctxcsn_id;
		*ctxcsn_added = 1;

		ret = bdb_dn2id_add( op, tid, eip, *ctxcsn_e );
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

		if ( *suffix_ei == NULL ) {
			ch_free( eip );
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
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
				"bdb_csn_commit : bdb_dn2entry retry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
				"bdb_csn_commit : bdb_dn2entry retry\n", 0, 0, 0 );
#endif
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

int
bdb_get_commit_csn(
	Operation	*op,
	SlapReply	*rs,
	struct berval	**search_context_csn,
	u_int32_t	locker,
	DB_LOCK		*ctxcsn_lock
)
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	struct berval ctxcsn_rdn = BER_BVNULL;
	struct berval ctxcsn_ndn = BER_BVNULL;
	struct berval csn = BER_BVNULL;
	struct berval ctx_nrdn = BER_BVC( "cn=ldapsync" );
	EntryInfo	*ctxcsn_ei = NULL;
	EntryInfo	*suffix_ei = NULL;
	Entry		*ctxcsn_e = NULL;
	DB_TXN		*ltid = NULL;
	Attribute	*csn_a;
	char		substr[67];
	char		gid[DB_XIDDATASIZE];
	char		csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];
	int			num_retries = 0;
	int			ctxcsn_added = 0;
	int			rc;

	if ( op->o_sync_mode != SLAP_SYNC_NONE ) {
		if ( op->o_bd->syncinfo ) {
			sprintf( substr, "cn=syncrepl%d", op->o_bd->syncinfo->id );
			ber_str2bv( substr, strlen( substr ), 0, &ctxcsn_rdn );
			build_new_dn( &ctxcsn_ndn, &op->o_bd->be_nsuffix[0], &ctxcsn_rdn );
		} else {
			ber_str2bv( "cn=ldapsync", strlen("cn=ldapsync"), 0, &ctxcsn_rdn );
			build_new_dn( &ctxcsn_ndn, &op->o_bd->be_nsuffix[0], &ctxcsn_rdn );
		}

ctxcsn_retry :
		rs->sr_err = bdb_dn2entry( op, NULL, &ctxcsn_ndn, &ctxcsn_ei,
									0, locker, ctxcsn_lock );
		switch(rs->sr_err) {
		case 0:
			ch_free( ctxcsn_ndn.bv_val );
			if ( ctxcsn_ei ) {
				ctxcsn_e = ctxcsn_ei->bei_e;
			}
			break;
        case LDAP_BUSY:
			ch_free( ctxcsn_ndn.bv_val );
			LOCK_ID_FREE (bdb->bi_dbenv, locker );
			return LDAP_BUSY;
        case DB_LOCK_DEADLOCK:
        case DB_LOCK_NOTGRANTED:
			goto ctxcsn_retry;
        case DB_NOTFOUND:
			if ( !op->o_bd->syncinfo ) {
				snprintf( gid, sizeof( gid ), "%s-%08lx-%08lx",
							bdb_uuid.bv_val, (long) op->o_connid, (long) op->o_opid );

				slap_get_csn( op, csnbuf, sizeof(csnbuf), &csn, 1 );

				if ( 0 ) {
txn_retry:
					rs->sr_err = TXN_ABORT( ltid );
					if ( rs->sr_err != 0 ) {
						rs->sr_err = LDAP_OTHER;
						return rs->sr_err;
					}

					bdb_trans_backoff( ++num_retries );
					ldap_pvt_thread_yield();
				}
				rs->sr_err = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, bdb->bi_db_opflags );
				if ( rs->sr_err != 0 ) {
					rs->sr_err = LDAP_OTHER;
					return rs->sr_err;
				}

				rs->sr_err = bdb_csn_commit( op, rs, ltid, NULL, &suffix_ei,
										&ctxcsn_e, &ctxcsn_added, locker );
				switch( rs->sr_err ) {
				case BDB_CSN_ABORT:
					LOCK_ID_FREE( bdb->bi_dbenv, locker );
					return LDAP_OTHER;
				case BDB_CSN_RETRY:
					goto txn_retry;
				}

				rs->sr_err = TXN_PREPARE( ltid, gid );
				if ( rs->sr_err != 0 ) {
					rs->sr_err = LDAP_OTHER;
					return rs->sr_err;
				}

				bdb_cache_add( bdb, suffix_ei, ctxcsn_e, &ctx_nrdn, locker );

				rs->sr_err = TXN_COMMIT( ltid, 0 );
				if ( rs->sr_err != 0 ) {
					rs->sr_err = LDAP_OTHER;
					return rs->sr_err;
				}

				ctxcsn_ei = NULL;
				rs->sr_err = bdb_dn2entry( op, NULL, &ctxcsn_ndn, &ctxcsn_ei,
										0, locker, ctxcsn_lock );
				ch_free( ctxcsn_ndn.bv_val );

				if ( ctxcsn_ei ) {
					ctxcsn_e = ctxcsn_ei->bei_e;
				}
			} else {
				LOCK_ID_FREE( bdb->bi_dbenv, locker );
				return LDAP_OTHER;
			}
			break;

		default:
			LOCK_ID_FREE (bdb->bi_dbenv, locker );
			return LDAP_OTHER;
		}

		if ( ctxcsn_e ) {
			if ( op->o_bd->syncinfo ) {
				csn_a = attr_find( ctxcsn_e->e_attrs, slap_schema.si_ad_syncreplCookie );
			} else {
				csn_a = attr_find( ctxcsn_e->e_attrs, slap_schema.si_ad_contextCSN );
			}
			if ( csn_a ) {
				*search_context_csn = ber_dupbv( NULL, &csn_a->a_vals[0] );
			} else {
				*search_context_csn = NULL;
			}
		} else {
			*search_context_csn = NULL;
		}
	}

	return LDAP_SUCCESS;
}

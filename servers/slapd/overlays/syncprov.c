/* syncprov.c - syncrepl provider */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Howard Chu for inclusion in
 * OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_OVER_SYNCPROV

#include "slap.h"

/* Record of a persistent search */
typedef struct syncops {
	struct syncops *s_next;
	struct berval	s_base;		/* ndn of search base */
	ID		s_eid;		/* entryID of search base */
	Operation	*s_op;		/* search op */
} syncops;

/* Record of which searches matched at premodify step */
typedef struct syncmatches {
	struct syncmatches *sm_next;
	syncops *sm_op;
} syncmatches;

typedef struct syncprov_info_t {
	Entry		*si_e;	/* cached ldapsync context */
	syncops		*si_ops;
	int		si_chkops;	/* checkpointing */
	int		si_chktime;
	int		si_numops;	/* number of ops since last checkpoint */
	time_t	si_chklast;	/* time of last checkpoint */
	ldap_pvt_thread_mutext_t si_e_mutex;
	ldap_pvt_thread_mutext_t si_ops_mutex;
	ldap_pvt_thread_mutext_t si_chk_mutex;
} syncprov_info_t;

typedef struct opcookie {
	slap_overinst *son;
	syncmatches *smatches;
} opcookie;

/* Refresh - find entries between cookie CSN and current CSN at start
 * of operation.
 */

static void
syncprov_matchops( Operation *op, opcookie *opc )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	syncops *ss;

	for (ss = si->si_ops; ss; ss=ss->s_next)
	{
		/* validate base */
		/* check if current o_req_dn is in scope and matches filter */
	}
}

static int
syncprov_op_response( Operation *op, SlapReply *rs )
{
	slap_callback *sc = op->o_callback;
	opcookie *opc = (opcookie *)(cb+1);
	slap_overinst *on = opc->son;
	syncprov_info_t		*si = on->on_bi.bi_private;

	if ( rs->sr_err == LDAP_SUCCESS )
	{
		switch(op->o_tag) {
		case LDAP_REQ_ADD:
			/* for each op in si->si_ops:
			 *   validate base
			 *   check for scope and filter
			 *   send ADD msg if matched
			 */
			 break;
		case LDAP_REQ_DELETE:
			/* for each match in opc->smatches:
			 *   send DELETE msg
			 */
			 break;
		case LDAP_REQ_MODIFY:
		case LDAP_REQ_MODRDN:
			/* for each op in si->si_ops:
			 *   validate base
			 *   check for scope and filter
			 *   if match
			 *     if match in opc->smatches, send UPDATE
			 *     else send ADD
			 *   else
			 *     if match in opc->smatches, send DELETE
			 */
			 break;
		case LDAP_REQ_EXTENDED:
			/* for each op in si->si_ops:
			 *   validate base
			 *   check for scope and filter
			 *   send UPDATE msg if matched
			 */
			 break;
		}
	}
	op->o_callback = cb->sc_next;
	op->o_tmpfree(cb, op->o_tmpmemctx);
	return SLAP_CB_CONTINUE;
}

static int
syncprov_op_compare( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;
	int rc = SLAP_CB_CONTINUE;

	if ( dn_match( &op->o_req_ndn, &si->si_e->e_nname ) )
	{
		
		ldap_pvt_thread_mutex_lock( &si->si_e_mutex );

		if ( get_assert( op ) &&
			( test_filter( op, si->si_e, get_assertion( op ) ) != LDAP_COMPARE_TRUE ) )
		{
			rs->sr_err = LDAP_ASSERTION_FAILED;
			goto return_results;
		}

		rs->sr_err = access_allowed( op, si->si_e, op->oq_compare.rs_ava->aa_desc,
			&op->oq_compare.rs_ava->aa_value, ACL_COMPARE, NULL );
		if ( ! rs->sr_err ) {
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		rs->sr_err = LDAP_NO_SUCH_ATTRIBUTE;

		for ( a = attr_find( si->si_e->e_attrs, op->oq_compare.rs_ava->aa_desc );
			a != NULL;
			a = attr_find( a->a_next, op->oq_compare.rs_ava->aa_desc ) )
		{
			rs->sr_err = LDAP_COMPARE_FALSE;

			if ( value_find_ex( op->oq_compare.rs_ava->aa_desc,
				SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
					SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
				a->a_nvals, &op->oq_compare.rs_ava->aa_value, op->o_tmpmemctx ) == 0 )
			{
				rs->sr_err = LDAP_COMPARE_TRUE;
				break;
			}
		}

return_results:;

		ldap_pvt_thread_mutex_unlock( &si->si_entry_mutex );

		send_ldap_result( op, rs );

		if( rs->sr_err == LDAP_COMPARE_FALSE || rs->sr_err == LDAP_COMPARE_TRUE ) {
			rs->sr_err = LDAP_SUCCESS;
		}
		rc = rs->sr_err;
	}

	return SLAP_CB_CONTINUE;
}
	
static int
syncprov_op_add( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	if ( si->si_ops )
	{
		slap_callback *cb = op->o_tmpcalloc(1, sizeof(slap_callback)+sizeof(opcookie), op->o_tmpmemctx);
		opcookie *opc = (opcookie *)(cb+1);
		opc->son = on;
		cb->sc_response = syncprov_op_response;
		cb->sc_private = opc;
		cb->sc_next = op->o_callback;
		op->o_callback = cb;
	}

	return SLAP_CB_CONTINUE;
}

static int
syncprov_op_delete( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	if ( si->si_ops )
	{
		slap_callback *cb = op->o_tmpcalloc(1, sizeof(slap_callback)+sizeof(opcookie), op->o_tmpmemctx);
		opcookie *opc = (opcookie *)(cb+1);
		opc->son = on;
		cb->sc_response = syncprov_op_response;
		cb->sc_private = opc;
		cb->sc_next = op->o_callback;
		op->o_callback = cb;

		syncprov_matchops( op, opc );
	}

	return SLAP_CB_CONTINUE;
}

static int
syncprov_op_modify( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	if ( si->si_ops )
	{
		slap_callback *cb = op->o_tmpcalloc(1, sizeof(slap_callback)+sizeof(opcookie), op->o_tmpmemctx);
		opcookie *opc = (opcookie *)(cb+1);
		opc->son = on;
		cb->sc_response = syncprov_op_response;
		cb->sc_private = opc;
		cb->sc_next = op->o_callback;
		op->o_callback = cb;

		syncprov_matchops( op, opc );
	}

	return SLAP_CB_CONTINUE;
}

static int
syncprov_op_modrdn( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	if ( si->si_ops )
	{
		slap_callback *cb = op->o_tmpcalloc(1, sizeof(slap_callback)+sizeof(opcookie), op->o_tmpmemctx);
		opcookie *opc = (opcookie *)(cb+1);
		opc->son = on;
		cb->sc_response = syncprov_op_response;
		cb->sc_private = opc;
		cb->sc_next = op->o_callback;
		op->o_callback = cb;

		syncprov_matchops( op, opc );
	}

	return SLAP_CB_CONTINUE;
}

static int
syncprov_op_extended( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	if ( si->si_ops )
	{
		int i, doit = 0;

		for ( i=0; write_exop[i]; i++ )
		{
			if ( !ber_bvcmp( write_exop[i], &op->oq_extended.rs_reqoid ))
			{
				doit = 1;
				break;
			}
		}
		if ( doit )
		{
			slap_callback *cb = op->o_tmpcalloc(1,
				sizeof(slap_callback)+sizeof(opcookie), op->o_tmpmemctx);
			opcookie *opc = (opcookie *)(cb+1);
			opc->son = on;
			cb->sc_response = syncprov_op_response;
			cb->sc_private = opc;
			cb->sc_next = op->o_callback;
			op->o_callback = cb;
		}
	}

	return SLAP_CB_CONTINUE;
}

static int
syncprov_response( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = (syncprov_info_t *)on->on_bi.bi_private;

	/* If the operation succeeded and we're checkpointing */
	if ( rs->sr_err == LDAP_SUCCESS && ( si->si_chkops || si->si_chktime ))
	{
		int do_check = 0;

		switch ( op->o_tag ) {
		case LDAP_REQ_EXTENDED:
			/* if not PASSWD_MODIFY, break */
			/* else fallthru */
		case LDAP_REQ_ADD:
		case LDAP_REQ_MODIFY:
		case LDAP_REQ_MODRDN:
		case LDAP_REQ_DELETE:
			ldap_pvt_thread_mutex_lock( &si->si_chk_mutex );
			if ( si->si_chkops )
			{
				si->si_numops++;
				if ( si->si_numops >= si->si_chkops )
				{
					do_check = 1;
					si->si_numops = 0;
				}
			}
			if ( si->si_chktime )
			{
				if ( op->o_time - si->si_chklast >= si->si_chktime )
				{
					do_check = 1;
					si->si_chklast = op->o_time;
				}
			}
			ldap_pvt_thread_mutex_unlock( &si->si_chk_mutex );
			if ( do_check )
			{
				/* write cn=ldapsync to underlying db */
			}
			break;
		}
	}
	return SLAP_CB_CONTINUE;
}

static int
syncprov_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char	**argv
)
{
	slap_overinst		*on = (slap_overinst *)be->bd_info;
	syncprov_info_t		*si = (syncprov_info_t *)on->on_bi.bi_private;

	if ( strcasecmp( argv[ 0 ], "syncprov-checkpoint" ) == 0 ) {
		if ( argc != 3 ) {
			fprintf( stderr, "%s: line %d: wrong number of arguments in "
				"\"syncprov-checkpint <ops> <minutes>\"\n", fname, lineno );
			return -1;
		}
		si->si_chkops = atoi( argv[1] );
		si->si_chktime = atoi( argv[2] ) * 60;

	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}

/* Read any existing cn=ldapsync context from the underlying db.
 * Then search for any entries newer than that. If no value exists,
 * just generate it. Cache whatever result.
 */
static int
syncprov_db_open(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	syncprov_info_t	*si = (syncprov_info_t *)on->on_bi.bi_private;

	return 0;
}

/* Write the current cn=ldapsync context into the underlying db.
 */
static int
syncprov_db_close(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	syncprov_info_t	*si = (syncprov_info_t *)on->on_bi.bi_private;

	/* for si->si_ops:
	 *   send DONE messages
	 *   free si_ops
	 */
	return 0;
}

static int
syncprov_db_init(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	syncprov_info_t	*si;

	si = ch_calloc(1, sizeof(syncprov_info_t));
	on->on_bi.bi_private = si;

	ldap_pvt_thread_mutex_init( &si->si_e_mutex );
	ldap_pvt_thread_mutex_init( &si->si_ops_mutex );
	ldap_pvt_thread_mutex_init( &si->si_chk_mutex );

	return 0;
}

static int
syncprov_db_destroy(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	syncprov_info_t	*si = (syncprov_info_t *)on->on_bi.bi_private;

	if ( si ) {
		if ( si->si_e ) {
			entry_free( si->si_e );

		}
		ldap_pvt_thread_mutex_destroy( &si->si_chk_mutex );
		ldap_pvt_thread_mutex_destroy( &si->si_ops_mutex );
		ldap_pvt_thread_mutex_destroy( &si->si_e_mutex );

		ch_free( si );
	}

	return 0;
}

/* This overlay is set up for dynamic loading via moduleload. For static
 * configuration, you'll need to arrange for the slap_overinst to be
 * initialized and registered by some other function inside slapd.
 */

static slap_overinst 		syncprov;

int
syncprov_init()
{
	syncprov.on_bi.bi_type = "syncprov";
	syncprov.on_bi.bi_db_init = syncprov_db_init;
	syncprov.on_bi.bi_db_config = syncprov_db_config;
	syncprov.on_bi.bi_db_destroy = syncprov_db_destroy;
	syncprov.on_bi.bi_db_open = syncprov_db_open;
	syncprov.on_bi.bi_db_close = syncprov_db_close;

	syncprov.on_bi.bi_op_add = syncprov_op_add;
	syncprov.on_bi.bi_op_compare = syncprov_op_compare;
	syncprov.on_bi.bi_op_delete = syncprov_op_delete;
	syncprov.on_bi.bi_op_modify = syncprov_op_modify;
	syncprov.on_bi.bi_op_modrdn = syncprov_op_modrdn;
	syncprov.on_bi.bi_op_search = syncprov_op_search;
	syncprov.on_bi.bi_extended = syncprov_op_extended;

	syncprov.on_response = syncprov_response;

	return overlay_register( &syncprov );
}

#if SLAPD_OVER_SYNCPROV == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return syncprov_init();
}
#endif /* SLAPD_OVER_SYNCPROV == SLAPD_MOD_DYNAMIC */

#endif /* defined(SLAPD_OVER_SYNCPROV) */

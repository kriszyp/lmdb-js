/* sessionlog.c -- Session History Management Routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
 * Portions Copyright 2003 IBM Corporation.
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
#include <ac/socket.h>

#include "lutil.h"
#include "slap.h"
#include "lutil_ldap.h"

#if 0
int
slap_send_session_log(
	Operation *op,
	Operation *sop,
	SlapReply *rs
)
{
	Entry e;
	AttributeName	uuid_attr[2];
	LDAPControl *ctrls[SLAP_MAX_RESPONSE_CONTROLS];
	int		num_ctrls = 0;
	struct slog_entry *slog_e;
	int		result;
	int		match;
	const	char	*text;

	uuid_attr[0].an_desc = NULL;
	uuid_attr[0].an_oc = NULL;
	uuid_attr[0].an_oc_exclude = 0;
	uuid_attr[0].an_name.bv_len = 0;
	uuid_attr[0].an_name.bv_val = NULL;
	e.e_attrs = NULL;
	e.e_id = 0;
	e.e_name.bv_val = NULL;
	e.e_name.bv_len = 0;
	e.e_nname.bv_val = NULL;
	e.e_nname.bv_len = 0;

	for( num_ctrls = 0;
		 num_ctrls < SLAP_MAX_RESPONSE_CONTROLS;
		 num_ctrls++ ) {
		ctrls[num_ctrls] = NULL;
	}
	num_ctrls = 0;

	LDAP_STAILQ_FOREACH( slog_e, &sop->o_sync_slog_list, sl_link ) {

		if ( op->o_sync_state.ctxcsn->bv_val == NULL ) {
			match = 1;
		} else {
			value_match( &match, slap_schema.si_ad_entryCSN,
						slap_schema.si_ad_entryCSN->ad_type->sat_ordering,
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						op->o_sync_state.ctxcsn, &slog_e->sl_csn, &text );
		}

		if ( match < 0 ) {
			rs->sr_err = slap_build_sync_state_ctrl_from_slog( op, rs, slog_e,
							LDAP_SYNC_DELETE, ctrls, num_ctrls++, 0, NULL );

			if ( rs->sr_err != LDAP_SUCCESS )
				return rs->sr_err;

			if ( e.e_name.bv_val )
				ch_free( e.e_name.bv_val );
			ber_dupbv( &e.e_name, &slog_e->sl_name );

			rs->sr_entry = &e;
			rs->sr_attrs = uuid_attr;
			rs->sr_ctrls = ctrls;
			rs->sr_flags = 0;
			result = send_search_entry( op, rs );
			slap_sl_free( ctrls[num_ctrls-1]->ldctl_value.bv_val, op->o_tmpmemctx );
			slap_sl_free( ctrls[--num_ctrls], op->o_tmpmemctx );
			ctrls[num_ctrls] = NULL;
			rs->sr_ctrls = NULL;
		}
	}
	return LDAP_SUCCESS;
}

int
slap_add_session_log(
	Operation *op,
	Operation *sop,
	Entry *e
)
{
	struct slog_entry* slog_e;
	Attribute *a;

	slog_e = (struct slog_entry *) ch_calloc (1, sizeof( struct slog_entry ));
	a = attr_find( e->e_attrs, slap_schema.si_ad_entryUUID );
	ber_dupbv( &slog_e->sl_uuid, &a->a_nvals[0] );
	ber_dupbv( &slog_e->sl_name, &e->e_name );
	ber_dupbv( &slog_e->sl_csn,  &op->o_sync_csn );
	LDAP_STAILQ_INSERT_TAIL( &sop->o_sync_slog_list, slog_e, sl_link );
	sop->o_sync_slog_len++;

	while ( sop->o_sync_slog_len > sop->o_sync_slog_size ) {
		slog_e = LDAP_STAILQ_FIRST( &sop->o_sync_slog_list );
		if ( sop->o_sync_slog_omitcsn.bv_val ) {
			ch_free( sop->o_sync_slog_omitcsn.bv_val );
		}
		ber_dupbv( &sop->o_sync_slog_omitcsn, &slog_e->sl_csn );
		LDAP_STAILQ_REMOVE_HEAD( &sop->o_sync_slog_list, sl_link );
		ch_free( slog_e->sl_uuid.bv_val );
		ch_free( slog_e->sl_name.bv_val );
		ch_free( slog_e->sl_csn.bv_val );
		ch_free( slog_e );
		sop->o_sync_slog_len--;
	}

	return LDAP_SUCCESS;
}
#endif

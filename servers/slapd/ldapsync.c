/* ldapsync.c -- LDAP Content Sync Routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003 The OpenLDAP Foundation.
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

#include "ldap_pvt.h"
#include "lutil.h"
#include "slap.h"
#include "lutil_ldap.h"

int
slap_build_sync_state_ctrl(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	int			entry_sync_state,
	LDAPControl	**ctrls,
	int			num_ctrls,
	int			send_cookie,
	struct berval	*cookie)
{
	Attribute* a;
	int ret;
	int res;
	const char *text = NULL;

	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;

	struct berval entryuuid_bv	= { 0, NULL };

	ber_init2( ber, 0, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	ctrls[num_ctrls] = sl_malloc ( sizeof ( LDAPControl ), op->o_tmpmemctx );

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		AttributeDescription *desc = a->a_desc;
		if ( desc == slap_schema.si_ad_entryUUID ) {
			ber_dupbv( &entryuuid_bv, &a->a_nvals[0] );
		}
	}

	if ( send_cookie && cookie ) {
		ber_printf( ber, "{eOON}",
			entry_sync_state, &entryuuid_bv, cookie );
	} else {
		ber_printf( ber, "{eON}",
			entry_sync_state, &entryuuid_bv );
	}

	ch_free( entryuuid_bv.bv_val );
	entryuuid_bv.bv_val = NULL;

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_SYNC_STATE;
	ctrls[num_ctrls]->ldctl_iscritical = op->o_sync;
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"slap_build_sync_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_build_sync_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}

int
slap_build_sync_done_ctrl(
	Operation	*op,
	SlapReply	*rs,
	LDAPControl	**ctrls,
	int			num_ctrls,
	int			send_cookie,
	struct berval *cookie,
	int			refreshDeletes )
{
	int ret;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;

	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	ctrls[num_ctrls] = ch_malloc ( sizeof ( LDAPControl ) );

	ber_printf( ber, "{" );
	if ( send_cookie && cookie ) {
		ber_printf( ber, "O", cookie );
	}
	if ( refreshDeletes == LDAP_SYNC_REFRESH_DELETES ) {
		ber_printf( ber, "b", refreshDeletes );
	}
	ber_printf( ber, "N}" );	

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_SYNC_DONE;
	ctrls[num_ctrls]->ldctl_iscritical = op->o_sync;
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"slap_build_sync_done_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_build_sync_done_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}


int
slap_build_sync_state_ctrl_from_slog(
	Operation	*op,
	SlapReply	*rs,
	struct slog_entry *slog_e,
	int			entry_sync_state,
	LDAPControl	**ctrls,
	int			num_ctrls,
	int			send_cookie,
	struct berval	*cookie)
{
	Attribute* a;
	int ret;
	int res;
	const char *text = NULL;

	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;

	struct berval entryuuid_bv	= { 0, NULL };

	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	ctrls[num_ctrls] = ch_malloc ( sizeof ( LDAPControl ) );

	ber_dupbv( &entryuuid_bv, &slog_e->sl_uuid );

	if ( send_cookie && cookie ) {
		ber_printf( ber, "{eOON}",
			entry_sync_state, &entryuuid_bv, cookie );
	} else {
		ber_printf( ber, "{eON}",
			entry_sync_state, &entryuuid_bv );
	}

	ch_free( entryuuid_bv.bv_val );
	entryuuid_bv.bv_val = NULL;

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_SYNC_STATE;
	ctrls[num_ctrls]->ldctl_iscritical = op->o_sync;
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"slap_build_sync_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_build_sync_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}

int
slap_send_syncinfo(
	Operation	*op,
	SlapReply	*rs,
	int			type,
	struct berval *cookie,
	int			refreshDone,
	BerVarray	syncUUIDs,
	int			refreshDeletes )
{
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	struct berval rspdata;

	int ret;

	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	if ( type ) {
		switch ( type ) {
		case LDAP_TAG_SYNC_NEW_COOKIE:
			ber_printf( ber, "tO", type, cookie );
			break;
		case LDAP_TAG_SYNC_REFRESH_DELETE:
		case LDAP_TAG_SYNC_REFRESH_PRESENT:
			ber_printf( ber, "t{", type );
			if ( cookie ) {
				ber_printf( ber, "O", cookie );
			}
			if ( refreshDone == 0 ) {
				ber_printf( ber, "b", refreshDone );
			}
			ber_printf( ber, "N}" );
			break;
		case LDAP_TAG_SYNC_ID_SET:
			ber_printf( ber, "t{", type );
			if ( cookie ) {
				ber_printf( ber, "O", cookie );
			}
			if ( refreshDeletes == 1 ) {
				ber_printf( ber, "b", refreshDeletes );
			}
			ber_printf( ber, "[W]", syncUUIDs );
			ber_printf( ber, "N}" );
			break;
		default:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, RESULTS,
				"slap_send_syncinfo: invalid syncinfo type (%d)\n",
				type, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"slap_send_syncinfo: invalid syncinfo type (%d)\n",
				type, 0, 0 );
#endif
			return LDAP_OTHER;
		}
	}

	ret = ber_flatten2( ber, &rspdata, 0 );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS,
			"slap_send_syncinfo: ber_flatten2 failed\n",
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_send_syncinfo: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	rs->sr_rspdata = &rspdata;
	send_ldap_intermediate( op, rs );
	rs->sr_rspdata = NULL;
	ber_free_buf( ber );

	return LDAP_SUCCESS;
}

void
slap_compose_sync_cookie(
	Operation *op,
	struct berval *cookie,
	struct berval *csn,
	int sid,
	int rid )
{
	char cookiestr[ LDAP_LUTIL_CSNSTR_BUFSIZE + 20 ];

	if ( csn->bv_val == NULL ) {
		if ( sid == -1 ) {
			if ( rid == -1 ) {
				cookiestr[0] = '\0';
			} else {
				snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
						"rid=%03d", rid );
			}
		} else {
			if ( rid == -1 ) {
				snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
						"sid=%03d", sid );
			} else {
				snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
						"sid=%03d,rid=%03d", sid, rid );
			}
		}
	} else {
		if ( sid == -1 ) {
			if ( rid == -1 ) {
				snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
						"csn=%s", csn->bv_val );
			} else {
				snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
						"csn=%s,rid=%03d", csn->bv_val, rid );
			}
		} else {
			if ( rid == -1 ) {
				snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
						"csn=%s,sid=%03d", csn->bv_val, sid );
			} else {
				snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
						"csn=%s,sid=%03d,rid=%03d", csn->bv_val, sid, rid );
			}
		}
	}
	ber_str2bv( cookiestr, strlen(cookiestr), 1, cookie );
}

void
slap_sync_cookie_free(
	struct sync_cookie *cookie,
	int free_cookie
)
{
	if ( cookie == NULL )
		return;

	if ( cookie->ctxcsn ) {
		ber_bvarray_free( cookie->ctxcsn );
		cookie->ctxcsn = NULL;
	}

	if ( cookie->octet_str ) {
		ber_bvarray_free( cookie->octet_str );
		cookie->octet_str = NULL;
	}

	if ( free_cookie ) {
		ch_free( cookie );
	}

	return;
}

int
slap_parse_sync_cookie(
	struct sync_cookie *cookie
)
{
	char *csn_ptr;
	char *csn_str;
	int csn_str_len;
	char *sid_ptr;
	char *sid_str;
	char *rid_ptr;
	char *rid_str;
	char *cval;
	struct berval *ctxcsn;

	if ( cookie == NULL )
		return -1;

	if (( csn_ptr = strstr( cookie->octet_str[0].bv_val, "csn=" )) != NULL ) {
		csn_str = (char *) SLAP_STRNDUP( csn_ptr, LDAP_LUTIL_CSNSTR_BUFSIZE );
		if ( cval = strchr( csn_str, ',' )) {
			*cval = '\0';
			csn_str_len = cval - csn_str - (sizeof("csn=") - 1);
		} else {
			csn_str_len = cookie->octet_str[0].bv_len -
							(csn_ptr - cookie->octet_str[0].bv_val) -
							(sizeof("csn=") - 1);
		}
		ctxcsn = ber_str2bv( csn_str + (sizeof("csn=")-1),
							 csn_str_len, 1, NULL );
		ch_free( csn_str );
		ber_bvarray_add( &cookie->ctxcsn, ctxcsn );
		ch_free( ctxcsn );
	} else {
		cookie->ctxcsn = NULL;
	}

	if (( sid_ptr = strstr( cookie->octet_str->bv_val, "sid=" )) != NULL ) {
		sid_str = (char *) SLAP_STRNDUP( sid_ptr,
							SLAP_SYNC_SID_SIZE + sizeof("sid=") - 1 );
		if ( cval = strchr( sid_str, ',' )) {
			*cval = '\0';
		}
		cookie->sid = atoi( sid_str + sizeof("sid=") - 1 );
		ch_free( sid_str );
	} else {
		cookie->sid = -1;
	}

	if (( rid_ptr = strstr( cookie->octet_str->bv_val, "rid=" )) != NULL ) {
		rid_str = (char *) SLAP_STRNDUP( rid_ptr,
							SLAP_SYNC_RID_SIZE + sizeof("rid=") - 1 );
		if ( cval = strchr( rid_str, ',' )) {
			*cval = '\0';
		}
		cookie->rid = atoi( rid_str + sizeof("rid=") - 1 );
		ch_free( rid_str );
	} else {
		cookie->rid = -1;
	}
}

int
slap_init_sync_cookie_ctxcsn(
	struct sync_cookie *cookie
)
{
	char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE + 4 ];
	struct berval octet_str = { 0, NULL };
	struct berval ctxcsn = { 0, NULL };
	struct berval ctxcsn_dup = { 0, NULL };
	struct berval slap_syncCookie;

	if ( cookie == NULL )
		return -1;

	octet_str.bv_len = snprintf( csnbuf, LDAP_LUTIL_CSNSTR_BUFSIZE + 4,
					"csn=%4d%02d%02d%02d%02d%02dZ#%06x#%02x#%06x",
					1900, 1, 1, 0, 0, 0, 0, 0, 0 );
	octet_str.bv_val = csnbuf;
	build_new_dn( &slap_syncCookie, &cookie->octet_str[0], &octet_str, NULL );
	ber_bvarray_free( cookie->octet_str );
	cookie->octet_str = NULL;
	ber_bvarray_add( &cookie->octet_str, &slap_syncCookie );

	ber_dupbv( &ctxcsn, &octet_str );
	ctxcsn.bv_val += 4;
	ctxcsn.bv_len -= 4;
	ber_dupbv( &ctxcsn_dup, &ctxcsn );
	ch_free( ctxcsn.bv_val );
	ber_bvarray_add( &cookie->ctxcsn, &ctxcsn_dup );

	return 0;
}

struct sync_cookie *
slap_dup_sync_cookie(
	struct sync_cookie *dst,
	struct sync_cookie *src
)
{
	int i;
	struct sync_cookie *new;
	struct berval tmp_bv;

	if ( src == NULL )
		return NULL;

	if ( dst ) {
		ber_bvarray_free( dst->ctxcsn );
		ber_bvarray_free( dst->octet_str );
		new = dst;
	} else {
		new = ( struct sync_cookie * )
				ch_calloc( 1, sizeof( struct sync_cookie ));
	}

	new->sid = src->sid;
	new->rid = src->rid;

	if ( src->ctxcsn ) {
		for ( i=0; src->ctxcsn[i].bv_val; i++ ) {
			ber_dupbv( &tmp_bv, &src->ctxcsn[i] );
			ber_bvarray_add( &new->ctxcsn, &tmp_bv );
		}
	}

	if ( src->octet_str ) {
		for ( i=0; src->octet_str[i].bv_val; i++ ) {
			ber_dupbv( &tmp_bv, &src->octet_str[i] );
			ber_bvarray_add( &new->octet_str, &tmp_bv );
		}
	}

	return new;
}

int
slap_build_syncUUID_set(
	Operation *op,
	BerVarray *set,
	Entry *e
)
{
	int ret;
	Attribute* a;

	struct berval entryuuid_bv	= { 0, NULL };

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		AttributeDescription *desc = a->a_desc;
		if ( desc == slap_schema.si_ad_entryUUID ) {
			ber_dupbv_x( &entryuuid_bv, &a->a_nvals[0], op->o_tmpmemctx );
		}
	}

	ret = ber_bvarray_add_x( set, &entryuuid_bv, op->o_tmpmemctx );

	return ret;
}

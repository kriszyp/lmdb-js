/* result.c - routines to send ldap results, errors, and referrals */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "slap.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

const struct berval slap_dummy_bv = BER_BVNULL;

int slap_null_cb( Operation *op, SlapReply *rs )
{
	return 0;
}

int slap_freeself_cb( Operation *op, SlapReply *rs )
{
	assert( op->o_callback );

	op->o_tmpfree( op->o_callback, op->o_tmpmemctx );
	op->o_callback = NULL;

	return SLAP_CB_CONTINUE;
}

int slap_replog_cb( Operation *op, SlapReply *rs )
{
	if ( rs->sr_err == LDAP_SUCCESS ) {
		replog( op );
	}
	return SLAP_CB_CONTINUE;
}

static char *v2ref( BerVarray ref, const char *text )
{
	size_t len = 0, i = 0;
	char *v2;

	if(ref == NULL) {
		if (text) {
			return ch_strdup(text);
		} else {
			return NULL;
		}
	}
	
	if ( text != NULL ) {
		len = strlen( text );
		if (text[len-1] != '\n') {
		    i = 1;
		}
	}

	v2 = SLAP_MALLOC( len+i+sizeof("Referral:") );
	if( v2 == NULL ) {
		Debug( LDAP_DEBUG_ANY, "v2ref: SLAP_MALLOC failed", 0, 0, 0 );
		return NULL;
	}

	if( text != NULL ) {
		strcpy(v2, text);
		if( i ) {
			v2[len++] = '\n';
		}
	}
	strcpy( v2+len, "Referral:" );
	len += sizeof("Referral:");

	for( i=0; ref[i].bv_val != NULL; i++ ) {
		v2 = SLAP_REALLOC( v2, len + ref[i].bv_len + 1 );
		if( v2 == NULL ) {
			Debug( LDAP_DEBUG_ANY, "v2ref: SLAP_MALLOC failed", 0, 0, 0 );
			return NULL;
		}
		v2[len-1] = '\n';
		AC_MEMCPY(&v2[len], ref[i].bv_val, ref[i].bv_len );
		len += ref[i].bv_len;
		if (ref[i].bv_val[ref[i].bv_len-1] != '/') {
			++len;
		}
	}

	v2[len-1] = '\0';
	return v2;
}

static ber_tag_t req2res( ber_tag_t tag )
{
	switch( tag ) {
	case LDAP_REQ_ADD:
	case LDAP_REQ_BIND:
	case LDAP_REQ_COMPARE:
	case LDAP_REQ_EXTENDED:
	case LDAP_REQ_MODIFY:
	case LDAP_REQ_MODRDN:
		tag++;
		break;

	case LDAP_REQ_DELETE:
		tag = LDAP_RES_DELETE;
		break;

	case LDAP_REQ_ABANDON:
	case LDAP_REQ_UNBIND:
		tag = LBER_SEQUENCE;
		break;

	case LDAP_REQ_SEARCH:
		tag = LDAP_RES_SEARCH_RESULT;
		break;

	default:
		tag = LBER_SEQUENCE;
	}

	return tag;
}

static long send_ldap_ber(
	Connection *conn,
	BerElement *ber )
{
	ber_len_t bytes;

	ber_get_option( ber, LBER_OPT_BER_BYTES_TO_WRITE, &bytes );

	/* write only one pdu at a time - wait til it's our turn */
	ldap_pvt_thread_mutex_lock( &conn->c_write_mutex );

	/* lock the connection */ 
	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	/* write the pdu */
	while( 1 ) {
		int err;
		ber_socket_t	sd;

		if ( connection_state_closing( conn ) ) {
			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
			ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );

			return 0;
		}

		if ( ber_flush( conn->c_sb, ber, 0 ) == 0 ) {
			break;
		}

		err = errno;

		/*
		 * we got an error.  if it's ewouldblock, we need to
		 * wait on the socket being writable.  otherwise, figure
		 * it's a hard error and return.
		 */

		Debug( LDAP_DEBUG_CONNS, "ber_flush failed errno=%d reason=\"%s\"\n",
		    err, sock_errstr(err), 0 );

		if ( err != EWOULDBLOCK && err != EAGAIN ) {
			connection_closing( conn );

			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
			ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );

			return( -1 );
		}

		/* wait for socket to be write-ready */
		conn->c_writewaiter = 1;
		ber_sockbuf_ctrl( conn->c_sb, LBER_SB_OPT_GET_FD, &sd );
		slapd_set_write( sd, 1 );

		ldap_pvt_thread_cond_wait( &conn->c_write_cv, &conn->c_mutex );
		conn->c_writewaiter = 0;
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
	ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );

	return bytes;
}

static int
send_ldap_control( BerElement *ber, LDAPControl *c )
{
	int rc;

	assert( c != NULL );

	rc = ber_printf( ber, "{s" /*}*/, c->ldctl_oid );

	if( c->ldctl_iscritical ) {
		rc = ber_printf( ber, "b",
			(ber_int_t) c->ldctl_iscritical ) ;
		if( rc == -1 ) return rc;
	}

	if( c->ldctl_value.bv_val != NULL ) {
		rc = ber_printf( ber, "O", &c->ldctl_value ); 
		if( rc == -1 ) return rc;
	}

	rc = ber_printf( ber, /*{*/"N}" );
	if( rc == -1 ) return rc;

	return 0;
}

static int
send_ldap_controls( Operation *o, BerElement *ber, LDAPControl **c )
{
	int rc;
#ifdef LDAP_SLAPI
	LDAPControl **sctrls = NULL;

	/*
	 * Retrieve any additional controls that may be set by the
	 * plugin.
	 */

	if ( o->o_pb && slapi_pblock_get( o->o_pb, SLAPI_RESCONTROLS, &sctrls ) != 0 ) {
		sctrls = NULL;
	}

	if ( c == NULL && sctrls == NULL ) return 0;
#else
	if( c == NULL ) return 0;
#endif /* LDAP_SLAPI */

	rc = ber_printf( ber, "t{"/*}*/, LDAP_TAG_CONTROLS );
	if( rc == -1 ) return rc;

#ifdef LDAP_SLAPI
	if ( c != NULL )
#endif /* LDAP_SLAPI */
	for( ; *c != NULL; c++) {
		rc = send_ldap_control( ber, *c );
		if( rc == -1 ) return rc;
	}

#ifdef LDAP_SLAPI
	if ( sctrls != NULL ) {
		for ( c = sctrls; *c != NULL; c++ ) {
			rc = send_ldap_control( ber, *c );
			if( rc == -1 ) return rc;
		}
	}
#endif /* LDAP_SLAPI */

	rc = ber_printf( ber, /*{*/"N}" );

	return rc;
}

static int
send_ldap_response(
	Operation *op,
	SlapReply *rs )
{
	BerElementBuffer berbuf;
	BerElement	*ber = (BerElement *) &berbuf;
	int		rc = LDAP_SUCCESS;
	long	bytes;

	if ( op->o_callback ) {
		int		first = 1;
		slap_callback	*sc = op->o_callback,
				*sc_next = op->o_callback;

		rc = SLAP_CB_CONTINUE;
		for ( sc_next = op->o_callback; sc_next; op->o_callback = sc_next) {
			sc_next = op->o_callback->sc_next;
			if ( op->o_callback->sc_response ) {
				rc = op->o_callback->sc_response( op, rs );
				if ( first && op->o_callback == NULL ) {
					sc = NULL;
				}
				if ( rc != SLAP_CB_CONTINUE ) break;
			}
			first = 0;
		}

		op->o_callback = sc;
		if ( rc != SLAP_CB_CONTINUE ) goto clean2;
	}

#ifdef LDAP_CONNECTIONLESS
	if (op->o_conn && op->o_conn->c_is_udp)
		ber = op->o_res_ber;
	else
#endif
	{
		ber_init_w_nullc( ber, LBER_USE_DER );
		ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );
	}

	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_response: msgid=%d tag=%lu err=%d\n",
		rs->sr_msgid, rs->sr_tag, rs->sr_err );

	if( rs->sr_ref ) {
		Debug( LDAP_DEBUG_ARGS, "send_ldap_response: ref=\"%s\"\n",
			rs->sr_ref[0].bv_val ? rs->sr_ref[0].bv_val : "NULL",
			NULL, NULL );
	}

#ifdef LDAP_CONNECTIONLESS
	if (op->o_conn && op->o_conn->c_is_udp &&
		op->o_protocol == LDAP_VERSION2 )
	{
		rc = ber_printf( ber, "t{ess" /*"}"*/,
			rs->sr_tag, rs->sr_err,
		rs->sr_matched == NULL ? "" : rs->sr_matched,
		rs->sr_text == NULL ? "" : rs->sr_text );
	} else 
#endif
	if ( rs->sr_type == REP_INTERMEDIATE ) {
	    rc = ber_printf( ber, "{it{" /*"}}"*/,
			rs->sr_msgid, rs->sr_tag );

	} else {
	    rc = ber_printf( ber, "{it{ess" /*"}}"*/,
		rs->sr_msgid, rs->sr_tag, rs->sr_err,
		rs->sr_matched == NULL ? "" : rs->sr_matched,
		rs->sr_text == NULL ? "" : rs->sr_text );
	}

	if( rc != -1 ) {
		if ( rs->sr_ref != NULL ) {
			assert( rs->sr_err == LDAP_REFERRAL );
			rc = ber_printf( ber, "t{W}",
				LDAP_TAG_REFERRAL, rs->sr_ref );
		} else {
			assert( rs->sr_err != LDAP_REFERRAL );
		}
	}

	if( rc != -1 && rs->sr_type == REP_SASL && rs->sr_sasldata != NULL ) {
		rc = ber_printf( ber, "tO",
			LDAP_TAG_SASL_RES_CREDS, rs->sr_sasldata );
	}

	if( rc != -1 &&
		( rs->sr_type == REP_EXTENDED || rs->sr_type == REP_INTERMEDIATE ))
	{
		if ( rs->sr_rspoid != NULL ) {
			rc = ber_printf( ber, "ts",
				LDAP_TAG_EXOP_RES_OID, rs->sr_rspoid );
		}
		if( rc != -1 && rs->sr_rspdata != NULL ) {
			rc = ber_printf( ber, "tO",
				LDAP_TAG_EXOP_RES_VALUE, rs->sr_rspdata );
		}
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}

	if( rc != -1 ) {
		rc = send_ldap_controls( op, ber, rs->sr_ctrls );
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}

#ifdef LDAP_CONNECTIONLESS
	if( op->o_conn && op->o_conn->c_is_udp && op->o_protocol == LDAP_VERSION2
		&& rc != -1 )
	{
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}
#endif
		
	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );

#ifdef LDAP_CONNECTIONLESS
		if (!op->o_conn || op->o_conn->c_is_udp == 0)
#endif
		{
			ber_free_buf( ber );
		}
		goto cleanup;
	}

	/* send BER */
	bytes = send_ldap_ber( op->o_conn, ber );
#ifdef LDAP_CONNECTIONLESS
	if (!op->o_conn || op->o_conn->c_is_udp == 0)
#endif
	{
		ber_free_buf( ber );
	}

	if ( bytes < 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"send_ldap_response: ber write failed\n",
			0, 0, 0 );

		goto cleanup;
	}

#ifdef LDAP_SLAPI
	if ( op->o_pb ) {
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_CODE, (void *)rs->sr_err );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_MATCHED,
			(void *)rs->sr_matched );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_TEXT, (void *)rs->sr_text );
	}
#endif /* LDAP_SLAPI */

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_pdu_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );

cleanup:;
	/* Tell caller that we did this for real, as opposed to being
	 * overridden by a callback
	 */
	rc = SLAP_CB_CONTINUE;

clean2:;
	if ( op->o_callback ) {
		int		first = 1;
		slap_callback	*sc = op->o_callback,
				*sc_next = op->o_callback;

		for ( sc_next = op->o_callback; sc_next; op->o_callback = sc_next) {
			sc_next = op->o_callback->sc_next;
			if ( op->o_callback->sc_cleanup ) {
				(void)op->o_callback->sc_cleanup( op, rs );
				if ( first && op->o_callback == NULL ) {
					sc = NULL;
				}
			}
			first = 0;
		}

		op->o_callback = sc;
	}


	if ( rs->sr_matched && rs->sr_flags & REP_MATCHED_MUSTBEFREED ) {
		free( (char *)rs->sr_matched );
		rs->sr_matched = NULL;
	}

	if ( rs->sr_ref && rs->sr_flags & REP_REF_MUSTBEFREED ) {
		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
	}

	return rc;
}


void
send_ldap_disconnect( Operation	*op, SlapReply *rs )
{
#define LDAP_UNSOLICITED_ERROR(e) \
	(  (e) == LDAP_PROTOCOL_ERROR \
	|| (e) == LDAP_STRONG_AUTH_REQUIRED \
	|| (e) == LDAP_UNAVAILABLE )

	assert( LDAP_UNSOLICITED_ERROR( rs->sr_err ) );

	rs->sr_type = REP_EXTENDED;

	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_disconnect %d:%s\n",
		rs->sr_err, rs->sr_text ? rs->sr_text : "", NULL );

	if ( op->o_protocol < LDAP_VERSION3 ) {
		rs->sr_rspoid = NULL;
		rs->sr_tag = req2res( op->o_tag );
		rs->sr_msgid = (rs->sr_tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	} else {
		rs->sr_rspoid = LDAP_NOTICE_DISCONNECT;
		rs->sr_tag = LDAP_RES_EXTENDED;
		rs->sr_msgid = 0;
	}

	if ( send_ldap_response( op, rs ) == SLAP_CB_CONTINUE ) {
		Statslog( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu DISCONNECT tag=%lu err=%d text=%s\n",
			op->o_connid, op->o_opid, rs->sr_tag, rs->sr_err,
			rs->sr_text ? rs->sr_text : "" );
	}
}

void
slap_send_ldap_result( Operation *op, SlapReply *rs )
{
	char *tmp = NULL;
	const char *otext = rs->sr_text;
	BerVarray oref = rs->sr_ref;

	rs->sr_type = REP_RESULT;

	assert( !LDAP_API_ERROR( rs->sr_err ));

	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_result: conn=%lu op=%lu p=%d\n",
		op->o_connid, op->o_opid, op->o_protocol );

	Debug( LDAP_DEBUG_ARGS,
		"send_ldap_result: err=%d matched=\"%s\" text=\"%s\"\n",
		rs->sr_err, rs->sr_matched ? rs->sr_matched : "",
		rs->sr_text ? rs->sr_text : "" );


	if( rs->sr_ref ) {
		Debug( LDAP_DEBUG_ARGS,
			"send_ldap_result: referral=\"%s\"\n",
			rs->sr_ref[0].bv_val ? rs->sr_ref[0].bv_val : "NULL",
			NULL, NULL );
	}

	assert( rs->sr_err != LDAP_PARTIAL_RESULTS );

	if ( rs->sr_err == LDAP_REFERRAL ) {
#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
		if( op->o_domain_scope ) {
			rs->sr_ref = NULL;
		}
#endif
		if( rs->sr_ref == NULL ) {
			rs->sr_err = LDAP_NO_SUCH_OBJECT;
		} else if ( op->o_protocol < LDAP_VERSION3 ) {
			rs->sr_err = LDAP_PARTIAL_RESULTS;
		}
	}

#ifdef LDAP_SLAPI
	/*
	 * Call pre-result plugins. To avoid infinite recursion plugins
	 * should just set SLAPI_RESULT_CODE rather than sending a
	 * result if they wish to change the result.
	 */
	if ( op->o_pb != NULL ) {
		slapi_int_pblock_set_operation( op->o_pb, op );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_CODE,
			(void *)rs->sr_err );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_TEXT,
			(void *)rs->sr_text );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_MATCHED,
			(void *)rs->sr_matched );

		(void) slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_PRE_RESULT_FN,
			op->o_pb );
	}
#endif /* LDAP_SLAPI */

	if ( op->o_protocol < LDAP_VERSION3 ) {
		tmp = v2ref( rs->sr_ref, rs->sr_text );
		rs->sr_text = tmp;
		rs->sr_ref = NULL;
	}

	rs->sr_tag = req2res( op->o_tag );
	rs->sr_msgid = (rs->sr_tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	if ( send_ldap_response( op, rs ) == SLAP_CB_CONTINUE ) {
		if ( op->o_tag == LDAP_REQ_SEARCH ) {
			char nbuf[64];
			snprintf( nbuf, sizeof nbuf, "%d nentries=%d",
				rs->sr_err, rs->sr_nentries );

			Statslog( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu SEARCH RESULT tag=%lu err=%s text=%s\n",
				op->o_connid, op->o_opid, rs->sr_tag, nbuf,
				rs->sr_text ? rs->sr_text : "" );
		} else {
			Statslog( LDAP_DEBUG_STATS,
				"conn=%lu op=%lu RESULT tag=%lu err=%d text=%s\n",
				op->o_connid, op->o_opid, rs->sr_tag, rs->sr_err,
				rs->sr_text ? rs->sr_text : "" );
		}
	}

	if( tmp != NULL ) ch_free(tmp);
	rs->sr_text = otext;
	rs->sr_ref = oref;
}

void
send_ldap_sasl( Operation *op, SlapReply *rs )
{
	rs->sr_type = REP_SASL;
	Debug( LDAP_DEBUG_TRACE, "send_ldap_sasl: err=%d len=%ld\n",
		rs->sr_err,
		rs->sr_sasldata ? (long) rs->sr_sasldata->bv_len : -1, NULL );

	rs->sr_tag = req2res( op->o_tag );
	rs->sr_msgid = (rs->sr_tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( op, rs );
}

void
slap_send_ldap_extended( Operation *op, SlapReply *rs )
{
	rs->sr_type = REP_EXTENDED;

	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_extended: err=%d oid=%s len=%ld\n",
		rs->sr_err,
		rs->sr_rspoid ? rs->sr_rspoid : "",
		rs->sr_rspdata != NULL ? rs->sr_rspdata->bv_len : 0 );

	rs->sr_tag = req2res( op->o_tag );
	rs->sr_msgid = (rs->sr_tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( op, rs );
}

void
slap_send_ldap_intermediate( Operation *op, SlapReply *rs )
{
	rs->sr_type = REP_INTERMEDIATE;
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_intermediate: err=%d oid=%s len=%ld\n",
		rs->sr_err,
		rs->sr_rspoid ? rs->sr_rspoid : "",
		rs->sr_rspdata != NULL ? rs->sr_rspdata->bv_len : 0 );
	rs->sr_tag = LDAP_RES_INTERMEDIATE;
	rs->sr_msgid = op->o_msgid;
	send_ldap_response( op, rs );
}

int
slap_send_search_entry( Operation *op, SlapReply *rs )
{
	BerElementBuffer berbuf;
	BerElement	*ber = (BerElement *) &berbuf;
	Attribute	*a;
	int		i, j, rc=-1, bytes;
	char		*edn;
	int		userattrs;
	AccessControlState acl_state = ACL_STATE_INIT;
#ifdef LDAP_SLAPI
	/* Support for computed attribute plugins */
	computed_attr_context	 ctx;
	AttributeName	*anp;
#endif
	AttributeDescription *ad_entry = slap_schema.si_ad_entry;

	/* a_flags: array of flags telling if the i-th element will be
	 *          returned or filtered out
	 * e_flags: array of a_flags
	 */
	char **e_flags = NULL;
	
	rs->sr_type = REP_SEARCH;

	/* eventually will loop through generated operational attributes */
	/* only subschemaSubentry and numSubordinates are implemented */
	/* NOTE: moved before overlays callback circling because
	 * they may modify entry and other stuff in rs */
	/* check for special all operational attributes ("+") type */
	/* FIXME: maybe we could se this flag at the operation level;
	 * however, in principle the caller of send_search_entry() may
	 * change the attribute list at each call */
	rs->sr_attr_flags = slap_attr_flags( rs->sr_attrs );

	rc = backend_operational( op, rs );
	if ( rc ) {
		goto error_return;
	}

	if ( op->o_callback ) {
		int		first = 1;
		slap_callback	*sc = op->o_callback,
				*sc_next = op->o_callback;

		rc = SLAP_CB_CONTINUE;
		for ( sc_next = op->o_callback; sc_next; op->o_callback = sc_next) {
			sc_next = op->o_callback->sc_next;
			if ( op->o_callback->sc_response ) {
				rc = op->o_callback->sc_response( op, rs );
				if ( first && op->o_callback == NULL ) {
					sc = NULL;
				}
				if ( rc != SLAP_CB_CONTINUE ) break;
			}
			first = 0;
		}

		op->o_callback = sc;
		if ( rc != SLAP_CB_CONTINUE ) goto error_return;
	}

	Debug( LDAP_DEBUG_TRACE, "=> send_search_entry: conn %lu dn=\"%s\"%s\n",
		op->o_connid, rs->sr_entry->e_name.bv_val,
		op->ors_attrsonly ? " (attrsOnly)" : "" );

	if ( !access_allowed( op, rs->sr_entry, ad_entry, NULL, ACL_READ, NULL )) {
		Debug( LDAP_DEBUG_ACL,
			"send_search_entry: conn %lu access to entry (%s) not allowed\n", 
			op->o_connid, rs->sr_entry->e_name.bv_val, 0 );

		rc = 1;
		goto error_return;
	}

	edn = rs->sr_entry->e_nname.bv_val;

	if ( op->o_res_ber ) {
		/* read back control or LDAP_CONNECTIONLESS */
	    ber = op->o_res_ber;
	} else {
		ber_len_t	siz, len;
		struct berval	bv;

		entry_flatsize( rs->sr_entry, &siz, &len, 0 );
		bv.bv_len = siz + len;
		bv.bv_val = op->o_tmpalloc(bv.bv_len, op->o_tmpmemctx );

		ber_init2( ber, &bv, LBER_USE_DER );
		ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );
	}

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_conn && op->o_conn->c_is_udp ) {
		/* CONNECTIONLESS */
		if ( op->o_protocol == LDAP_VERSION2 ) {
	    	rc = ber_printf(ber, "t{O{" /*}}*/,
				LDAP_RES_SEARCH_ENTRY, &rs->sr_entry->e_name );
		} else {
	    	rc = ber_printf( ber, "{it{O{" /*}}}*/, op->o_msgid,
				LDAP_RES_SEARCH_ENTRY, &rs->sr_entry->e_name );
		}
	} else
#endif
	if ( op->o_res_ber ) {
		/* read back control */
	    rc = ber_printf( ber, "{O{" /*}}*/, &rs->sr_entry->e_name );
	} else {
	    rc = ber_printf( ber, "{it{O{" /*}}}*/, op->o_msgid,
			LDAP_RES_SEARCH_ENTRY, &rs->sr_entry->e_name );
	}

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, 
			"send_search_entry: conn %lu  ber_printf failed\n", 
			op->o_connid, 0, 0 );

		if ( op->o_res_ber == NULL ) ber_free_buf( ber );
		send_ldap_error( op, rs, LDAP_OTHER, "encoding DN error" );
		goto error_return;
	}

	/* check for special all user attributes ("*") type */
	userattrs = SLAP_USERATTRS( rs->sr_attr_flags );

	/* create an array of arrays of flags. Each flag corresponds
	 * to particular value of attribute and equals 1 if value matches
	 * to ValuesReturnFilter or 0 if not
	 */	
	if ( op->o_vrFilter != NULL ) {
		int	k = 0;
		size_t	size;

		for ( a = rs->sr_entry->e_attrs, i=0; a != NULL; a = a->a_next, i++ ) {
			for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) k++;
		}

		size = i * sizeof(char *) + k;
		if ( size > 0 ) {
			char	*a_flags;
			e_flags = slap_sl_calloc ( 1, i * sizeof(char *) + k, op->o_tmpmemctx );
			if( e_flags == NULL ) {
		    	Debug( LDAP_DEBUG_ANY, 
					"send_search_entry: conn %lu slap_sl_calloc failed\n",
					op->o_connid ? op->o_connid : 0, 0, 0 );
				ber_free( ber, 1 );
	
				send_ldap_error( op, rs, LDAP_OTHER, "out of memory" );
				goto error_return;
			}
			a_flags = (char *)(e_flags + i);
			memset( a_flags, 0, k );
			for ( a=rs->sr_entry->e_attrs, i=0; a != NULL; a=a->a_next, i++ ) {
				for ( j = 0; a->a_vals[j].bv_val != NULL; j++ );
				e_flags[i] = a_flags;
				a_flags += j;
			}
	
			rc = filter_matched_values(op, rs->sr_entry->e_attrs, &e_flags) ; 
			if ( rc == -1 ) {
			    	Debug( LDAP_DEBUG_ANY, "send_search_entry: "
					"conn %lu matched values filtering failed\n",
					op->o_connid ? op->o_connid : 0, 0, 0 );
				if ( op->o_res_ber == NULL ) ber_free_buf( ber );
				send_ldap_error( op, rs, LDAP_OTHER,
					"matched values filtering error" );
				goto error_return;
			}
		}
	}

	for ( a = rs->sr_entry->e_attrs, j = 0; a != NULL; a = a->a_next, j++ ) {
		AttributeDescription *desc = a->a_desc;
		int finish = 0;

		if ( rs->sr_attrs == NULL ) {
			/* all attrs request, skip operational attributes */
			if( is_at_operational( desc->ad_type ) ) {
				continue;
			}

		} else {
			/* specific attrs requested */
			if ( is_at_operational( desc->ad_type ) ) {
				if ( !SLAP_OPATTRS( rs->sr_attr_flags ) &&
						!ad_inlist( desc, rs->sr_attrs ) )
				{
					continue;
				}

			} else {
				if ( !userattrs && !ad_inlist( desc, rs->sr_attrs ) )
				{
					continue;
				}
			}
		}

		if ( op->ors_attrsonly ) {
			if ( ! access_allowed( op, rs->sr_entry, desc, NULL,
				ACL_READ, &acl_state ) )
			{
				Debug( LDAP_DEBUG_ACL, "send_search_entry: "
					"conn %lu access to attribute %s not allowed\n",
				        op->o_connid, desc->ad_cname.bv_val, 0 );
				continue;
			}

			if (( rc = ber_printf( ber, "{O[" /*]}*/ , &desc->ad_cname )) == -1 ) {
				Debug( LDAP_DEBUG_ANY, 
					"send_search_entry: conn %lu  ber_printf failed\n", 
					op->o_connid, 0, 0 );

				if ( op->o_res_ber == NULL ) ber_free_buf( ber );
				send_ldap_error( op, rs, LDAP_OTHER,
					"encoding description error");
				goto error_return;
			}
			finish = 1;

		} else {
			int first = 1;
			for ( i = 0; a->a_nvals[i].bv_val != NULL; i++ ) {
				if ( ! access_allowed( op, rs->sr_entry,
					desc, &a->a_nvals[i], ACL_READ, &acl_state ) )
				{
					Debug( LDAP_DEBUG_ACL,
						"send_search_entry: conn %lu "
						"access to attribute %s, value #%d not allowed\n",
						op->o_connid, desc->ad_cname.bv_val, i );

					continue;
				}

				if ( op->o_vrFilter && e_flags[j][i] == 0 ){
					continue;
				}

				if ( first ) {
					first = 0;
					finish = 1;
					if (( rc = ber_printf( ber, "{O[" /*]}*/ , &desc->ad_cname )) == -1 ) {
						Debug( LDAP_DEBUG_ANY,
							"send_search_entry: conn %lu  ber_printf failed\n", 
							op->o_connid, 0, 0 );

						if ( op->o_res_ber == NULL ) ber_free_buf( ber );
						send_ldap_error( op, rs, LDAP_OTHER,
							"encoding description error");
						goto error_return;
					}
				}
				if (( rc = ber_printf( ber, "O", &a->a_vals[i] )) == -1 ) {
					Debug( LDAP_DEBUG_ANY,
						"send_search_entry: conn %lu  "
						"ber_printf failed.\n", op->o_connid, 0, 0 );

					if ( op->o_res_ber == NULL ) ber_free_buf( ber );
					send_ldap_error( op, rs, LDAP_OTHER,
						"encoding values error" );
					goto error_return;
				}
			}
		}

		if ( finish && ( rc = ber_printf( ber, /*{[*/ "]N}" )) == -1 ) {
			Debug( LDAP_DEBUG_ANY,
				"send_search_entry: conn %lu ber_printf failed\n", 
				op->o_connid, 0, 0 );

			if ( op->o_res_ber == NULL ) ber_free_buf( ber );
			send_ldap_error( op, rs, LDAP_OTHER, "encode end error" );
			goto error_return;
		}
	}

	/* NOTE: moved before overlays callback circling because
	 * they may modify entry and other stuff in rs */
	if ( rs->sr_operational_attrs != NULL && op->o_vrFilter != NULL ) {
		int	k = 0;
		size_t	size;

		for ( a = rs->sr_operational_attrs, i=0; a != NULL; a = a->a_next, i++ ) {
			for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) k++;
		}

		size = i * sizeof(char *) + k;
		if ( size > 0 ) {
			char	*a_flags, **tmp;
		
			/*
			 * Reuse previous memory - we likely need less space
			 * for operational attributes
			 */
			tmp = slap_sl_realloc( e_flags, i * sizeof(char *) + k,
				op->o_tmpmemctx );
			if ( tmp == NULL ) {
			    	Debug( LDAP_DEBUG_ANY,
					"send_search_entry: conn %lu "
					"not enough memory "
					"for matched values filtering\n",
					op->o_connid, 0, 0 );
				if ( op->o_res_ber == NULL ) ber_free_buf( ber );
				send_ldap_error( op, rs, LDAP_OTHER,
					"not enough memory for matched values filtering" );
				goto error_return;
			}
			e_flags = tmp;
			a_flags = (char *)(e_flags + i);
			memset( a_flags, 0, k );
			for ( a = rs->sr_operational_attrs, i=0; a != NULL; a = a->a_next, i++ ) {
				for ( j = 0; a->a_vals[j].bv_val != NULL; j++ );
				e_flags[i] = a_flags;
				a_flags += j;
			}
			rc = filter_matched_values(op, rs->sr_operational_attrs, &e_flags) ; 
		    
			if ( rc == -1 ) {
			    	Debug( LDAP_DEBUG_ANY,
					"send_search_entry: conn %lu "
					"matched values filtering failed\n", 
					op->o_connid ? op->o_connid : 0, 0, 0);
				if ( op->o_res_ber == NULL ) ber_free_buf( ber );
				send_ldap_error( op, rs, LDAP_OTHER,
					"matched values filtering error" );
				goto error_return;
			}
		}
	}

	for (a = rs->sr_operational_attrs, j=0; a != NULL; a = a->a_next, j++ ) {
		AttributeDescription *desc = a->a_desc;

		if ( rs->sr_attrs == NULL ) {
			/* all attrs request, skip operational attributes */
			if( is_at_operational( desc->ad_type ) ) {
				continue;
			}

		} else {
			/* specific attrs requested */
			if( is_at_operational( desc->ad_type ) ) {
				if ( !SLAP_OPATTRS( rs->sr_attr_flags ) && 
						!ad_inlist( desc, rs->sr_attrs ) )
				{
					continue;
				}
			} else {
				if ( !userattrs && !ad_inlist( desc, rs->sr_attrs ) ) {
					continue;
				}
			}
		}

		if ( ! access_allowed( op, rs->sr_entry, desc, NULL,
			ACL_READ, &acl_state ) )
		{
			Debug( LDAP_DEBUG_ACL,
				"send_search_entry: conn %lu "
				"access to attribute %s not allowed\n",
				op->o_connid, desc->ad_cname.bv_val, 0 );

			continue;
		}

		rc = ber_printf( ber, "{O[" /*]}*/ , &desc->ad_cname );
		if ( rc == -1 ) {
			Debug( LDAP_DEBUG_ANY,
				"send_search_entry: conn %lu  "
				"ber_printf failed\n", op->o_connid, 0, 0 );

			if ( op->o_res_ber == NULL ) ber_free_buf( ber );
			send_ldap_error( op, rs, LDAP_OTHER,
				"encoding description error" );
			goto error_return;
		}

		if ( ! op->ors_attrsonly ) {
			for ( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
				if ( ! access_allowed( op, rs->sr_entry,
					desc, &a->a_vals[i], ACL_READ, &acl_state ) )
				{
					Debug( LDAP_DEBUG_ACL,
						"send_search_entry: conn %lu "
						"access to %s, value %d not allowed\n",
						op->o_connid, desc->ad_cname.bv_val, i );

					continue;
				}

				if ( op->o_vrFilter && e_flags[j][i] == 0 ){
					continue;
				}

				if (( rc = ber_printf( ber, "O", &a->a_vals[i] )) == -1 ) {
					Debug( LDAP_DEBUG_ANY,
						"send_search_entry: conn %lu  ber_printf failed\n", 
						op->o_connid, 0, 0 );

					if ( op->o_res_ber == NULL ) ber_free_buf( ber );
					send_ldap_error( op, rs, LDAP_OTHER,
						"encoding values error" );
					goto error_return;
				}
			}
		}

		if (( rc = ber_printf( ber, /*{[*/ "]N}" )) == -1 ) {
			Debug( LDAP_DEBUG_ANY,
				"send_search_entry: conn %lu  ber_printf failed\n",
				op->o_connid, 0, 0 );

			if ( op->o_res_ber == NULL ) ber_free_buf( ber );
			send_ldap_error( op, rs, LDAP_OTHER, "encode end error" );
			goto error_return;
		}
	}

#ifdef LDAP_SLAPI
	/*
	 * First, setup the computed attribute context that is
	 * passed to all plugins.
	 */
	if ( op->o_pb ) {
		ctx.cac_pb = op->o_pb;
		ctx.cac_attrs = rs->sr_attrs;
		ctx.cac_attrsonly = op->ors_attrsonly;
		ctx.cac_userattrs = userattrs;
		ctx.cac_opattrs = rs->sr_attr_flags;
		ctx.cac_acl_state = acl_state;
		ctx.cac_private = (void *)ber;

		/*
		 * For each client requested attribute, call the plugins.
		 */
		if ( rs->sr_attrs != NULL ) {
			for ( anp = rs->sr_attrs; anp->an_name.bv_val != NULL; anp++ ) {
				rc = compute_evaluator( &ctx, anp->an_name.bv_val,
					rs->sr_entry, slapi_int_compute_output_ber );
				if ( rc == 1 ) break;
			}
		} else {
			/*
			 * Technically we shouldn't be returning operational attributes
			 * when the user requested only user attributes. We'll let the
			 * plugin decide whether to be naughty or not.
			 */
			rc = compute_evaluator( &ctx, "*",
				rs->sr_entry, slapi_int_compute_output_ber );
		}
		if ( rc == 1 ) {
			if ( op->o_res_ber == NULL ) ber_free_buf( ber );
			send_ldap_error( op, rs, LDAP_OTHER, "computed attribute error" );
			goto error_return;
		}
	}
#endif /* LDAP_SLAPI */

	/* free e_flags */
	if ( e_flags ) {
		slap_sl_free( e_flags, op->o_tmpmemctx );
		e_flags = NULL;
	}

	rc = ber_printf( ber, /*{{*/ "}N}" );

	if( rc != -1 ) {
		rc = send_ldap_controls( op, ber, rs->sr_ctrls );
	}

	if( rc != -1 ) {
#ifdef LDAP_CONNECTIONLESS
		if( op->o_conn && op->o_conn->c_is_udp ) {
			if ( op->o_protocol != LDAP_VERSION2 ) {
				rc = ber_printf( ber, /*{*/ "N}" );
			}
		} else
#endif
		if ( op->o_res_ber == NULL ) {
			rc = ber_printf( ber, /*{*/ "N}" );
		}
	}

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );

		if ( op->o_res_ber == NULL ) ber_free_buf( ber );
		send_ldap_error( op, rs, LDAP_OTHER, "encode entry end error" );
		rc = 1;
		goto error_return;
	}

	if ( op->o_res_ber == NULL ) {
		bytes = send_ldap_ber( op->o_conn, ber );
		ber_free_buf( ber );

		if ( bytes < 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"send_search_entry: conn %lu  ber write failed.\n", 
				op->o_connid, 0, 0 );

			rc = -1;
			goto error_return;
		}
		rs->sr_nentries++;

		ldap_pvt_thread_mutex_lock( &num_sent_mutex );
		num_bytes_sent += bytes;
		num_entries_sent++;
		num_pdu_sent++;
		ldap_pvt_thread_mutex_unlock( &num_sent_mutex );
	}

	Statslog( LDAP_DEBUG_STATS2, "conn=%lu op=%lu ENTRY dn=\"%s\"\n",
	    op->o_connid, op->o_opid, rs->sr_entry->e_dn, 0, 0 );

	Debug( LDAP_DEBUG_TRACE,
		"<= send_search_entry: conn %lu exit.\n", op->o_connid, 0, 0 );

	rc = 0;

error_return:;
	if ( op->o_callback ) {
		int		first = 1;
		slap_callback	*sc = op->o_callback,
				*sc_next = op->o_callback;

		for ( sc_next = op->o_callback; sc_next; op->o_callback = sc_next) {
			sc_next = op->o_callback->sc_next;
			if ( op->o_callback->sc_cleanup ) {
				(void)op->o_callback->sc_cleanup( op, rs );
				if ( first && op->o_callback == NULL ) {
					sc = NULL;
				}
			}
			first = 0;
		}

		op->o_callback = sc;
	}

	if ( e_flags ) {
		slap_sl_free( e_flags, op->o_tmpmemctx );
	}

	if ( rs->sr_operational_attrs ) {
		attrs_free( rs->sr_operational_attrs );
		rs->sr_operational_attrs = NULL;
	}
	rs->sr_attr_flags = SLAP_ATTRS_UNDEFINED;

	/* FIXME: I think rs->sr_type should be explicitly set to
	 * REP_SEARCH here. That's what it was when we entered this
	 * function. send_ldap_error may have changed it, but we
	 * should set it back so that the cleanup functions know
	 * what they're doing.
	 */
	if ( op->o_tag == LDAP_REQ_SEARCH && rs->sr_type == REP_SEARCH 
		&& rs->sr_entry 
		&& ( rs->sr_flags & REP_ENTRY_MUSTBEFREED ) ) 
	{
		entry_free( rs->sr_entry );
		rs->sr_entry = NULL;
		rs->sr_flags &= ~REP_ENTRY_MUSTBEFREED;
	}

	return( rc );
}

int
slap_send_search_reference( Operation *op, SlapReply *rs )
{
	BerElementBuffer berbuf;
	BerElement	*ber = (BerElement *) &berbuf;
	int rc = 0;
	int bytes;

	AttributeDescription *ad_ref = slap_schema.si_ad_ref;
	AttributeDescription *ad_entry = slap_schema.si_ad_entry;

	rs->sr_type = REP_SEARCHREF;
	if ( op->o_callback ) {
		int		first = 1;
		slap_callback	*sc = op->o_callback,
				*sc_next = op->o_callback;

		rc = SLAP_CB_CONTINUE;
		for ( sc_next = op->o_callback; sc_next; op->o_callback = sc_next) {
			sc_next = op->o_callback->sc_next;
			if ( op->o_callback->sc_response ) {
				rc = op->o_callback->sc_response( op, rs );
				if ( first && op->o_callback == NULL ) {
					sc = NULL;
				}
				if ( rc != SLAP_CB_CONTINUE ) break;
			}
			first = 0;
		}

		op->o_callback = sc;
		if ( rc != SLAP_CB_CONTINUE ) goto rel;
	}

	Debug( LDAP_DEBUG_TRACE,
		"=> send_search_reference: dn=\"%s\"\n",
		rs->sr_entry ? rs->sr_entry->e_name.bv_val : "(null)", 0, 0 );

	if (  rs->sr_entry && ! access_allowed( op, rs->sr_entry,
		ad_entry, NULL, ACL_READ, NULL ) )
	{
		Debug( LDAP_DEBUG_ACL,
			"send_search_reference: access to entry not allowed\n",
		    0, 0, 0 );
		rc = 1;
		goto rel;
	}

	if ( rs->sr_entry && ! access_allowed( op, rs->sr_entry,
		ad_ref, NULL, ACL_READ, NULL ) )
	{
		Debug( LDAP_DEBUG_ACL,
			"send_search_reference: access "
			"to reference not allowed\n",
		    0, 0, 0 );
		rc = 1;
		goto rel;
	}

#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
	if( op->o_domain_scope ) {
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: domainScope control in (%s)\n", 
			rs->sr_entry->e_dn, 0, 0 );
		rc = 0;
		goto rel;
	}
#endif

	if( rs->sr_ref == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: null ref in (%s)\n", 
			rs->sr_entry ? rs->sr_entry->e_dn : "(null)", 0, 0 );
		rc = 1;
		goto rel;
	}

	if( op->o_protocol < LDAP_VERSION3 ) {
		rc = 0;
		/* save the references for the result */
		if( rs->sr_ref[0].bv_val != NULL ) {
			if( value_add( &rs->sr_v2ref, rs->sr_ref ) )
				rc = LDAP_OTHER;
		}
		goto rel;
	}

#ifdef LDAP_CONNECTIONLESS
	if( op->o_conn && op->o_conn->c_is_udp ) {
		ber = op->o_res_ber;
	} else
#endif
	{
		ber_init_w_nullc( ber, LBER_USE_DER );
		ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );
	}

	rc = ber_printf( ber, "{it{W}" /*"}"*/ , op->o_msgid,
		LDAP_RES_SEARCH_REFERENCE, rs->sr_ref );

	if( rc != -1 ) {
		rc = send_ldap_controls( op, ber, rs->sr_ctrls );
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: ber_printf failed\n", 0, 0, 0 );

#ifdef LDAP_CONNECTIONLESS
		if (!op->o_conn || op->o_conn->c_is_udp == 0)
#endif
		ber_free_buf( ber );
		send_ldap_error( op, rs, LDAP_OTHER, "encode DN error" );
		goto rel;
	}

#ifdef LDAP_CONNECTIONLESS
	if (!op->o_conn || op->o_conn->c_is_udp == 0) {
#endif
	bytes = send_ldap_ber( op->o_conn, ber );
	ber_free_buf( ber );

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_refs_sent++;
	num_pdu_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );
#ifdef LDAP_CONNECTIONLESS
	}
#endif

	Statslog( LDAP_DEBUG_STATS2, "conn=%lu op=%lu REF dn=\"%s\"\n",
		op->o_connid, op->o_opid, rs->sr_entry ? rs->sr_entry->e_dn : "(null)", 0, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= send_search_reference\n", 0, 0, 0 );

rel:
	if ( op->o_callback ) {
		int		first = 1;
		slap_callback	*sc = op->o_callback,
				*sc_next = op->o_callback;

		for ( sc_next = op->o_callback; sc_next; op->o_callback = sc_next) {
			sc_next = op->o_callback->sc_next;
			if ( op->o_callback->sc_cleanup ) {
				(void)op->o_callback->sc_cleanup( op, rs );
				if ( first && op->o_callback == NULL ) {
					sc = NULL;
				}
			}
			first = 0;
		}

		op->o_callback = sc;
	}

	return rc;
}

int
str2result(
    char	*s,
    int		*code,
    char	**matched,
    char	**info
)
{
	int	rc;
	char	*c;

	*code = LDAP_SUCCESS;
	*matched = NULL;
	*info = NULL;

	if ( strncasecmp( s, "RESULT", STRLENOF( "RESULT" ) ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "str2result (%s) expecting \"RESULT\"\n",
		    s, 0, 0 );

		return( -1 );
	}

	rc = 0;
	while ( (s = strchr( s, '\n' )) != NULL ) {
		*s++ = '\0';
		if ( *s == '\0' ) {
			break;
		}
		if ( (c = strchr( s, ':' )) != NULL ) {
			c++;
		}

		if ( strncasecmp( s, "code", STRLENOF( "code" ) ) == 0 ) {
			if ( c != NULL ) {
				*code = atoi( c );
			}
		} else if ( strncasecmp( s, "matched", STRLENOF( "matched" ) ) == 0 ) {
			if ( c != NULL ) {
				*matched = c;
			}
		} else if ( strncasecmp( s, "info", STRLENOF( "info" ) ) == 0 ) {
			if ( c != NULL ) {
				*info = c;
			}
		} else {
			Debug( LDAP_DEBUG_ANY, "str2result (%s) unknown\n",
			    s, 0, 0 );

			rc = -1;
		}
	}

	return( rc );
}

int slap_read_controls(
	Operation *op,
	SlapReply *rs,
	Entry *e,
	const struct berval *oid,
	LDAPControl **ctrl )
{
	int rc;
	struct berval bv;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *) &berbuf;
	LDAPControl c;
	ber_len_t	siz, len;
	Operation myop;

	Debug( LDAP_DEBUG_ANY, "slap_read_controls: (%s) %s\n",
		oid->bv_val, e->e_dn, 0 );

	rs->sr_entry = e;
	rs->sr_attrs = ( oid == &slap_pre_read_bv ) ?
		op->o_preread_attrs : op->o_postread_attrs; 

	entry_flatsize( rs->sr_entry, &siz, &len, 0 );
	bv.bv_len = siz + len;
	bv.bv_val = op->o_tmpalloc(bv.bv_len, op->o_tmpmemctx );

	ber_init2( ber, &bv, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	/* create new operation */
	myop = *op;
	myop.o_bd = NULL;
	myop.o_res_ber = ber;

	rc = slap_send_search_entry( &myop, rs );
	if( rc ) return rc;

	rc = ber_flatten2( ber, &c.ldctl_value, 0 );

	if( rc == LBER_ERROR ) return LDAP_OTHER;

	c.ldctl_oid = oid->bv_val;
	c.ldctl_iscritical = 0;

	if ( ctrl == NULL ) {
		/* first try */
		*ctrl = (LDAPControl *) slap_sl_calloc( 1, sizeof(LDAPControl), NULL );
	} else {
		/* retry: free previous try */
		slap_sl_free( (*ctrl)->ldctl_value.bv_val, &op->o_tmpmemctx );
	}

	**ctrl = c;
	return LDAP_SUCCESS;
}

/* Map API errors to protocol errors... */
int
slap_map_api2result( SlapReply *rs )
{
	switch(rs->sr_err) {
	case LDAP_SERVER_DOWN:
		return LDAP_UNAVAILABLE;
	case LDAP_LOCAL_ERROR:
		return LDAP_OTHER;
	case LDAP_ENCODING_ERROR:
	case LDAP_DECODING_ERROR:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_TIMEOUT:
		return LDAP_UNAVAILABLE;
	case LDAP_AUTH_UNKNOWN:
		return LDAP_AUTH_METHOD_NOT_SUPPORTED;
	case LDAP_FILTER_ERROR:
		rs->sr_text = "Filter error";
		return LDAP_OTHER;
	case LDAP_USER_CANCELLED:
		rs->sr_text = "User cancelled";
		return LDAP_OTHER;
	case LDAP_PARAM_ERROR:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_NO_MEMORY:
		return LDAP_OTHER;
	case LDAP_CONNECT_ERROR:
		return LDAP_UNAVAILABLE;
	case LDAP_NOT_SUPPORTED:
		return LDAP_UNWILLING_TO_PERFORM;
	case LDAP_CONTROL_NOT_FOUND:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_NO_RESULTS_RETURNED:
		return LDAP_NO_SUCH_OBJECT;
	case LDAP_MORE_RESULTS_TO_RETURN:
		rs->sr_text = "More results to return";
		return LDAP_OTHER;
	case LDAP_CLIENT_LOOP:
	case LDAP_REFERRAL_LIMIT_EXCEEDED:
		return LDAP_LOOP_DETECT;
	default:
		if ( LDAP_API_ERROR(rs->sr_err) ) return LDAP_OTHER;
		return rs->sr_err;
	}
}


slap_mask_t
slap_attr_flags( AttributeName *an )
{
	slap_mask_t	flags = SLAP_ATTRS_UNDEFINED;

	if ( an == NULL ) {
		flags |= ( SLAP_OPATTRS_NO | SLAP_USERATTRS_YES );

	} else {
		flags |= an_find( an, &AllOper ) ?  SLAP_OPATTRS_YES : SLAP_OPATTRS_NO;
		flags |= an_find( an, &AllUser ) ?  SLAP_USERATTRS_YES : SLAP_USERATTRS_NO;
	}

	return flags;
}


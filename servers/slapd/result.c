/* result.c - routines to send ldap results, errors, and referrals */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
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
#include "slapi.h"
#endif

int slap_null_cb( Operation *op, SlapReply *rs )
{
	return 0;
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
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "v2ref: SLAP_MALLOC failed", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "v2ref: SLAP_MALLOC failed", 0, 0, 0 );
#endif
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
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, "v2ref: SLAP_MALLOC failed", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "v2ref: SLAP_MALLOC failed", 0, 0, 0 );
#endif
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

#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_ldap_ber: conn %lu  ber_flush failed err=%d (%s)\n",
			conn ? conn->c_connid : 0, err, sock_errstr(err) );
#else
		Debug( LDAP_DEBUG_CONNS, "ber_flush failed errno=%d reason=\"%s\"\n",
		    err, sock_errstr(err), 0 );
#endif

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
send_ldap_controls( BerElement *ber, LDAPControl **c )
{
	int rc;
	if( c == NULL ) return 0;

	rc = ber_printf( ber, "t{"/*}*/, LDAP_TAG_CONTROLS );
	if( rc == -1 ) return rc;

	for( ; *c != NULL; c++) {
		rc = ber_printf( ber, "{s" /*}*/, (*c)->ldctl_oid );

		if( (*c)->ldctl_iscritical ) {
			rc = ber_printf( ber, "b",
				(ber_int_t) (*c)->ldctl_iscritical ) ;
			if( rc == -1 ) return rc;
		}

		if( (*c)->ldctl_value.bv_val != NULL ) {
			rc = ber_printf( ber, "O", &((*c)->ldctl_value)); 
			if( rc == -1 ) return rc;
		}

		rc = ber_printf( ber, /*{*/"N}" );
		if( rc == -1 ) return rc;
	}

	rc = ber_printf( ber, /*{*/"N}" );

	return rc;
}

void
send_ldap_response(
	Operation *op,
	SlapReply *rs )
{
	BerElementBuffer berbuf;
	BerElement	*ber = (BerElement *) &berbuf;
	int		rc;
	long	bytes;

	if (op->o_callback && op->o_callback->sc_response) {
		rc = op->o_callback->sc_response( op, rs );
		if ( rc != SLAP_CB_CONTINUE ) return;
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

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_response:  msgid=%d tag=%lu err=%d\n",
		rs->sr_msgid, rs->sr_tag, rs->sr_err );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_response: msgid=%d tag=%lu err=%d\n",
		rs->sr_msgid, rs->sr_tag, rs->sr_err );
#endif

	if( rs->sr_ref ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ARGS, 
			"send_ldap_response: conn %lu  ref=\"%s\"\n",
			op->o_connid,
			rs->sr_ref[0].bv_val ? rs->sr_ref[0].bv_val : "NULL" , 0 );
#else
		Debug( LDAP_DEBUG_ARGS, "send_ldap_response: ref=\"%s\"\n",
			rs->sr_ref[0].bv_val ? rs->sr_ref[0].bv_val : "NULL",
			NULL, NULL );
#endif
	}

#ifdef LDAP_CONNECTIONLESS
	if (op->o_conn && op->o_conn->c_is_udp &&
		op->o_protocol == LDAP_VERSION2 )
	{
		rc = ber_printf( ber, "t{ess" /*"}}"*/,
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

	if( rc != -1 && rs->sr_ctrls != NULL ) {
		rc = send_ldap_controls( ber, rs->sr_ctrls );
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}

#ifdef LDAP_CONNECTIONLESS
	if( op->o_conn && op->o_conn->c_is_udp && op->o_protocol == LDAP_VERSION2 && rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}
#endif
		
	if ( rc == -1 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_ldap_response: conn %lu  ber_printf failed\n",
			op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

#ifdef LDAP_CONNECTIONLESS
		if (!op->o_conn || op->o_conn->c_is_udp == 0)
#endif
		ber_free_buf( ber );
		return;
	}

	/* send BER */
	bytes = send_ldap_ber( op->o_conn, ber );
#ifdef LDAP_CONNECTIONLESS
	if (!op->o_conn || op->o_conn->c_is_udp == 0)
#endif
	ber_free_buf( ber );

	if ( bytes < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_ldap_response: conn %lu ber write failed\n",
			op->o_connid ? op->o_connid : 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"send_ldap_response: ber write failed\n",
			0, 0, 0 );
#endif

		return;
	}

#ifdef LDAP_SLAPI
	if ( op->o_pb ) {
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_CODE, (void *)rs->sr_err );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_MATCHED, (void *)rs->sr_matched );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_TEXT, (void *)rs->sr_text );
	}
#endif /* LDAP_SLAPI */

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_pdu_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );
	return;
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

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_disconnect: conn %lu  %d:%s\n",
		op->o_connid, rs->sr_err, rs->sr_text ? rs->sr_text : "" );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_disconnect %d:%s\n",
		rs->sr_err, rs->sr_text ? rs->sr_text : "", NULL );
#endif


	if ( op->o_protocol < LDAP_VERSION3 ) {
		rs->sr_rspoid = NULL;
		rs->sr_tag = req2res( op->o_tag );
		rs->sr_msgid = (rs->sr_tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	} else {
		rs->sr_rspoid = LDAP_NOTICE_DISCONNECT;
		rs->sr_tag = LDAP_RES_EXTENDED;
		rs->sr_msgid = 0;
	}

	send_ldap_response( op, rs );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%lu op=%lu DISCONNECT tag=%lu err=%d text=%s\n",
		op->o_connid, op->o_opid, rs->sr_tag, rs->sr_err, rs->sr_text ? rs->sr_text : "" );
}

void
slap_send_ldap_result( Operation *op, SlapReply *rs )
{
	char *tmp = NULL;
	const char *otext = rs->sr_text;
	BerVarray oref = rs->sr_ref;

	rs->sr_type = REP_RESULT;

	assert( !LDAP_API_ERROR( rs->sr_err ) && ( rs->sr_err >= 0 ));

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_result: conn %lu op=%lu p=%d\n",
		op->o_connid, op->o_opid, op->o_protocol );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_result: conn=%lu op=%lu p=%d\n",
		op->o_connid, op->o_opid, op->o_protocol );
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, 
		"send_ldap_result: err=%d matched=\"%s\" text=\"%s\"\n",
		rs->sr_err, rs->sr_matched ? rs->sr_matched : "",
		rs->sr_text ? rs->sr_text : "" );
#else
	Debug( LDAP_DEBUG_ARGS,
		"send_ldap_result: err=%d matched=\"%s\" text=\"%s\"\n",
		rs->sr_err, rs->sr_matched ? rs->sr_matched : "",
		rs->sr_text ? rs->sr_text : "" );
#endif


	if( rs->sr_ref ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ARGS, 
			"send_ldap_result: referral=\"%s\"\n",
			rs->sr_ref[0].bv_val ? rs->sr_ref[0].bv_val : "NULL", 0, 0 );
#else
		Debug( LDAP_DEBUG_ARGS,
			"send_ldap_result: referral=\"%s\"\n",
			rs->sr_ref[0].bv_val ? rs->sr_ref[0].bv_val : "NULL",
			NULL, NULL );
#endif
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
	if ( op->o_pb ) {
		slapi_x_pblock_set_operation( op->o_pb, op );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_CODE, (void *)rs->sr_err );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_TEXT, (void *)rs->sr_text );
		slapi_pblock_set( op->o_pb, SLAPI_RESULT_MATCHED, (void *)rs->sr_matched );

		(void) doPluginFNs( op->o_bd, SLAPI_PLUGIN_PRE_RESULT_FN, op->o_pb );
	}
#endif /* LDAP_SLAPI */

	if ( op->o_protocol < LDAP_VERSION3 ) {
		tmp = v2ref( rs->sr_ref, rs->sr_text );
		rs->sr_text = tmp;
		rs->sr_ref = NULL;
	}

	rs->sr_tag = req2res( op->o_tag );
	rs->sr_msgid = (rs->sr_tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( op, rs );

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

	if( tmp != NULL ) ch_free(tmp);
	rs->sr_text = otext;
	rs->sr_ref = oref;
}

void
send_ldap_sasl( Operation *op, SlapReply *rs )
{
	rs->sr_type = REP_SASL;
#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_sasl: conn %lu err=%d len=%lu\n",
		op->o_connid, rs->sr_err,
		rs->sr_sasldata ? rs->sr_sasldata->bv_len : -1 );
#else
	Debug( LDAP_DEBUG_TRACE, "send_ldap_sasl: err=%d len=%ld\n",
		rs->sr_err,
		rs->sr_sasldata ? (long) rs->sr_sasldata->bv_len : -1, NULL );
#endif

	rs->sr_tag = req2res( op->o_tag );
	rs->sr_msgid = (rs->sr_tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( op, rs );
}

void
slap_send_ldap_extended( Operation *op, SlapReply *rs )
{
	rs->sr_type = REP_EXTENDED;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_extended: err=%d oid=%s len=%ld\n",
		rs->sr_err, rs->sr_rspoid ? rs->sr_rspoid : "",
		rs->sr_rspdata != NULL ? rs->sr_rspdata->bv_len : 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_extended: err=%d oid=%s len=%ld\n",
		rs->sr_err,
		rs->sr_rspoid ? rs->sr_rspoid : "",
		rs->sr_rspdata != NULL ? rs->sr_rspdata->bv_len : 0 );
#endif

	rs->sr_tag = req2res( op->o_tag );
	rs->sr_msgid = (rs->sr_tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( op, rs );
}

void
slap_send_ldap_intermediate( Operation *op, SlapReply *rs )
{
	rs->sr_type = REP_INTERMEDIATE;
#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY,
		"send_ldap_intermediate: err=%d oid=%s len=%ld\n",
		rs->sr_err, rs->sr_rspoid ? rs->sr_rspoid : "",
		rs->sr_rspdata != NULL ? rs->sr_rspdata->bv_len : 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_intermediate: err=%d oid=%s len=%ld\n",
		rs->sr_err,
		rs->sr_rspoid ? rs->sr_rspoid : "",
		rs->sr_rspdata != NULL ? rs->sr_rspdata->bv_len : 0 );
#endif
	rs->sr_tag = LDAP_RES_INTERMEDIATE;
	rs->sr_msgid = op->o_msgid;
	send_ldap_response( op, rs );
}

int
slap_send_search_entry( Operation *op, SlapReply *rs )
{
	BerElementBuffer berbuf;
	BerElement	*ber = (BerElement *) &berbuf;
	Attribute	*a, *aa;
	int		i, j, rc=-1, bytes;
	char		*edn;
	int		userattrs;
	int		opattrs;
	AccessControlState acl_state = ACL_STATE_INIT;
#ifdef LDAP_SLAPI
	/* Support for computed attribute plugins */
	computed_attr_context	 ctx;
	AttributeName	*anp;
#endif
	void		*mark = NULL;

	AttributeDescription *ad_entry = slap_schema.si_ad_entry;

	/* a_flags: array of flags telling if the i-th element will be
	 *          returned or filtered out
	 * e_flags: array of a_flags
	 */
	char **e_flags = NULL;

	rs->sr_type = REP_SEARCH;
	if (op->o_callback && op->o_callback->sc_response) {
		rc = op->o_callback->sc_response( op, rs );
		if ( rc != SLAP_CB_CONTINUE ) return rc;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "send_search_entry: conn %lu	dn=\"%s\"%s\n",
		op->o_connid, rs->sr_entry->e_name.bv_val,
		op->ors_attrsonly ? " (attrsOnly)" : "" );
#else
	Debug( LDAP_DEBUG_TRACE, "=> send_search_entry: dn=\"%s\"%s\n",
		rs->sr_entry->e_name.bv_val,
		op->ors_attrsonly ? " (attrsOnly)" : "", 0 );
#endif

	mark = sl_mark( op->o_tmpmemctx );

	if ( !access_allowed( op, rs->sr_entry, ad_entry, NULL, ACL_READ, NULL )) {
#ifdef NEW_LOGGING
		LDAP_LOG( ACL, INFO, 
			"send_search_entry: conn %lu access to entry (%s) not allowed\n", 
			op->o_connid, rs->sr_entry->e_name.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"send_search_entry: access to entry not allowed\n",
		    0, 0, 0 );
#endif

		sl_release( mark, op->o_tmpmemctx );
		return( 1 );
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
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_entry: conn %lu  ber_printf failed\n", 
			op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

		if ( op->o_res_ber == NULL ) ber_free_buf( ber );
		send_ldap_error( op, rs, LDAP_OTHER, "encoding DN error" );
		goto error_return;
	}

	/* check for special all user attributes ("*") type */
	userattrs = ( rs->sr_attrs == NULL ) ? 1
		: an_find( rs->sr_attrs, &AllUser );

	/* check for special all operational attributes ("+") type */
	opattrs = ( rs->sr_attrs == NULL ) ? 0
		: an_find( rs->sr_attrs, &AllOper );

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
			e_flags = sl_calloc ( 1, i * sizeof(char *) + k, op->o_tmpmemctx );
			if( e_flags == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"send_search_entry: conn %lu sl_calloc failed\n",
					op->o_connid ? op->o_connid : 0, 0, 0 );
#else
		    	Debug( LDAP_DEBUG_ANY, 
					"send_search_entry: sl_calloc failed\n", 0, 0, 0 );
#endif
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
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, "send_search_entry: "
					"conn %lu matched values filtering failed\n",
					op->o_connid ? op->o_connid : 0, 0, 0 );
#else
		    	Debug( LDAP_DEBUG_ANY,
					"matched values filtering failed\n", 0, 0, 0 );
#endif
				if ( op->o_res_ber == NULL ) ber_free_buf( ber );
				send_ldap_error( op, rs, LDAP_OTHER,
					"matched values filtering error" );
				goto error_return;
			}
		}
	}

	for ( a = rs->sr_entry->e_attrs, j = 0; a != NULL; a = a->a_next, j++ ) {
		AttributeDescription *desc = a->a_desc;

		if ( rs->sr_attrs == NULL ) {
			/* all attrs request, skip operational attributes */
			if( is_at_operational( desc->ad_type ) ) {
				continue;
			}

		} else {
			/* specific attrs requested */
			if ( is_at_operational( desc->ad_type ) ) {
				if( !opattrs && !ad_inlist( desc, rs->sr_attrs ) ) {
					continue;
				}

			} else {
				if (!userattrs && !ad_inlist( desc, rs->sr_attrs ) ) {
					continue;
				}
			}
		}

		if ( ! access_allowed( op, rs->sr_entry, desc, NULL,
			ACL_READ, &acl_state ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( ACL, INFO, 
				"send_search_entry: conn %lu  access to attribute %s not "
				"allowed\n", op->o_connid, desc->ad_cname.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ACL, "acl: "
				"access to attribute %s not allowed\n",
			    desc->ad_cname.bv_val, 0, 0 );
#endif
			continue;
		}

		if (( rc = ber_printf( ber, "{O[" /*]}*/ , &desc->ad_cname )) == -1 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				"send_search_entry: conn %lu  ber_printf failed\n", 
				op->o_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

			if ( op->o_res_ber == NULL ) ber_free_buf( ber );
			send_ldap_error( op, rs, LDAP_OTHER, "encoding description error");
			goto error_return;
		}

		if ( ! op->ors_attrsonly ) {
			for ( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
				if ( ! access_allowed( op, rs->sr_entry,
					desc, &a->a_vals[i], ACL_READ, &acl_state ) )
				{
#ifdef NEW_LOGGING
					LDAP_LOG( ACL, INFO, 
						"send_search_entry: conn %lu "
						"access to attribute %s, value %d not allowed\n",
						op->o_connid, desc->ad_cname.bv_val, i );
#else
					Debug( LDAP_DEBUG_ACL,
						"acl: access to attribute %s, "
						"value %d not allowed\n",
						desc->ad_cname.bv_val, i, 0 );
#endif

					continue;
				}

				if ( op->o_vrFilter && e_flags[j][i] == 0 ){
					continue;
				}

				if (( rc = ber_printf( ber, "O", &a->a_vals[i] )) == -1 ) {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR, 
						"send_search_entry: conn %lu  "
						"ber_printf failed.\n", op->o_connid, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
					    "ber_printf failed\n", 0, 0, 0 );
#endif

					if ( op->o_res_ber == NULL ) ber_free_buf( ber );
					send_ldap_error( op, rs, LDAP_OTHER,
						"encoding values error" );
					goto error_return;
				}
			}
		}

		if (( rc = ber_printf( ber, /*{[*/ "]N}" )) == -1 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				"send_search_entry: conn %lu ber_printf failed\n", 
				op->o_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

			if ( op->o_res_ber == NULL ) ber_free_buf( ber );
			send_ldap_error( op, rs, LDAP_OTHER, "encode end error" );
			goto error_return;
		}
	}

	/* eventually will loop through generated operational attributes */
	/* only have subschemaSubentry and numSubordinates are implemented */
	aa = backend_operational( op, rs, opattrs );

	if ( aa != NULL && op->o_vrFilter != NULL ) {
		int	k = 0;
		size_t	size;

		for ( a = aa, i=0; a != NULL; a = a->a_next, i++ ) {
			for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) k++;
		}

		size = i * sizeof(char *) + k;
		if ( size > 0 ) {
			char	*a_flags, **tmp;
		
			/*
			 * Reuse previous memory - we likely need less space
			 * for operational attributes
			 */
			tmp = sl_realloc( e_flags, i * sizeof(char *) + k,
				op->o_tmpmemctx );
			if ( tmp == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"send_search_entry: conn %lu "
					"not enough memory "
					"for matched values filtering\n", 
					op->o_connid, 0, 0);
#else
			    	Debug( LDAP_DEBUG_ANY,
					"send_search_entry: conn %lu "
					"not enough memory "
					"for matched values filtering\n",
					op->o_connid, 0, 0 );
#endif
				if ( op->o_res_ber == NULL ) ber_free_buf( ber );
				send_ldap_error( op, rs, LDAP_OTHER,
					"not enough memory for matched values filtering" );
				goto error_return;
			}
			e_flags = tmp;
			a_flags = (char *)(e_flags + i);
			memset( a_flags, 0, k );
			for ( a = aa, i=0; a != NULL; a = a->a_next, i++ ) {
				for ( j = 0; a->a_vals[j].bv_val != NULL; j++ );
				e_flags[i] = a_flags;
				a_flags += j;
			}
			rc = filter_matched_values(op, aa, &e_flags) ; 
		    
			if ( rc == -1 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"send_search_entry: conn %lu "
					"matched values filtering failed\n", 
					op->o_connid ? op->o_connid : 0, 0, 0);
#else
			    	Debug( LDAP_DEBUG_ANY,
					"matched values filtering failed\n", 0, 0, 0 );
#endif
				if ( op->o_res_ber == NULL ) ber_free_buf( ber );
				send_ldap_error( op, rs, LDAP_OTHER,
					"matched values filtering error" );
				goto error_return;
			}
		}
	}

	for (a = aa, j=0; a != NULL; a = a->a_next, j++ ) {
		AttributeDescription *desc = a->a_desc;

		if ( rs->sr_attrs == NULL ) {
			/* all attrs request, skip operational attributes */
			if( is_at_operational( desc->ad_type ) ) {
				continue;
			}

		} else {
			/* specific attrs requested */
			if( is_at_operational( desc->ad_type ) ) {
				if( !opattrs && !ad_inlist( desc, rs->sr_attrs ) ) {
					continue;
				}
			} else {
				if (!userattrs && !ad_inlist( desc, rs->sr_attrs ) ) {
					continue;
				}
			}
		}

		if ( ! access_allowed( op, rs->sr_entry, desc, NULL,
			ACL_READ, &acl_state ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( ACL, INFO, 
				"send_search_entry: conn %lu "
				"access to attribute %s not allowed\n",
				op->o_connid, desc->ad_cname.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ACL, "send_search_entry: access to attribute %s "
				"not allowed\n", desc->ad_cname.bv_val, 0, 0 );
#endif

			continue;
		}

		rc = ber_printf( ber, "{O[" /*]}*/ , &desc->ad_cname );
		if ( rc == -1 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				"send_search_entry: conn %lu  "
				"ber_printf failed\n", op->o_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

			if ( op->o_res_ber == NULL ) ber_free_buf( ber );
			send_ldap_error( op, rs, LDAP_OTHER, "encoding description error" );
			attrs_free( aa );
			goto error_return;
		}

		if ( ! op->ors_attrsonly ) {
			for ( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
				if ( ! access_allowed( op, rs->sr_entry,
					desc, &a->a_vals[i], ACL_READ, &acl_state ) )
				{
#ifdef NEW_LOGGING
					LDAP_LOG( ACL, INFO, 
						"send_search_entry: conn %lu "
						"access to %s, value %d not allowed\n",
						op->o_connid, desc->ad_cname.bv_val, i );
#else
					Debug( LDAP_DEBUG_ACL,
						"send_search_entry: access to attribute %s, "
						"value %d not allowed\n",
						desc->ad_cname.bv_val, i, 0 );
#endif

					continue;
				}

				if ( op->o_vrFilter && e_flags[j][i] == 0 ){
					continue;
				}

				if (( rc = ber_printf( ber, "O", &a->a_vals[i] )) == -1 ) {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR, 
						"send_search_entry: conn %lu  ber_printf failed\n", 
						op->o_connid, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
					    "ber_printf failed\n", 0, 0, 0 );
#endif

					if ( op->o_res_ber == NULL ) ber_free_buf( ber );
					send_ldap_error( op, rs, LDAP_OTHER,
						"encoding values error" );
					attrs_free( aa );
					goto error_return;
				}
			}
		}

		if (( rc = ber_printf( ber, /*{[*/ "]N}" )) == -1 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				"send_search_entry: conn %lu  ber_printf failed\n",
				op->o_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

			if ( op->o_res_ber == NULL ) ber_free_buf( ber );
			send_ldap_error( op, rs, LDAP_OTHER, "encode end error" );
			attrs_free( aa );
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
		ctx.cac_opattrs = opattrs;
		ctx.cac_acl_state = acl_state;
		ctx.cac_private = (void *)ber;

		/*
		 * For each client requested attribute, call the plugins.
		 */
		if ( rs->sr_attrs != NULL ) {
			for ( anp = rs->sr_attrs; anp->an_name.bv_val != NULL; anp++ ) {
				rc = compute_evaluator( &ctx, anp->an_name.bv_val,
					rs->sr_entry, slapi_x_compute_output_ber );
				if ( rc == 1 ) {
					break;
				}
			}
		} else {
			/*
			 * Technically we shouldn't be returning operational attributes
			 * when the user requested only user attributes. We'll let the
			 * plugin decide whether to be naughty or not.
			 */
			rc = compute_evaluator( &ctx, "*",
				rs->sr_entry, slapi_x_compute_output_ber );
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
		sl_free( e_flags, op->o_tmpmemctx );
		e_flags = NULL;
	}

	attrs_free( aa );
	rc = ber_printf( ber, /*{{*/ "}N}" );

	if( rc != -1 && rs->sr_ctrls != NULL ) {
		rc = send_ldap_controls( ber, rs->sr_ctrls );
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
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_entry: conn %lu ber_printf failed\n", 
			op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

		if ( op->o_res_ber == NULL ) ber_free_buf( ber );
		send_ldap_error( op, rs, LDAP_OTHER, "encode entry end error" );
		sl_release( mark, op->o_tmpmemctx );
		return( 1 );
	}

	if ( op->o_res_ber == NULL ) {
		bytes = op->o_noop ? 0 : send_ldap_ber( op->o_conn, ber );
		ber_free_buf( ber );

		if ( bytes < 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				"send_search_entry: conn %lu  ber write failed.\n", 
				op->o_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"send_search_entry: ber write failed\n",
				0, 0, 0 );
#endif

			sl_release( mark, op->o_tmpmemctx );
			return -1;
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

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_search_entry: conn %lu exit.\n", op->o_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= send_search_entry\n", 0, 0, 0 );
#endif

	rc = 0;

error_return:;
	sl_release( mark, op->o_tmpmemctx );
	if ( e_flags ) sl_free( e_flags, op->o_tmpmemctx );
	return( rc );
}

int
slap_send_search_reference( Operation *op, SlapReply *rs )
{
	BerElementBuffer berbuf;
	BerElement	*ber = (BerElement *) &berbuf;
	int rc = 0;
	int bytes;
	void *mark;

	AttributeDescription *ad_ref = slap_schema.si_ad_ref;
	AttributeDescription *ad_entry = slap_schema.si_ad_entry;

	rs->sr_type = REP_SEARCHREF;
	if (op->o_callback && op->o_callback->sc_response) {
		rc = op->o_callback->sc_response( op, rs );
		if ( rc != SLAP_CB_CONTINUE ) return rc;
	}

	mark = sl_mark( op->o_tmpmemctx );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_search_reference: conn %lu  dn=\"%s\"\n", 
		op->o_connid,
		rs->sr_entry ? rs->sr_entry->e_name.bv_val : "(null)", 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"=> send_search_reference: dn=\"%s\"\n",
		rs->sr_entry ? rs->sr_entry->e_name.bv_val : "(null)", 0, 0 );
#endif

	if (  rs->sr_entry && ! access_allowed( op, rs->sr_entry,
		ad_entry, NULL, ACL_READ, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( ACL, INFO, 
			"send_search_reference: conn %lu	"
			"access to entry %s not allowed\n",
			op->o_connid, rs->sr_entry->e_dn, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"send_search_reference: access to entry not allowed\n",
		    0, 0, 0 );
#endif
		rc = 1;
		goto rel;
	}

	if ( rs->sr_entry && ! access_allowed( op, rs->sr_entry,
		ad_ref, NULL, ACL_READ, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( ACL, INFO, 
			"send_search_reference: conn %lu access "
			"to reference not allowed.\n", op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"send_search_reference: access "
			"to reference not allowed\n",
		    0, 0, 0 );
#endif
		rc = 1;
		goto rel;
	}

#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
	if( op->o_domain_scope ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_reference: conn %lu domainScope control in (%s).\n",
			op->o_connid, rs->sr_entry->e_dn, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: domainScope control in (%s)\n", 
			rs->sr_entry->e_dn, 0, 0 );
#endif
		rc = 0;
		goto rel;
	}
#endif

	if( rs->sr_ref == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_reference: conn %lu null ref in (%s).\n",
			op->o_connid, rs->sr_entry ? rs->sr_entry->e_dn : "(null)", 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: null ref in (%s)\n", 
			rs->sr_entry ? rs->sr_entry->e_dn : "(null)", 0, 0 );
#endif
		rc = 1;
		goto rel;
	}

	if( op->o_protocol < LDAP_VERSION3 ) {
		/* save the references for the result */
		if( rs->sr_ref[0].bv_val != NULL ) {
			if( value_add( &rs->sr_v2ref, rs->sr_ref ) )
				return LDAP_OTHER;
		}
		rc = 0;
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

	if( rc != -1 && rs->sr_ctrls != NULL ) {
		rc = send_ldap_controls( ber, rs->sr_ctrls );
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}

	if ( rc == -1 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_reference: conn %lu	"
			"ber_printf failed.\n", op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: ber_printf failed\n", 0, 0, 0 );
#endif

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
	bytes = op->o_noop ? 0 : send_ldap_ber( op->o_conn, ber );
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

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_search_reference: conn %lu exit.\n", op->o_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= send_search_reference\n", 0, 0, 0 );
#endif

rel:
	sl_release( mark, op->o_tmpmemctx );
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

	if ( strncasecmp( s, "RESULT", 6 ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"str2result: (%s), expecting \"RESULT\"\n", s, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "str2result (%s) expecting \"RESULT\"\n",
		    s, 0, 0 );
#endif

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

		if ( strncasecmp( s, "code", 4 ) == 0 ) {
			if ( c != NULL ) {
				*code = atoi( c );
			}
		} else if ( strncasecmp( s, "matched", 7 ) == 0 ) {
			if ( c != NULL ) {
				*matched = c;
			}
		} else if ( strncasecmp( s, "info", 4 ) == 0 ) {
			if ( c != NULL ) {
				*info = c;
			}
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, "str2result: (%s) unknown.\n", s, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "str2result (%s) unknown\n",
			    s, 0, 0 );
#endif

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

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, INFO, "slap_read_controls: (%s) %s\n",
		oid->bv_val, e->e_dn, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "slap_read_controls: (%s) %s\n",
		oid->bv_val, e->e_dn, 0 );
#endif

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

	*ctrl = sl_calloc( 1, sizeof(LDAPControl), NULL );
	**ctrl = c;
	return LDAP_SUCCESS;
}

/* result.c - routines to send ldap results, errors, and referrals */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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
#include "slapi.h"

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

static void
send_ldap_response(
    Connection	*conn,
    Operation	*op,
	ber_tag_t	tag,
	ber_int_t	msgid,
    ber_int_t	err,
    const char	*matched,
    const char	*text,
	BerVarray	ref,
	const char	*resoid,
	struct berval	*resdata,
	struct berval	*sasldata,
	LDAPControl **ctrls
)
{
	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement	*ber = (BerElement *)berbuf;
	int		rc;
	long	bytes;

	if (op->o_callback && op->o_callback->sc_response) {
		op->o_callback->sc_response( conn, op, tag, msgid, err, matched,
			text, ref, resoid, resdata, sasldata, ctrls );
		return;
	}
		
#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp)
		ber = op->o_res_ber;
	else
#endif

	ber_init_w_nullc( ber, LBER_USE_DER );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_response:  msgid=%d tag=%lu err=%d\n",
		msgid, tag, err );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_response: msgid=%d tag=%lu err=%d\n",
		msgid, tag, err );
#endif

	if( ref ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ARGS, 
			"send_ldap_response: conn %lu  ref=\"%s\"\n",
			conn ? conn->c_connid : 0, 
			ref[0].bv_val ? ref[0].bv_val : "NULL" , 0 );
#else
		Debug( LDAP_DEBUG_ARGS, "send_ldap_response: ref=\"%s\"\n",
			ref[0].bv_val ? ref[0].bv_val : "NULL",
			NULL, NULL );
#endif
	}

#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp && conn->c_protocol == LDAP_VERSION2) {
		rc = ber_printf( ber, "t{ess" /*"}}"*/,
			tag, err,
		matched == NULL ? "" : matched,
		text == NULL ? "" : text );
	} else 
#endif
	{
	    rc = ber_printf( ber, "{it{ess" /*"}}"*/,
		msgid, tag, err,
		matched == NULL ? "" : matched,
		text == NULL ? "" : text );
	}

	if( rc != -1 ) {
		if ( ref != NULL ) {
			assert( err == LDAP_REFERRAL );
			rc = ber_printf( ber, "t{W}",
				LDAP_TAG_REFERRAL, ref );
		} else {
			assert( err != LDAP_REFERRAL );
		}
	}

	if( rc != -1 && sasldata != NULL ) {
		rc = ber_printf( ber, "tO",
			LDAP_TAG_SASL_RES_CREDS, sasldata );
	}

	if( rc != -1 && resoid != NULL ) {
		rc = ber_printf( ber, "ts",
			LDAP_TAG_EXOP_RES_OID, resoid );
	}

	if( rc != -1 && resdata != NULL ) {
		rc = ber_printf( ber, "tO",
			LDAP_TAG_EXOP_RES_VALUE, resdata );
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}

	if( rc != -1 && ctrls != NULL ) {
		rc = send_ldap_controls( ber, ctrls );
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}" );
	}

	if ( rc == -1 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_ldap_response: conn %lu  ber_printf failed\n",
			conn ? conn->c_connid : 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

#ifdef LDAP_CONNECTIONLESS
		if (conn->c_is_udp == 0)
#endif
		ber_free_buf( ber );
		return;
	}

	/* send BER */
	bytes = send_ldap_ber( conn, ber );
#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp == 0)
#endif
	ber_free_buf( ber );

	if ( bytes < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_ldap_response: conn %lu ber write failed\n",
			conn ? conn->c_connid : 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"send_ldap_response: ber write failed\n",
			0, 0, 0 );
#endif

		return;
	}

#ifdef LDAP_SLAPI
	slapi_pblock_set( op->o_pb, SLAPI_RESULT_CODE, (void *)err );
	slapi_pblock_set( op->o_pb, SLAPI_RESULT_MATCHED, ( matched != NULL ) ? (void *)ch_strdup( matched ) : NULL );
	slapi_pblock_set( op->o_pb, SLAPI_RESULT_TEXT, ( text != NULL ) ? (void *)ch_strdup( text ) : NULL );
#endif /* LDAP_SLAPI */

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_pdu_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );
	return;
}


void
send_ldap_disconnect(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*text
)
{
	ber_tag_t tag;
	ber_int_t msgid;
	char *reqoid;

#define LDAP_UNSOLICITED_ERROR(e) \
	(  (e) == LDAP_PROTOCOL_ERROR \
	|| (e) == LDAP_STRONG_AUTH_REQUIRED \
	|| (e) == LDAP_UNAVAILABLE )

	assert( LDAP_UNSOLICITED_ERROR( err ) );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_disconnect: conn %lu  %d:%s\n",
		conn ? conn->c_connid : 0, err, text ? text : "" );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_disconnect %d:%s\n",
		err, text ? text : "", NULL );
#endif


	if ( op->o_protocol < LDAP_VERSION3 ) {
		reqoid = NULL;
		tag = req2res( op->o_tag );
		msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	} else {
		reqoid = LDAP_NOTICE_DISCONNECT;
		tag = LDAP_RES_EXTENDED;
		msgid = 0;
	}

	send_ldap_response( conn, op, tag, msgid,
		err, NULL, text, NULL,
		reqoid, NULL, NULL, NULL );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%lu op=%lu DISCONNECT tag=%lu err=%d text=%s\n",
		op->o_connid, op->o_opid, tag, err, text ? text : "" );
}

void
slap_send_ldap_result(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
    const char	*text,
	BerVarray ref,
	LDAPControl **ctrls
)
{
	ber_tag_t tag;
	ber_int_t msgid;
	char *tmp = NULL;

	assert( !LDAP_API_ERROR( err ) );

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
		err, matched ? matched : "", text ? text : "" );
#else
	Debug( LDAP_DEBUG_ARGS,
		"send_ldap_result: err=%d matched=\"%s\" text=\"%s\"\n",
		err, matched ?	matched : "", text ? text : "" );
#endif


	if( ref ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ARGS, 
			"send_ldap_result: referral=\"%s\"\n",
			ref[0].bv_val ? ref[0].bv_val : "NULL", 0, 0 );
#else
		Debug( LDAP_DEBUG_ARGS,
			"send_ldap_result: referral=\"%s\"\n",
			ref[0].bv_val ? ref[0].bv_val : "NULL",
			NULL, NULL );
#endif
	}

	assert( err != LDAP_PARTIAL_RESULTS );

	if ( err == LDAP_REFERRAL ) {
#ifdef LDAP_CONTROL_NOREFERRALS
		if( op->o_noreferrals ) {
			ref = NULL;
		}
#endif
		if( ref == NULL ) {
			err = LDAP_NO_SUCH_OBJECT;
		} else if ( op->o_protocol < LDAP_VERSION3 ) {
			err = LDAP_PARTIAL_RESULTS;
		}
	}

	if ( op->o_protocol < LDAP_VERSION3 ) {
		tmp = v2ref( ref, text );
		text = tmp;
		ref = NULL;
	}

	tag = req2res( op->o_tag );
	msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, ref,
		NULL, NULL, NULL, ctrls );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%lu op=%lu RESULT tag=%lu err=%d text=%s\n",
		op->o_connid, op->o_opid, tag, err, text ? text : "" );

	if( tmp != NULL ) {
		ch_free(tmp);
	}
}

void
send_ldap_sasl(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
    const char	*text,
	BerVarray ref,
	LDAPControl **ctrls,
	struct berval *cred
)
{
	ber_tag_t tag;
	ber_int_t msgid;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_sasl: conn %lu err=%d len=%lu\n",
		op->o_connid, err, cred ? cred->bv_len : -1 );
#else
	Debug( LDAP_DEBUG_TRACE, "send_ldap_sasl: err=%d len=%ld\n",
		err, cred ? (long) cred->bv_len : -1, NULL );
#endif


	tag = req2res( op->o_tag );
	msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, ref,
		NULL, NULL, cred, ctrls	 );
}

void
slap_send_ldap_extended(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
    const char	*text,
    BerVarray	refs,
    const char		*rspoid,
	struct berval *rspdata,
	LDAPControl **ctrls
)
{
	ber_tag_t tag;
	ber_int_t msgid;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_ldap_extended: err=%d oid=%s len=%ld\n",
		err, rspoid ? rspoid : "",
		rspdata != NULL ? rspdata->bv_len : 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_extended: err=%d oid=%s len=%ld\n",
		err,
		rspoid ? rspoid : "",
		rspdata != NULL ? rspdata->bv_len : 0 );
#endif

	tag = req2res( op->o_tag );
	msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, refs,
		rspoid, rspdata, NULL, ctrls );
}

#ifdef LDAP_RES_INTERMEDIATE_RESP
void
slap_send_ldap_intermediate_resp(
	Connection  *conn,
	Operation   *op,
	ber_int_t   err,
	const char  *matched,
	const char  *text,
	BerVarray   refs,
	const char  *rspoid,
	struct berval *rspdata,
	LDAPControl **ctrls )
{
	ber_tag_t tag;
	ber_int_t msgid;
#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY,
		"send_ldap_intermediate: err=%d oid=%s len=%ld\n",
		err, rspoid ? rspoid : "",
		rspdata != NULL ? rspdata->bv_len : 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_intermediate: err=%d oid=%s len=%ld\n",
		err,
		rspoid ? rspoid : "",
		rspdata != NULL ? rspdata->bv_len : 0 );
#endif
	tag = LDAP_RES_INTERMEDIATE_RESP;
	msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;
	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, refs,
		rspoid, rspdata, NULL, ctrls );
}
#endif

void
slap_send_search_result(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
	const char	*text,
    BerVarray	refs,
	LDAPControl **ctrls,
    int		nentries
)
{
	ber_tag_t tag;
	ber_int_t msgid;
	char *tmp = NULL;

	assert( !LDAP_API_ERROR( err ) );

	if (op->o_callback && op->o_callback->sc_sresult) {
		op->o_callback->sc_sresult(conn, op, err, matched, text, refs,
			ctrls, nentries);
		return;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_search_result: err=%d matched=\"%s\" text=\"%s\"\n",
		err, matched ? matched : "", text ? text : "" );
#else
	Debug( LDAP_DEBUG_TRACE,
		"send_search_result: err=%d matched=\"%s\" text=\"%s\"\n",
		err, matched ?	matched : "", text ? text : "" );
#endif


	assert( err != LDAP_PARTIAL_RESULTS );

	if( op->o_protocol < LDAP_VERSION3 ) {
		/* send references in search results */
		if( err == LDAP_REFERRAL ) {
			err = LDAP_PARTIAL_RESULTS;
		}

		tmp = v2ref( refs, text );
		text = tmp;
		refs = NULL;

	} else {
		/* don't send references in search results */
		assert( refs == NULL );
		refs = NULL;

		if( err == LDAP_REFERRAL ) {
			err = LDAP_SUCCESS;
		}
	}

	tag = req2res( op->o_tag );
	msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, refs,
		NULL, NULL, NULL, ctrls );

	{
	char nbuf[64];
	snprintf( nbuf, sizeof nbuf, "%d nentries=%d", err, nentries );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%lu op=%lu SEARCH RESULT tag=%lu err=%s text=%s\n",
		op->o_connid, op->o_opid, tag, nbuf, text ? text : "" );
	}

	if (tmp != NULL) {
	    ch_free(tmp);
	}
}

int
slap_send_search_entry(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    AttributeName	*attrs,
    int		attrsonly,
	LDAPControl **ctrls
)
{
	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement	*ber = (BerElement *)berbuf;
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

	AttributeDescription *ad_entry = slap_schema.si_ad_entry;

	/* a_flags: array of flags telling if the i-th element will be
	 *          returned or filtered out
	 * e_flags: array of a_flags
	 */
	char **e_flags = NULL;

	if (op->o_callback && op->o_callback->sc_sendentry) {
		return op->o_callback->sc_sendentry( be, conn, op, e, attrs,
			attrsonly, ctrls );
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_search_entry: conn %lu	dn=\"%s\"%s\n",
		op->o_connid, e->e_dn, attrsonly ? " (attrsOnly)" : "" );
#else
	Debug( LDAP_DEBUG_TRACE,
		"=> send_search_entry: dn=\"%s\"%s\n",
		e->e_dn, attrsonly ? " (attrsOnly)" : "", 0 );
#endif

	if ( ! access_allowed( be, conn, op, e,
		ad_entry, NULL, ACL_READ, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( ACL, INFO, 
			"send_search_entry: conn %lu access to entry (%s) not allowed\n", 
			op->o_connid, e->e_dn, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"send_search_entry: access to entry not allowed\n",
		    0, 0, 0 );
#endif

		return( 1 );
	}

	edn = e->e_ndn;

#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp)
	    ber = op->o_res_ber;
	else
#endif
	ber_init_w_nullc( ber, LBER_USE_DER );

#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp && conn->c_protocol == LDAP_VERSION2) {
	    rc = ber_printf(ber, "t{0{" /*}}*/,
		LDAP_RES_SEARCH_ENTRY, &e->e_name);
	} else
#endif
	{
	    rc = ber_printf( ber, "{it{O{" /*}}}*/, op->o_msgid,
		LDAP_RES_SEARCH_ENTRY, &e->e_name );
	}

	if ( rc == -1 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_entry: conn %lu  ber_printf failed\n", 
			op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

#ifdef LDAP_CONNECTIONLESS
		if (conn->c_is_udp == 0)
#endif
		ber_free_buf( ber );
		send_ldap_result( conn, op, LDAP_OTHER,
		    NULL, "encoding DN error", NULL, NULL );
		goto error_return;
	}

	/* check for special all user attributes ("*") type */
	userattrs = ( attrs == NULL ) ? 1
		: an_find( attrs, &AllUser );

	/* check for special all operational attributes ("+") type */
	opattrs = ( attrs == NULL ) ? 0
		: an_find( attrs, &AllOper );

	/* create an array of arrays of flags. Each flag corresponds
	 * to particular value of attribute and equals 1 if value matches
	 * to ValuesReturnFilter or 0 if not
	 */	
	if ( op->vrFilter != NULL ) {
		int	k = 0;
		size_t	size;

		for ( a = e->e_attrs, i=0; a != NULL; a = a->a_next, i++ ) {
			for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) k++;
		}

		size = i * sizeof(char *) + k;
		if ( size > 0 ) {
			char	*a_flags;
			e_flags = SLAP_CALLOC ( 1, i * sizeof(char *) + k );
			if( e_flags == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"send_search_entry: conn %lu SLAP_CALLOC failed\n",
					conn ? conn->c_connid : 0, 0, 0 );
#else
		    	Debug( LDAP_DEBUG_ANY, 
					"send_search_entry: SLAP_CALLOC failed\n", 0, 0, 0 );
#endif
				ber_free( ber, 1 );
	
				send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "memory error", 
					NULL, NULL );
				goto error_return;
			}
			a_flags = (char *)(e_flags + i);
			memset( a_flags, 0, k );
			for ( a = e->e_attrs, i=0; a != NULL; a = a->a_next, i++ ) {
				for ( j = 0; a->a_vals[j].bv_val != NULL; j++ );
				e_flags[i] = a_flags;
				a_flags += j;
			}
	
			rc = filter_matched_values(be, conn, op, e->e_attrs, &e_flags) ; 
			if ( rc == -1 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"send_search_entry: conn %lu matched values filtering failed\n",
					conn ? conn->c_connid : 0, 0, 0 );
#else
		    	Debug( LDAP_DEBUG_ANY,
					"matched values filtering failed\n", 0, 0, 0 );
#endif
#ifdef LDAP_CONNECTIONLESS
			if (conn->c_is_udp == 0)
#endif
				ber_free( ber, 1 );
	
				send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "matched values filtering error", 
					NULL, NULL );
				goto error_return;
			}
		}
	}

	for ( a = e->e_attrs, j = 0; a != NULL; a = a->a_next, j++ ) {
		AttributeDescription *desc = a->a_desc;

		if ( attrs == NULL ) {
			/* all attrs request, skip operational attributes */
			if( is_at_operational( desc->ad_type ) ) {
				continue;
			}

		} else {
			/* specific attrs requested */
			if ( is_at_operational( desc->ad_type ) ) {
				if( !opattrs && !ad_inlist( desc, attrs ) ) {
					continue;
				}

			} else {
				if (!userattrs && !ad_inlist( desc, attrs ) ) {
					continue;
				}
			}
		}

		if ( ! access_allowed( be, conn, op, e, desc, NULL,
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

#ifdef LDAP_CONNECTIONLESS
			if (conn->c_is_udp == 0)
#endif
			ber_free_buf( ber );
			send_ldap_result( conn, op, LDAP_OTHER,
			    NULL, "encoding description error", NULL, NULL );
			goto error_return;
		}

		if ( ! attrsonly ) {
			for ( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
				if ( ! access_allowed( be, conn, op, e,
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

				if ( op->vrFilter && e_flags[j][i] == 0 ){
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

#ifdef LDAP_CONNECTIONLESS
					if (conn->c_is_udp == 0)
#endif
					ber_free_buf( ber );
					send_ldap_result( conn, op, LDAP_OTHER,
						NULL, "encoding values error",
						NULL, NULL );
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

#ifdef LDAP_CONNECTIONLESS
			if (conn->c_is_udp == 0)
#endif
			ber_free_buf( ber );
			send_ldap_result( conn, op, LDAP_OTHER,
			    NULL, "encode end error", NULL, NULL );
			goto error_return;
		}
	}

	/* eventually will loop through generated operational attributes */
	/* only have subschemaSubentry implemented */
	aa = backend_operational( be, conn, op, e, attrs, opattrs );

	if ( aa != NULL && op->vrFilter != NULL ) {
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
			tmp = SLAP_REALLOC ( e_flags, i * sizeof(char *) + k );
			if ( tmp == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"send_search_entry: conn %lu "
					"not enough memory "
					"for matched values filtering\n", 
					conn ? conn->c_connid : 0, 0, 0);
#else
			    	Debug( LDAP_DEBUG_ANY,
					"send_search_entry: conn %lu "
					"not enough memory "
					"for matched values filtering\n",
					conn ? conn->c_connid : 0, 0, 0 );
#endif
				ber_free( ber, 1 );
	
				send_ldap_result( conn, op, LDAP_NO_MEMORY,
					NULL, NULL, NULL, NULL );
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
			rc = filter_matched_values(be, conn, op, aa, &e_flags) ; 
		    
			if ( rc == -1 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"send_search_entry: conn %lu "
					"matched values filtering failed\n", 
					conn ? conn->c_connid : 0, 0, 0);
#else
			    	Debug( LDAP_DEBUG_ANY,
					"matched values filtering failed\n", 0, 0, 0 );
#endif
#ifdef LDAP_CONNECTIONLESS
			if (conn->c_is_udp == 0)
#endif
				ber_free( ber, 1 );
	
				send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "matched values filtering error", 
					NULL, NULL );
				goto error_return;
			}
		}
	}

	for (a = aa, j=0; a != NULL; a = a->a_next, j++ ) {
		AttributeDescription *desc = a->a_desc;

		if ( attrs == NULL ) {
			/* all attrs request, skip operational attributes */
			if( is_at_operational( desc->ad_type ) ) {
				continue;
			}

		} else {
			/* specific attrs requested */
			if( is_at_operational( desc->ad_type ) ) {
				if( !opattrs && !ad_inlist( desc, attrs ) ) {
					continue;
				}
			} else {
				if (!userattrs && !ad_inlist( desc, attrs ) )
				{
					continue;
				}
			}
		}

		if ( ! access_allowed( be, conn, op, e,	desc, NULL,
			ACL_READ, &acl_state ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( ACL, INFO, 
				"send_search_entry: conn %lu "
				"access to attribute %s not allowed\n",
				op->o_connid, desc->ad_cname.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ACL, "acl: access to attribute %s "
					"not allowed\n",
			    		desc->ad_cname.bv_val, 0, 0 );
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

#ifdef LDAP_CONNECTIONLESS
			if (conn->c_is_udp == 0)
#endif
			ber_free_buf( ber );
			send_ldap_result( conn, op, LDAP_OTHER,
			    NULL, "encoding description error", NULL, NULL );

			attrs_free( aa );
			goto error_return;
		}

		if ( ! attrsonly ) {
			for ( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
				if ( ! access_allowed( be, conn, op, e,
					desc, &a->a_vals[i], ACL_READ, &acl_state ) )
				{
#ifdef NEW_LOGGING
					LDAP_LOG( ACL, INFO, 
						"send_search_entry: conn %lu "
						"access to %s, value %d not allowed\n",
						op->o_connid, desc->ad_cname.bv_val, i );
#else
					Debug( LDAP_DEBUG_ACL,
						"acl: access to attribute %s, "
						"value %d not allowed\n",
						desc->ad_cname.bv_val, i, 0 );
#endif

					continue;
				}

				if ( op->vrFilter && e_flags[j][i] == 0 ){
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

#ifdef LDAP_CONNECTIONLESS
					if (conn->c_is_udp == 0)
#endif
					ber_free_buf( ber );
					send_ldap_result( conn, op, LDAP_OTHER,
						NULL, "encoding values error", 
						NULL, NULL );

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

#ifdef LDAP_CONNECTIONLESS
			if (conn->c_is_udp == 0)
#endif
			ber_free_buf( ber );
			send_ldap_result( conn, op, LDAP_OTHER,
			    NULL, "encode end error", NULL, NULL );

			attrs_free( aa );
			goto error_return;
		}
	}

#ifdef LDAP_SLAPI
	/*
	 * First, setup the computed attribute context that is
	 * passed to all plugins.
	 */
	ctx.cac_pb = op->o_pb;
	ctx.cac_attrs = attrs;
	ctx.cac_attrsonly = attrsonly;
	ctx.cac_userattrs = userattrs;
	ctx.cac_opattrs = opattrs;
	ctx.cac_acl_state = acl_state;
	ctx.cac_private = (void *)ber;

	/*
	 * For each client requested attribute, call the plugins.
	 */
	if ( attrs != NULL ) {
		for ( anp = attrs; anp->an_name.bv_val != NULL; anp++ ) {
			rc = compute_evaluator( &ctx, anp->an_name.bv_val, e, slapi_x_compute_output_ber );
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
		rc = compute_evaluator( &ctx, "*", e, slapi_x_compute_output_ber );
	}
	if ( rc == 1 ) {
		ber_free_buf( ber );
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "computed attribute error", NULL, NULL );
		goto error_return;
	}
#endif /* LDAP_SLAPI */

	/* free e_flags */
	if ( e_flags ) {
		free( e_flags );
		e_flags = NULL;
	}

	attrs_free( aa );
	rc = ber_printf( ber, /*{{*/ "}N}" );

	if( rc != -1 && ctrls != NULL ) {
		rc = send_ldap_controls( ber, ctrls );
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*{*/ "N}" );
	}

	if ( rc == -1 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_entry: conn %lu ber_printf failed\n", 
			op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
#endif

#ifdef LDAP_CONNECTIONLESS
		if (conn->c_is_udp == 0)
#endif
		ber_free_buf( ber );
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "encode entry end error", NULL, NULL );
		return( 1 );
	}

#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp == 0) {
#endif
	bytes = op->o_noop ? 0 : send_ldap_ber( conn, ber );
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

		return -1;
	}

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_entries_sent++;
	num_pdu_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );

#ifdef LDAP_CONNECTIONLESS
	}
#endif

	Statslog( LDAP_DEBUG_STATS2, "conn=%lu op=%lu ENTRY dn=\"%s\"\n",
	    conn->c_connid, op->o_opid, e->e_dn, 0, 0 );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_search_entry: conn %lu exit.\n", op->o_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= send_search_entry\n", 0, 0, 0 );
#endif

	rc = 0;

error_return:;
	if ( e_flags ) free( e_flags );
	return( rc );
}

int
slap_send_search_reference(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
	BerVarray refs,
	LDAPControl **ctrls,
    BerVarray *v2refs
)
{
	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement	*ber = (BerElement *)berbuf;
	int rc;
	int bytes;

	AttributeDescription *ad_ref = slap_schema.si_ad_ref;
	AttributeDescription *ad_entry = slap_schema.si_ad_entry;

	if (op->o_callback && op->o_callback->sc_sendreference) {
		return op->o_callback->sc_sendreference( be, conn, op, e, refs, ctrls, v2refs );
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_search_reference: conn %lu  dn=\"%s\"\n", 
		op->o_connid, e ? e->e_dn : "(null)", 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"=> send_search_reference: dn=\"%s\"\n",
		e ? e->e_dn : "(null)", 0, 0 );
#endif

	if (  e && ! access_allowed( be, conn, op, e,
		ad_entry, NULL, ACL_READ, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( ACL, INFO, 
			"send_search_reference: conn %lu	"
			"access to entry %s not allowed\n",
			op->o_connid, e->e_dn, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"send_search_reference: access to entry not allowed\n",
		    0, 0, 0 );
#endif

		return( 1 );
	}

	if ( e && ! access_allowed( be, conn, op, e,
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

		return( 1 );
	}

#ifdef LDAP_CONTROL_NOREFERRALS
	if( op->o_noreferrals ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_reference: conn %lu noreferrals control in (%s).\n",
			op->o_connid, e->e_dn, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: noreferrals control in (%s)\n", 
			e->e_dn, 0, 0 );
#endif

		return( 0 );
	}
#endif

	if( refs == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"send_search_reference: conn %lu null ref in (%s).\n",
			op->o_connid, e ? e->e_dn : "(null)", 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: null ref in (%s)\n", 
			e ? e->e_dn : "(null)", 0, 0 );
#endif

		return( 1 );
	}

	if( op->o_protocol < LDAP_VERSION3 ) {
		/* save the references for the result */
		if( refs[0].bv_val != NULL ) {
			if( value_add( v2refs, refs ) )
				return LDAP_OTHER;
		}
		return 0;
	}

#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp)
		ber = op->o_res_ber;
	else
#endif
	ber_init_w_nullc( ber, LBER_USE_DER );

	rc = ber_printf( ber, "{it{W}" /*"}"*/ , op->o_msgid,
		LDAP_RES_SEARCH_REFERENCE, refs );

	if( rc != -1 && ctrls != NULL ) {
		rc = send_ldap_controls( ber, ctrls );
	}

	if( rc != -1 ) {
		rc = ber_printf( ber, /*"{"*/ "N}", op->o_msgid,
			LDAP_RES_SEARCH_REFERENCE, refs );
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
		if (conn->c_is_udp == 0)
#endif
		ber_free_buf( ber );
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "encode DN error", NULL, NULL );
		return -1;
	}

#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp == 0) {
#endif
	bytes = op->o_noop ? 0 : send_ldap_ber( conn, ber );
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
		conn->c_connid, op->o_opid, e ? e->e_dn : "(null)", 0, 0 );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"send_search_reference: conn %lu exit.\n", op->o_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= send_search_reference\n", 0, 0, 0 );
#endif

	return 0;
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

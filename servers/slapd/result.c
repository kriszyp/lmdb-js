/* result.c - routines to send ldap results, errors, and referrals */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "slap.h"

/* we need LBER internals */
#include "../../libraries/liblber/lber-int.h"

static char *v2ref( struct berval **ref, const char *text )
{
	size_t len = 0, i = 0;
	char *v2;

	if(ref == NULL)
	{
	    if (text)
		return ch_strdup(text);
	    else
		return NULL;
	}
	
	if (text) {
		len = strlen( text );
		if (text[len-1] != '\n')
		    i = 1;
	}
	v2 = ch_malloc( len+i+sizeof("Referral:") );
	if (text) {
		strcpy(v2, text);
		if (i)
			v2[len++] = '\n';
	}
	strcpy( v2+len, "Referral:" );
	len += sizeof("Referral:");

	for( i=0; ref[i] != NULL; i++ ) {
		v2 = ch_realloc( v2, len + ref[i]->bv_len + 1 );
		v2[len-1] = '\n';
		memcpy(&v2[len], ref[i]->bv_val, ref[i]->bv_len );
		len += ref[i]->bv_len;
		if (ref[i]->bv_val[ref[i]->bv_len-1] != '/')
			++len;
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
		assert( 0 );
		tag = LBER_ERROR;
	}
	return tag;
}

static void trim_refs_urls(
	struct berval **refs )
{
	unsigned i;

	if( refs == NULL ) return;

	for( i=0; refs[i] != NULL; i++ ) {
		if(	refs[i]->bv_len > sizeof("ldap://")-1 &&
			strncasecmp( refs[i]->bv_val, "ldap://",
				sizeof("ldap://")-1 ) == 0 )
		{
			unsigned j;
			for( j=sizeof("ldap://")-1; j<refs[i]->bv_len ; j++ ) {
				if( refs[i]->bv_val[j] == '/' ) {
					refs[i]->bv_val[j] = '\0';
					refs[i]->bv_len = j;
					break;
				}
			}
		}
	}
}

struct berval **get_entry_referrals(
	Backend *be,
	Connection *conn,
	Operation *op,
	Entry *e )
{
	Attribute *attr;
	struct berval **refs;
	unsigned i, j;

	attr = attr_find( e->e_attrs, "ref" );

	if( attr == NULL ) return NULL;

	for( i=0; attr->a_vals[i] != NULL; i++ ) {
		/* count references */
	}

	if( i < 1 ) return NULL;

	refs = ch_malloc( i + 1 );

	for( i=0, j=0; attr->a_vals[i] != NULL; i++ ) {
		unsigned k;
		struct berval *ref = ber_bvdup( attr->a_vals[i] );

		/* trim the label */
		for( k=0; k<ref->bv_len; k++ ) {
			if( isspace(ref->bv_val[k]) ) {
				ref->bv_val[k] = '\0';
				ref->bv_len = k;
				break;
			}
		}

		if(	ref->bv_len > 0 ) {
			refs[j++] = ref;

		} else {
			ber_bvfree( ref );
		}
	}

	refs[j] = NULL;

	if( j == 0 ) {
		ber_bvecfree( refs );
		refs = NULL;
	}

	/* we should check that a referral value exists... */

	return refs;
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
		    err, STRERROR(err), 0 );

		if ( err != EWOULDBLOCK && err != EAGAIN ) {
			connection_closing( conn );

			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
			ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );

			return( -1 );
		}

		/* wait for socket to be write-ready */
		conn->c_writewaiter = 1;
		slapd_set_write( ber_pvt_sb_get_desc( conn->c_sb ), 1 );

		ldap_pvt_thread_cond_wait( &conn->c_write_cv, &conn->c_mutex );
		conn->c_writewaiter = 0;
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
	ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );

	return bytes;
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
	struct berval	**ref,
	const char	*resoid,
	struct berval	*resdata,
	struct berval	*sasldata,
	LDAPControl **ctrls
)
{
	BerElement	*ber;
	int		rc;
	long	bytes;

	assert( ctrls == NULL ); /* ctrls not implemented */

	ber = ber_alloc_t( LBER_USE_DER );

	Debug( LDAP_DEBUG_TRACE, "send_ldap_response: msgid=%ld tag=%ld err=%ld\n",
		(long) msgid, (long) tag, (long) err );

	if ( ber == NULL ) {
		Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n", 0, 0, 0 );
		return;
	}

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		rc = ber_printf( ber, "{is{t{ess}}}", msgid, "", tag,
		    err, matched ? matched : "", text ? text : "" );
	} else
#endif
	{
		rc = ber_printf( ber, "{it{ess",
			msgid, tag, err,
			matched == NULL ? "" : matched,
			text == NULL ? "" : text );

		if( rc != -1 && ref != NULL ) {
			rc = ber_printf( ber, "{V}", ref );
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
			rc = ber_printf( ber, "}}" );
		}
	}

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		ber_free( ber, 1 );
		return;
	}

	/* send BER */
	bytes = send_ldap_ber( conn, ber );
	ber_free( ber, 1 );

	if ( bytes < 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"send_ldap_response: ber write failed\n",
			0, 0, 0 );
		return;
	}

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

	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_disconnect %d:%s\n",
		err, text ? text : "", NULL );

	if ( op->o_protocol < LDAP_VERSION3 ) {
		reqoid = NULL;
		tag = req2res( op->o_tag );
		msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;

	} else {
		reqoid = LDAP_NOTICE_DISCONNECT;
		tag = LDAP_RES_EXTENDED;
		msgid = 0;
	}

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		ber_pvt_sb_udp_set_dst( conn->c_sb, &op->o_clientaddr );
		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &op->o_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *) &op->o_clientaddr)->sin_port,
		    0 );
	}
#endif

	send_ldap_response( conn, op, tag, msgid,
		err, NULL, text, NULL,
		reqoid, NULL, NULL, NULL );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%ld op=%ld DISCONNECT err=%ld tag=%lu text=%s\n",
		(long) op->o_connid, (long) op->o_opid,
		(long) tag, (long) err, text ? text : "" );
}

void
send_ldap_result(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
    const char	*text,
	struct berval **ref,
	LDAPControl **ctrls
)
{
	ber_tag_t tag;
	ber_int_t msgid;
	char *tmp = NULL;

	assert( !LDAP_API_ERROR( err ) );

	Debug( LDAP_DEBUG_TRACE, "send_ldap_result: conn=%ld op=%ld p=%d\n",
		(long) op->o_connid, (long) op->o_opid, op->o_protocol );
	Debug( LDAP_DEBUG_ARGS, "send_ldap_result: %d:%s:%s\n",
		err, matched ?  matched : "", text ? text : "" );

	assert( err != LDAP_PARTIAL_RESULTS );

	if( op->o_tag != LDAP_REQ_SEARCH ) {
		trim_refs_urls( ref );
	}

	if ( err == LDAP_REFERRAL ) {
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

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		ber_pvt_sb_udp_set_dst( conn->c_sb, &op->o_clientaddr );
		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &op->o_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *) &op->o_clientaddr)->sin_port,
		    0 );
	}
#endif

	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, ref,
		NULL, NULL, NULL, ctrls );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%ld op=%ld RESULT tag=%lu err=%ld text=%s\n",
		(long) op->o_connid, (long) op->o_opid,
		(long) tag, (long) err, text ? text : "" );

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
	struct berval **ref,
	LDAPControl **ctrls,
	struct berval *cred
)
{
	ber_tag_t tag;
	ber_int_t msgid;

	Debug( LDAP_DEBUG_TRACE, "send_ldap_sasl %ld\n",
		(long) err, NULL, NULL );

	tag = req2res( op->o_tag );
	msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		ber_pvt_sb_udp_set_dst( conn->c_sb, &op->o_clientaddr );
		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &op->o_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *) &op->o_clientaddr)->sin_port,
		    0 );
	}
#endif

	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, ref,
		NULL, NULL, cred, ctrls  );
}

void
send_ldap_extended(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
    const char	*text,
    struct berval **refs,
    char		*rspoid,
	struct berval *rspdata,
	LDAPControl **ctrls
)
{
	ber_tag_t tag;
	ber_int_t msgid;

	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_extended %ld:%s (%ld)\n",
		(long) err,
		rspoid ? rspoid : "",
		rspdata != NULL ? (long) rspdata->bv_len : (long) 0 );

	tag = req2res( op->o_tag );
	msgid = (tag != LBER_SEQUENCE) ? op->o_msgid : 0;

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		ber_pvt_sb_udp_set_dst( conn->c_sb, &op->o_clientaddr );
		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &op->o_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *) &op->o_clientaddr)->sin_port,
		    0 );
	}
#endif

	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, refs,
		rspoid, rspdata, NULL, ctrls );
}


void
send_search_result(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
	const char	*text,
    struct berval **refs,
	LDAPControl **ctrls,
    int		nentries
)
{
	ber_tag_t tag;
	ber_int_t msgid;
	char *tmp = NULL;
	assert( !LDAP_API_ERROR( err ) );

	Debug( LDAP_DEBUG_TRACE, "send_ldap_search_result %d:%s:%s\n",
		err, matched ?  matched : "", text ? text : "" );

	assert( err != LDAP_PARTIAL_RESULTS );

	trim_refs_urls( refs );

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

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		ber_pvt_sb_udp_set_dst( conn->c_sb, &op->o_clientaddr );
		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &op->o_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *) &op->o_clientaddr)->sin_port,
		    0 );
	}
#endif

	send_ldap_response( conn, op, tag, msgid,
		err, matched, text, refs,
		NULL, NULL, NULL, ctrls );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%ld op=%ld SEARCH RESULT tag=%lu err=%ld text=%s\n",
		(long) op->o_connid, (long) op->o_opid,
		(long) tag, (long) err, text ? text : "" );

	if (tmp != NULL)
	    ch_free(tmp);
}


int
send_search_entry(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    char	**attrs,
    int		attrsonly,
	LDAPControl **ctrls
)
{
	BerElement	*ber;
	Attribute	*a;
	int		i, rc=-1, bytes;
	char            *edn;
	int		userattrs;
	int		opattrs;

	Debug( LDAP_DEBUG_TRACE, "=> send_search_entry: \"%s\"\n", e->e_dn, 0, 0 );

	if ( ! access_allowed( be, conn, op, e,
		"entry", NULL, ACL_READ ) )
	{
		Debug( LDAP_DEBUG_ACL, "acl: access to entry not allowed\n",
		    0, 0, 0 );
		return( 1 );
	}

	edn = e->e_ndn;

	ber = ber_alloc_t( LBER_USE_DER );

	if ( ber == NULL ) {
		Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, "allocating BER error", NULL, NULL );
		goto error_return;
	}

	rc = ber_printf( ber, "{it{s{", op->o_msgid,
		LDAP_RES_SEARCH_ENTRY, e->e_dn );

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		ber_free( ber, 1 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
		    NULL, "encoding dn error", NULL, NULL );
		goto error_return;
	}

	/* check for special all user attributes ("*") type */
	userattrs = ( attrs == NULL ) ? 1
		: charray_inlist( attrs, LDAP_ALL_USER_ATTRIBUTES );

	/* check for special all operational attributes ("+") type */
	opattrs = ( attrs == NULL ) ? 0
		: charray_inlist( attrs, LDAP_ALL_OPERATIONAL_ATTRIBUTES );

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		if ( attrs == NULL ) {
			/* all addrs request, skip operational attributes */
			if( !opattrs && oc_check_operational_attr( a->a_type ) ) {
				continue;
			}

		} else {
			/* specific addrs requested */
			if (  oc_check_operational_attr( a->a_type ) ) {
				if( !opattrs && !charray_inlist( attrs, a->a_type ) )
				{
					continue;
				}
			} else {
				if (!userattrs && !charray_inlist( attrs, a->a_type ) )
				{
					continue;
				}
			}
		}

		if ( ! access_allowed( be, conn, op, e,
			a->a_type, NULL, ACL_READ ) )
		{
			Debug( LDAP_DEBUG_ACL, "acl: access to attribute %s not allowed\n",
			    a->a_type, 0, 0 );
			continue;
		}

		if (( rc = ber_printf( ber, "{s[" /*]}*/ , a->a_type )) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( ber, 1 );
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			    NULL, "encoding type error", NULL, NULL );
			goto error_return;
		}

		if ( ! attrsonly ) {
			for ( i = 0; a->a_vals[i] != NULL; i++ ) {
				if ( ! access_allowed( be, conn, op, e,
					a->a_type, a->a_vals[i], ACL_READ ) )
				{
					Debug( LDAP_DEBUG_ACL,
						"acl: access to attribute %s, value %d not allowed\n",
			    		a->a_type, i, 0 );
					continue;
				}

				if (( rc = ber_printf( ber, "O", a->a_vals[i] )) == -1 ) {
					Debug( LDAP_DEBUG_ANY,
					    "ber_printf failed\n", 0, 0, 0 );
					ber_free( ber, 1 );
					send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
						NULL, "encoding value error", NULL, NULL );
					goto error_return;
				}
			}
		}

		if (( rc = ber_printf( ber, /*{[*/ "]}" )) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( ber, 1 );
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			    NULL, "encode end error", NULL, NULL );
			goto error_return;
		}
	}

#ifdef SLAPD_SCHEMA_DN
	/* eventually will loop through generated operational attributes */
	/* only have subschemaSubentry implemented */
	a = backend_subschemasubentry( be );
	
	do {
		if ( attrs == NULL ) {
			/* all addrs request, skip operational attributes */
			if( !opattrs && oc_check_operational_attr( a->a_type ) ) {
				continue;
			}

		} else {
			/* specific addrs requested */
			if (  oc_check_operational_attr( a->a_type ) ) {
				if( !opattrs && !charray_inlist( attrs, a->a_type ) )
				{
					continue;
				}
			} else {
				if (!userattrs && !charray_inlist( attrs, a->a_type ) )
				{
					continue;
				}
			}
		}

		if ( ! access_allowed( be, conn, op, e,
			a->a_type, NULL, ACL_READ ) )
		{
			Debug( LDAP_DEBUG_ACL, "acl: access to attribute %s not allowed\n",
			    a->a_type, 0, 0 );
			continue;
		}

		if (( rc = ber_printf( ber, "{s[" /*]}*/ , a->a_type )) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( ber, 1 );
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			    NULL, "encoding type error", NULL, NULL );
			goto error_return;
		}

		if ( ! attrsonly ) {
			for ( i = 0; a->a_vals[i] != NULL; i++ ) {
				if ( ! access_allowed( be, conn, op, e,
					a->a_type, a->a_vals[i], ACL_READ ) )
				{
					Debug( LDAP_DEBUG_ACL,
						"acl: access to attribute %s, value %d not allowed\n",
			    		a->a_type, i, 0 );
					continue;
				}


				if (( rc = ber_printf( ber, "O", a->a_vals[i] )) == -1 ) {
					Debug( LDAP_DEBUG_ANY,
					    "ber_printf failed\n", 0, 0, 0 );
					ber_free( ber, 1 );
					send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
						NULL, "encoding value error", NULL, NULL );
					goto error_return;
				}
			}
		}

		if (( rc = ber_printf( ber, /*{[*/ "]}" )) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( ber, 1 );
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			    NULL, "encode end error", NULL, NULL );
			goto error_return;
		}
	} while (0);
#endif

	rc = ber_printf( ber, /*{{{*/ "}}}" );

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		ber_free( ber, 1 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, "encode entry end error", NULL, NULL );
		return( 1 );
	}

	bytes = send_ldap_ber( conn, ber );
	ber_free( ber, 1 );

	if ( bytes < 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"send_ldap_response: ber write failed\n",
			0, 0, 0 );
		return -1;
	}

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_entries_sent++;
	num_pdu_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );

	Statslog( LDAP_DEBUG_STATS2, "conn=%ld op=%ld ENTRY dn=\"%s\"\n",
	    (long) conn->c_connid, (long) op->o_opid, e->e_dn, 0, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= send_search_entry\n", 0, 0, 0 );

	rc = 0;

error_return:;
	return( rc );
}

int
send_search_reference(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
	struct berval **refs,
	int scope,
	LDAPControl **ctrls,
    struct berval ***v2refs
)
{
	BerElement	*ber;
	int rc;
	int bytes;

	Debug( LDAP_DEBUG_TRACE, "=> send_search_reference (%s)\n", e->e_dn, 0, 0 );

	if ( ! access_allowed( be, conn, op, e,
		"entry", NULL, ACL_READ ) )
	{
		Debug( LDAP_DEBUG_ACL,
			"send_search_reference: access to entry not allowed\n",
		    0, 0, 0 );
		return( 1 );
	}

	if ( ! access_allowed( be, conn, op, e,
		"ref", NULL, ACL_READ ) )
	{
		Debug( LDAP_DEBUG_ACL,
			"send_search_reference: access to reference not allowed\n",
		    0, 0, 0 );
		return( 1 );
	}

	if( refs == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: null ref in (%s)\n", 
			e->e_dn, 0, 0 );
		return( 1 );
	}

	if( op->o_protocol < LDAP_VERSION3 ) {
		/* save the references for the result */
		if( *refs != NULL ) {
			value_add( v2refs, refs );
		}
		return 0;
	}

	ber = ber_alloc_t( LBER_USE_DER );

	if ( ber == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: ber_alloc failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, "alloc BER error", NULL, NULL );
		return -1;
	}

	rc = ber_printf( ber, "{it{V}}", op->o_msgid,
		LDAP_RES_SEARCH_REFERENCE, refs );

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY,
			"send_search_reference: ber_printf failed\n", 0, 0, 0 );
		ber_free( ber, 1 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, "encode dn error", NULL, NULL );
		return -1;
	}

	bytes = send_ldap_ber( conn, ber );
	ber_free( ber, 1 );

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_refs_sent++;
	num_pdu_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );

	Statslog( LDAP_DEBUG_STATS2, "conn=%ld op=%ld ENTRY dn=\"%s\"\n",
	    (long) conn->c_connid, (long) op->o_opid, e->e_dn, 0, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= send_search_reference\n", 0, 0, 0 );

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
			Debug( LDAP_DEBUG_ANY, "str2result (%s) unknown\n",
			    s, 0, 0 );
			rc = -1;
		}
	}

	return( rc );
}

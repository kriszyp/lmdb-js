/* result.c - routines to send ldap results, errors, and referrals */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>		/* get close() */

#include "slap.h"

/* we need LBER internals */
#include "../../libraries/liblber/lber-int.h"

static void
send_ldap_result2(
    Connection	*conn,
    Operation	*op,
	int		disconnect,
    ber_int_t	err,
    char	*matched,
    char	*text,
    int		nentries
)
{
	BerElement	*ber;
	int		rc;
	ber_tag_t	tag;
	ber_len_t	bytes;
	int	msgid;

	assert( !LDAP_API_ERROR( err ) );

	if ( err == LDAP_PARTIAL_RESULTS && (text == NULL || *text == '\0') )
		err = LDAP_NO_SUCH_OBJECT;

	if( disconnect ) {
		msgid = 0;	/* unsolicited */
		if ( op->o_protocol > LDAP_VERSION3 ) {
			tag = LDAP_RES_EXTENDED;
		}

#define LDAP_UNSOLICITED_ERROR(e) \
	(  (e) == LDAP_PROTOCOL_ERROR \
	|| (e) == LDAP_STRONG_AUTH_REQUIRED \
	|| (e) == LDAP_UNAVAILABLE )

		assert( LDAP_UNSOLICITED_ERROR( err ) );

	} else {
		msgid = op->o_msgid;

		switch ( op->o_tag ) {
		case LDAP_REQ_ABANDON:
		case LDAP_REQ_UNBIND:
		case LBER_ERROR:
			tag = LBER_SEQUENCE;
			msgid = 0;
			assert( LDAP_UNSOLICITED_ERROR( err ) );
			break;

		case LDAP_REQ_SEARCH:
			tag = LDAP_RES_SEARCH_RESULT;
			break;

		case LDAP_REQ_DELETE:
			tag = LDAP_RES_DELETE;
			break;

		default:
			tag = op->o_tag + 1;
			break;
		}
	}


	ber = ber_alloc_t( LBER_USE_DER );

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
	if( tag == LDAP_RES_EXTENDED ) {
		rc = ber_printf( ber, "{it{esss}}",
			msgid, tag, err,
			"", text ? text : "",
			LDAP_NOTICE_DISCONNECT );

	} else {
		rc = ber_printf( ber, "{it{ess}}",
			msgid, tag, err,
			matched ? matched : "", text ? text : "" );
	}

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		return;
	}

	/* write only one pdu at a time - wait til it's our turn */
	ldap_pvt_thread_mutex_lock( &conn->c_write_mutex );

	/* lock the connection */
	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	/* write the pdu */
	bytes = ber_pvt_ber_bytes( ber );

	while ( 1 ) {
		int err;

		if ( connection_state_closing( conn ) ) {
			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
			ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );
			return;
		}

		if ( ber_flush( conn->c_sb, ber, 1 ) == 0 ) {
			break;
		}

		err = errno;

		/*
		 * we got an error.  if it's ewouldblock, we need to
		 * wait on the socket being writable.  otherwise, figure
		 * it's a hard error and return.
		 */

		Debug( LDAP_DEBUG_CONNS, "ber_flush failed errno %d msg (%s)\n",
		    err, err > -1 && err < sys_nerr ? sys_errlist[err]
		    : "unknown", 0 );

		if ( err != EWOULDBLOCK && err != EAGAIN ) {
			connection_closing( conn );

			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
			ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );
			return;
		}

		/* wait for socket to be write-ready */
		conn->c_writewaiter = 1;
		slapd_set_write( ber_pvt_sb_get_desc( conn->c_sb ), 1 );

		ldap_pvt_thread_cond_wait( &conn->c_write_cv, &conn->c_mutex );
		conn->c_writewaiter = 0;
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
	ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%ld op=%ld RESULT err=%ld tag=%lu nentries=%d\n",
		(long) conn->c_connid, (long) op->o_opid,
		(long) err, (long) tag, nentries );

	return;
}

void
send_ldap_result(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    char	*matched,
    char	*text
)
{
	assert( !LDAP_API_ERROR( err ) );

	Debug( LDAP_DEBUG_TRACE, "send_ldap_result %d:%s:%s\n",
		err, matched ?  matched : "", text ? text : "" );

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		ber_pvt_sb_udp_set_dst( &conn->c_sb, &op->o_clientaddr );
		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &op->o_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *) &op->o_clientaddr)->sin_port,
		    0 );
	}
#endif
	send_ldap_result2( conn, op, 0, err, matched, text, 0 );
}

void
send_ldap_disconnect(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    char	*text
)
{
	assert( !LDAP_API_ERROR( err ) );

	Debug( LDAP_DEBUG_TRACE,
		"send_ldap_disconnect %d:%s\n",
		err, text ? text : "", NULL );

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		ber_pvt_sb_udp_set_dst( &conn->c_sb, &op->o_clientaddr );
		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &op->o_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *) &op->o_clientaddr)->sin_port,
		    0 );
	}
#endif
	send_ldap_result2( conn, op, 0, err, NULL, text, 0 );
}

void
send_ldap_search_result(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    char	*matched,
    char	*text,
    int		nentries
)
{
	Debug( LDAP_DEBUG_TRACE, "send_ldap_search_result %d:%s:%s\n",
		err, matched ?  matched : "", text ? text : "" );

	send_ldap_result2( conn, op, 0, err, matched, text, nentries );
}

int
send_search_entry(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    char	**attrs,
    int		attrsonly,
	int		opattrs
)
{
	BerElement	*ber;
	Attribute	*a;
	int		i, rc=-1, bytes;
	struct acl	*acl;
	char            *edn;

	Debug( LDAP_DEBUG_TRACE, "=> send_search_entry (%s)\n", e->e_dn, 0, 0 );

#if defined( SLAPD_SCHEMA_DN )
	{
		/* this could be backend specific */
		struct	berval	val;
		val.bv_val = SLAPD_SCHEMA_DN;
		val.bv_len = strlen( val.bv_val );
		attr_merge( e, "subschemaSubentry", vals );
		ldap_memfree( val.bv_val );
	}
#endif

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
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
			"ber_alloc" );
		goto error_return;
	}

	rc = ber_printf( ber, "{it{s{", op->o_msgid,
		LDAP_RES_SEARCH_ENTRY, e->e_dn );

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		ber_free( ber, 1 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "ber_printf dn" );
		goto error_return;
	}

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		regmatch_t       matches[MAXREMATCHES];

		if ( attrs == NULL ) {
			/* all addrs request, skip operational attributes */
			if( !opattrs && oc_check_operational_attr( a->a_type )) {
				continue;
			}

		} else {
			/* specific addrs requested */
			if ( !charray_inlist( attrs, a->a_type )
				&& !charray_inlist( attrs, LDAP_ALL_USER_ATTRIBUTES ) )
			{
				continue;
			}
		}

		acl = acl_get_applicable( be, op, e, a->a_type,
			MAXREMATCHES, matches );

		if ( ! acl_access_allowed( acl, be, conn, e,
			NULL, op, ACL_READ, edn, matches ) ) 
		{
			continue;
		}

		if (( rc = ber_printf( ber, "{s[" /*]}*/ , a->a_type )) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( ber, 1 );
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			    NULL, "ber_printf type" );
			goto error_return;
		}

		if ( ! attrsonly ) {
			for ( i = 0; a->a_vals[i] != NULL; i++ ) {
				if ( a->a_syntax & SYNTAX_DN && 
					! acl_access_allowed( acl, be, conn, e, a->a_vals[i], op,
						ACL_READ, edn, matches) )
				{
					continue;
				}

				if (( rc = ber_printf( ber, "O", a->a_vals[i] )) == -1 ) {
					Debug( LDAP_DEBUG_ANY,
					    "ber_printf failed\n", 0, 0, 0 );
					ber_free( ber, 1 );
					send_ldap_result( conn, op,
					    LDAP_OPERATIONS_ERROR, NULL,
					    "ber_printf value" );
					goto error_return;
				}
			}
		}

		if (( rc = ber_printf( ber, /*{[*/ "]}" )) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( ber, 1 );
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			    NULL, "ber_printf type end" );
			goto error_return;
		}
	}

	rc = ber_printf( ber, /*{{{*/ "}}}" );

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		ber_free( ber, 1 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "ber_printf entry end" );
		return( 1 );
	}

	bytes = ber_pvt_ber_bytes( ber );

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

		if ( ber_flush( conn->c_sb, ber, 1 ) == 0 ) {
			break;
		}

		err = errno;

		/*
		 * we got an error.  if it's ewouldblock, we need to
		 * wait on the socket being writable.  otherwise, figure
		 * it's a hard error and return.
		 */

		Debug( LDAP_DEBUG_CONNS, "ber_flush failed errno %d msg (%s)\n",
		    err, err > -1 && err < sys_nerr ? sys_errlist[err]
		    : "unknown", 0 );

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

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_entries_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );

	Statslog( LDAP_DEBUG_STATS2, "conn=%ld op=%ld ENTRY dn=\"%s\"\n",
	    (long) conn->c_connid, (long) op->o_opid, e->e_dn, 0, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= send_search_entry\n", 0, 0, 0 );

	rc = 0;

error_return:;
	return( rc );
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

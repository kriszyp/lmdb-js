/* result.c - routines to send ldap results, errors, and referrals */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>		/* get close() */

#include "slap.h"

#ifdef HAVE_WINSOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

static void
send_ldap_result2(
    Connection	*conn,
    Operation	*op,
    int		err,
    char	*matched,
    char	*text,
    int		nentries
)
{
	BerElement	*ber;
	int		rc;
	unsigned long	tag, bytes;

	if ( err == LDAP_PARTIAL_RESULTS && (text == NULL || *text == '\0') )
		err = LDAP_NO_SUCH_OBJECT;

	Debug( LDAP_DEBUG_TRACE, "send_ldap_result %d:%s:%s\n", err, matched ?
	    matched : "", text ? text : "" );

	switch ( op->o_tag ) {
	case LBER_DEFAULT:
		tag = LBER_SEQUENCE;
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


#ifdef LDAP_COMPAT30
	if ( (ber = ber_alloc_t( conn->c_version == 30 ? 0 : LBER_USE_DER ))
	    == NULLBER )
#else
	if ( (ber = der_alloc()) == NULLBER )
#endif
	{
		Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n", 0, 0, 0 );
		return;
	}

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		rc = ber_printf( ber, "{is{t{ess}}}", op->o_msgid, "", tag,
		    err, matched ? matched : "", text ? text : "" );
	} else
#endif
#ifdef LDAP_COMPAT30
	if ( conn->c_version == 30 ) {
		rc = ber_printf( ber, "{it{{ess}}}", op->o_msgid, tag, err,
		    matched ? matched : "", text ? text : "" );
	} else
#endif
		rc = ber_printf( ber, "{it{ess}}", op->o_msgid, tag, err,
		    matched ? matched : "", text ? text : "" );

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		return;
	}

	/* write only one pdu at a time - wait til it's our turn */
	ldap_pvt_thread_mutex_lock( &conn->c_write_mutex );

	/* lock the connection */
	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	/* write the pdu */
	bytes = ber->ber_ptr - ber->ber_buf;

	while ( ber_flush( &conn->c_sb, ber, 1 ) != 0 ) {
		int err = errno;
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
		slapd_set_write( conn->c_sb.sb_sd, 1 );

		ldap_pvt_thread_cond_wait( &conn->c_write_cv, &conn->c_mutex );
		conn->c_writewaiter = 0;
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
	ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%d op=%d RESULT err=%d tag=%lu nentries=%d\n", conn->c_connid,
	    op->o_opid, err, tag, nentries );

	return;
}

void
send_ldap_result(
    Connection	*conn,
    Operation	*op,
    int		err,
    char	*matched,
    char	*text
)
{
#ifdef LDAP_CONNECTIONLESS
	if ( op->o_cldap ) {
		lber_pvt_sb_udp_set_dst( &conn->c_sb, &op->o_clientaddr );
		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &op->o_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *) &op->o_clientaddr)->sin_port,
		    0 );
	}
#endif
	send_ldap_result2( conn, op, err, matched, text, 0 );
}

void
send_ldap_search_result(
    Connection	*conn,
    Operation	*op,
    int		err,
    char	*matched,
    char	*text,
    int		nentries
)
{
	send_ldap_result2( conn, op, err, matched, text, nentries );
}

int
send_search_entry(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    char	**attrs,
    int		attrsonly
)
{
	BerElement	*ber;
	Attribute	*a;
	int		i, rc=-1, bytes;
	struct acl	*acl;
	char            *edn;

	Debug( LDAP_DEBUG_TRACE, "=> send_search_entry (%s)\n", e->e_dn, 0, 0 );

	if ( ! access_allowed( be, conn, op, e,
		"entry", NULL, ACL_READ ) )
	{
		Debug( LDAP_DEBUG_ACL, "acl: access to entry not allowed\n",
		    0, 0, 0 );
		return( 1 );
	}

	edn = e->e_ndn;

#ifdef LDAP_COMPAT30
	if ( (ber = ber_alloc_t( conn->c_version == 30 ? 0 : LBER_USE_DER ))
		== NULLBER )
#else
	if ( (ber = der_alloc()) == NULLBER )
#endif
	{
		Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
			"ber_alloc" );
		goto error_return;
	}

#ifdef LDAP_COMPAT30
	if ( conn->c_version == 30 ) {
		rc = ber_printf( ber, "{it{{s{", op->o_msgid,
		    LDAP_RES_SEARCH_ENTRY, e->e_dn );
	} else
#endif
	{
		rc = ber_printf( ber, "{it{s{", op->o_msgid,
			LDAP_RES_SEARCH_ENTRY, e->e_dn );
	}

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		ber_free( ber, 1 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "ber_printf dn" );
		goto error_return;
	}

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		regmatch_t       matches[MAXREMATCHES];

		if ( attrs != NULL && ! charray_inlist( attrs, a->a_type ) ) {
			continue;
		}

		/* the lastmod attributes are ignored by ACL checking */
		if ( strcasecmp( a->a_type, "modifiersname" ) == 0 ||
			strcasecmp( a->a_type, "modifytimestamp" ) == 0 ||
			strcasecmp( a->a_type, "creatorsname" ) == 0 ||
			strcasecmp( a->a_type, "createtimestamp" ) == 0 ) 
		{
			Debug( LDAP_DEBUG_ACL, "LASTMOD attribute: %s access DEFAULT\n",
				a->a_type, 0, 0 );
			acl = NULL;
		} else {
			acl = acl_get_applicable( be, op, e, a->a_type,
				MAXREMATCHES, matches );
		}

		if ( ! acl_access_allowed( acl, be, conn, e,
			NULL, op, ACL_READ, edn, matches ) ) 
		{
			continue;
		}

		if (( rc = ber_printf( ber, "{s[", a->a_type )) == -1 ) {
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

				if (( rc = ber_printf( ber, "o",
				    a->a_vals[i]->bv_val,
				    a->a_vals[i]->bv_len )) == -1 )
				{
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

		if (( rc = ber_printf( ber, "]}" )) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( ber, 1 );
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			    NULL, "ber_printf type end" );
			goto error_return;
		}
	}

#ifdef LDAP_COMPAT30
	if ( conn->c_version == 30 ) {
		rc = ber_printf( ber, "}}}}" );
	} else
#endif
		rc = ber_printf( ber, "}}}" );

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		ber_free( ber, 1 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "ber_printf entry end" );
		return( 1 );
	}

	bytes = ber->ber_ptr - ber->ber_buf;

	/* write only one pdu at a time - wait til it's our turn */
	ldap_pvt_thread_mutex_lock( &conn->c_write_mutex );

	/* lock the connection */ 
	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	/* write the pdu */
	while ( ber_flush( &conn->c_sb, ber, 1 ) != 0 ) {
		int err = errno;
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
		slapd_set_write( conn->c_sb.sb_sd, 1 );

		ldap_pvt_thread_cond_wait( &conn->c_write_cv, &conn->c_mutex );
		conn->c_writewaiter = 0;
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
	ldap_pvt_thread_mutex_unlock( &conn->c_write_mutex );

	ldap_pvt_thread_mutex_lock( &num_sent_mutex );
	num_bytes_sent += bytes;
	num_entries_sent++;
	ldap_pvt_thread_mutex_unlock( &num_sent_mutex );

	Statslog( LDAP_DEBUG_STATS2, "conn=%d op=%d ENTRY dn=\"%s\"\n",
	    conn->c_connid, op->o_opid, e->e_dn, 0, 0 );

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

/* conn.c - deal with connection subsystem */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2008 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "lutil.h"
#include "back-monitor.h"

#ifndef LDAP_DEVEL
#define MONITOR_LEGACY_CONN
#endif

static int
monitor_subsys_conn_update(
	Operation		*op,
	SlapReply		*rs,
	Entry                   *e );

static int 
monitor_subsys_conn_create( 
	Operation		*op,
	SlapReply		*rs,
	struct berval		*ndn,
	Entry 			*e_parent,
	Entry			**ep );

int
monitor_subsys_conn_init(
	BackendDB		*be,
	monitor_subsys_t	*ms )
{
	monitor_info_t	*mi;
	Entry		*e, **ep, *e_conn;
	monitor_entry_t	*mp;
	char		buf[ BACKMONITOR_BUFSIZE ];
	struct berval	bv;

	assert( be != NULL );

	ms->mss_update = monitor_subsys_conn_update;
	ms->mss_create = monitor_subsys_conn_create;

	mi = ( monitor_info_t * )be->be_private;

	if ( monitor_cache_get( mi, &ms->mss_ndn, &e_conn ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_conn_init: "
			"unable to get entry \"%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	mp = ( monitor_entry_t * )e_conn->e_private;
	mp->mp_children = NULL;
	ep = &mp->mp_children;

	/*
	 * Total conns
	 */
	snprintf( buf, sizeof( buf ),
		"dn: cn=Total,%s\n"
		"objectClass: %s\n"
		"structuralObjectClass: %s\n"
		"cn: Total\n"
		"creatorsName: %s\n"
		"modifiersName: %s\n"
		"createTimestamp: %s\n"
		"modifyTimestamp: %s\n",
		ms->mss_dn.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_creatorsName.bv_val,
		mi->mi_creatorsName.bv_val,
		mi->mi_startTime.bv_val,
		mi->mi_startTime.bv_val );
	
	e = str2entry( buf );
	if ( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_conn_init: "
			"unable to create entry \"cn=Total,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	BER_BVSTR( &bv, "0" );
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, &bv );
	
	mp = monitor_entrypriv_create();
	if ( mp == NULL ) {
		return -1;
	}
	e->e_private = ( void * )mp;
	mp->mp_info = ms;
	mp->mp_flags = ms->mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;
	mp->mp_flags &= ~MONITOR_F_VOLATILE_CH;

	if ( monitor_cache_add( mi, e ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_conn_init: "
			"unable to add entry \"cn=Total,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	*ep = e;
	ep = &mp->mp_next;
	
	/*
	 * Current conns
	 */
	snprintf( buf, sizeof( buf ),
		"dn: cn=Current,%s\n"
		"objectClass: %s\n"
		"structuralObjectClass: %s\n"
		"cn: Current\n"
		"creatorsName: %s\n"
		"modifiersName: %s\n"
		"createTimestamp: %s\n"
		"modifyTimestamp: %s\n",
		ms->mss_dn.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_creatorsName.bv_val,
		mi->mi_creatorsName.bv_val,
		mi->mi_startTime.bv_val,
		mi->mi_startTime.bv_val );
	
	e = str2entry( buf );
	if ( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_conn_init: "
			"unable to create entry \"cn=Current,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	BER_BVSTR( &bv, "0" );
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, &bv );
	
	mp = monitor_entrypriv_create();
	if ( mp == NULL ) {
		return -1;
	}
	e->e_private = ( void * )mp;
	mp->mp_info = ms;
	mp->mp_flags = ms->mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;
	mp->mp_flags &= ~MONITOR_F_VOLATILE_CH;

	if ( monitor_cache_add( mi, e ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_conn_init: "
			"unable to add entry \"cn=Current,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	*ep = e;
	ep = &mp->mp_next;

	monitor_cache_release( mi, e_conn );

	return( 0 );
}

static int
monitor_subsys_conn_update(
	Operation		*op,
	SlapReply		*rs,
	Entry                   *e )
{
	monitor_info_t	*mi = ( monitor_info_t * )op->o_bd->be_private;

	long 			n = -1;
	static struct berval	total_bv = BER_BVC( "cn=total" ),
				current_bv = BER_BVC( "cn=current" );
	struct berval		rdn;

	assert( mi != NULL );
	assert( e != NULL );

	dnRdn( &e->e_nname, &rdn );
	
	if ( dn_match( &rdn, &total_bv ) ) {
		n = connections_nextid();

	} else if ( dn_match( &rdn, &current_bv ) ) {
		Connection	*c;
		int		connindex;

		for ( n = 0, c = connection_first( &connindex );
				c != NULL;
				n++, c = connection_next( c, &connindex ) ) {
			/* No Op */ ;
		}
		connection_done( c );
	}

	if ( n != -1 ) {
		Attribute	*a;
		char		buf[] = "+9223372036854775807L";
		ber_len_t	len;

		a = attr_find( e->e_attrs, mi->mi_ad_monitorCounter );
		if ( a == NULL ) {
			return( -1 );
		}

		snprintf( buf, sizeof( buf ), "%ld", n );
		len = strlen( buf );
		if ( len > a->a_vals[ 0 ].bv_len ) {
			a->a_vals[ 0 ].bv_val = ber_memrealloc( a->a_vals[ 0 ].bv_val, len + 1 );
		}
		a->a_vals[ 0 ].bv_len = len;
		AC_MEMCPY( a->a_vals[ 0 ].bv_val, buf, len + 1 );

		/* FIXME: touch modifyTimestamp? */
	}

	return SLAP_CB_CONTINUE;
}

static int
conn_create(
	monitor_info_t		*mi,
	Connection		*c,
	Entry			**ep,
	monitor_subsys_t	*ms )
{
	monitor_entry_t *mp;
	struct tm	*ltm;
	char		buf[ BACKMONITOR_BUFSIZE ];
	char		buf2[ LDAP_LUTIL_GENTIME_BUFSIZE ];
	char		buf3[ LDAP_LUTIL_GENTIME_BUFSIZE ];

	Entry		*e;

	struct tm	*ctm;
	char		ctmbuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];
	struct tm	*mtm;
	char		mtmbuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];
#ifdef HAVE_GMTIME_R
	struct tm	tm_buf;
#endif /* HAVE_GMTIME_R */

	assert( c != NULL );
	assert( ep != NULL );

#ifndef HAVE_GMTIME_R
	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
#endif
#ifdef HACK_LOCAL_TIME
# ifdef HAVE_LOCALTIME_R
	ctm = localtime_r( &c->c_starttime, &tm_buf );
	lutil_localtime( ctmbuf, sizeof( ctmbuf ), ctm, -timezone );
	mtm = localtime_r( &c->c_activitytime, &tm_buf );
	lutil_localtime( mtmbuf, sizeof( mtmbuf ), mtm, -timezone );
# else
	ctm = localtime( &c->c_starttime );
	lutil_localtime( ctmbuf, sizeof( ctmbuf ), ctm, -timezone );
	mtm = localtime( &c->c_activitytime );
	lutil_localtime( mtmbuf, sizeof( mtmbuf ), mtm, -timezone );
# endif /* HAVE_LOCALTIME_R */
#else /* !HACK_LOCAL_TIME */
# ifdef HAVE_GMTIME_R
	ctm = gmtime_r( &c->c_starttime, &tm_buf );
	lutil_gentime( ctmbuf, sizeof( ctmbuf ), ctm );
	mtm = gmtime_r( &c->c_activitytime, &tm_buf );
	lutil_gentime( mtmbuf, sizeof( mtmbuf ), mtm );
# else
	ctm = gmtime( &c->c_starttime );
	lutil_gentime( ctmbuf, sizeof( ctmbuf ), ctm );
	mtm = gmtime( &c->c_activitytime );
	lutil_gentime( mtmbuf, sizeof( mtmbuf ), mtm );
# endif /* HAVE_GMTIME_R */
#endif /* !HACK_LOCAL_TIME */
#ifndef HAVE_GMTIME_R
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
#endif

#ifndef HAVE_GMTIME_R
	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
#endif

#ifdef HAVE_GMTIME_R
	ltm = gmtime_r( &c->c_starttime, &tm_buf );
#else
	ltm = gmtime( &c->c_starttime );
#endif
	lutil_gentime( buf2, sizeof( buf2 ), ltm );

#ifdef HAVE_GMTIME_R
	ltm = gmtime_r( &c->c_activitytime, &tm_buf );
#else
	ltm = gmtime( &c->c_activitytime );
#endif
	lutil_gentime( buf3, sizeof( buf3 ), ltm );

#ifndef HAVE_GMTIME_R
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
#endif /* HAVE_GMTIME_R */

	snprintf( buf, sizeof( buf ),
		"dn: cn=Connection %ld,%s\n"
		"objectClass: %s\n"
		"structuralObjectClass: %s\n"
		"cn: Connection %ld\n"

#ifdef MONITOR_LEGACY_CONN
		/* NOTE: this will disappear, as the exploded data
		 * has been moved to dedicated attributes */
		"%s: "
			"%ld "
			": %ld "
			": %ld/%ld/%ld/%ld "
			": %ld/%ld/%ld "
			": %s%s%s%s%s%s "
			": %s "
			": %s "
			": %s "
			": %s "
			": %s "
			": %s "
			": %s\n"
#endif /* MONITOR_LEGACY_CONN */

		"%s: %lu\n"
		"%s: %ld\n"

		"%s: %ld\n"
		"%s: %ld\n"
		"%s: %ld\n"
		"%s: %ld\n"

		"%s: %ld\n"
		"%s: %ld\n"
		"%s: %ld\n"

		"%s: %s%s%s%s%s%s\n"

		"%s: %s\n"

		"%s: %s\n"
		"%s: %s\n"
		"%s: %s\n"
		"%s: %s\n"

		"%s: %s\n"
		"%s: %s\n"

		"creatorsName: %s\n"
		"modifiersName: %s\n"
		"createTimestamp: %s\n"
		"modifyTimestamp: %s\n",
		c->c_connid, ms->mss_dn.bv_val,
		mi->mi_oc_monitorConnection->soc_cname.bv_val,
		mi->mi_oc_monitorConnection->soc_cname.bv_val,
		c->c_connid,

#ifdef MONITOR_LEGACY_CONN
		mi->mi_ad_monitoredInfo->ad_cname.bv_val,
			c->c_connid,
			(long) c->c_protocol,
			c->c_n_ops_received, c->c_n_ops_executing,
				c->c_n_ops_pending, c->c_n_ops_completed,
			
			/* add low-level counters here */
			c->c_n_get, c->c_n_read, c->c_n_write,
			
			c->c_currentber ? "r" : "",
			c->c_writewaiter ? "w" : "",
			LDAP_STAILQ_EMPTY( &c->c_ops ) ? "" : "x",
			LDAP_STAILQ_EMPTY( &c->c_pending_ops ) ? "" : "p",
			connection_state2str( c->c_conn_state ),
			c->c_sasl_bind_in_progress ? "S" : "",
			
			c->c_dn.bv_len ? c->c_dn.bv_val : SLAPD_ANONYMOUS,
			
			c->c_listener_url.bv_val,
			BER_BVISNULL( &c->c_peer_domain )
				? "" : c->c_peer_domain.bv_val,
			BER_BVISNULL( &c->c_peer_name )
				? "" : c->c_peer_name.bv_val,
			c->c_sock_name.bv_val,
			
			buf2,
			buf3,
#endif /* MONITOR_LEGACY_CONN */

		mi->mi_ad_monitorConnectionNumber->ad_cname.bv_val,
			c->c_connid,
		mi->mi_ad_monitorConnectionProtocol->ad_cname.bv_val,
			(long)c->c_protocol,

		mi->mi_ad_monitorConnectionOpsReceived->ad_cname.bv_val,
			c->c_n_ops_received,
		mi->mi_ad_monitorConnectionOpsExecuting->ad_cname.bv_val,
			c->c_n_ops_executing,
		mi->mi_ad_monitorConnectionOpsPending->ad_cname.bv_val,
			c->c_n_ops_pending,
		mi->mi_ad_monitorConnectionOpsCompleted->ad_cname.bv_val,
			c->c_n_ops_completed,

		mi->mi_ad_monitorConnectionGet->ad_cname.bv_val,
			c->c_n_get,
		mi->mi_ad_monitorConnectionRead->ad_cname.bv_val,
			c->c_n_read,
		mi->mi_ad_monitorConnectionWrite->ad_cname.bv_val,
			c->c_n_write,

		mi->mi_ad_monitorConnectionMask->ad_cname.bv_val,
			c->c_currentber ? "r" : "",
			c->c_writewaiter ? "w" : "",
			LDAP_STAILQ_EMPTY( &c->c_ops ) ? "" : "x",
			LDAP_STAILQ_EMPTY( &c->c_pending_ops ) ? "" : "p",
			connection_state2str( c->c_conn_state ),
			c->c_sasl_bind_in_progress ? "S" : "",
		
		mi->mi_ad_monitorConnectionAuthzDN->ad_cname.bv_val,
			c->c_dn.bv_len ? c->c_dn.bv_val : SLAPD_ANONYMOUS,

		/* NOTE: client connections leave the c_peer_* fields NULL */
		mi->mi_ad_monitorConnectionListener->ad_cname.bv_val,
			c->c_listener_url.bv_val,
		mi->mi_ad_monitorConnectionPeerDomain->ad_cname.bv_val,
			BER_BVISNULL( &c->c_peer_domain ) ? "unknown" : c->c_peer_domain.bv_val,
		mi->mi_ad_monitorConnectionLocalAddress->ad_cname.bv_val,
			BER_BVISNULL( &c->c_peer_name ) ? "unknown" : c->c_peer_name.bv_val,
		mi->mi_ad_monitorConnectionPeerAddress->ad_cname.bv_val,
			c->c_sock_name.bv_val,

		mi->mi_ad_monitorConnectionStartTime->ad_cname.bv_val,
			buf2,
		mi->mi_ad_monitorConnectionActivityTime->ad_cname.bv_val,
			buf3,

		mi->mi_creatorsName.bv_val,
		mi->mi_creatorsName.bv_val,
		ctmbuf,
		mtmbuf );
		
	e = str2entry( buf );

	if ( e == NULL) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_conn_create: "
			"unable to create entry "
			"\"cn=Connection %ld,%s\" entry\n",
			c->c_connid, 
			ms->mss_dn.bv_val, 0 );
		return( -1 );
	}

	mp = monitor_entrypriv_create();
	if ( mp == NULL ) {
		return LDAP_OTHER;
	}
	e->e_private = ( void * )mp;
	mp->mp_info = ms;
	mp->mp_flags = MONITOR_F_SUB | MONITOR_F_VOLATILE;

	*ep = e;

	return SLAP_CB_CONTINUE;
}

static int 
monitor_subsys_conn_create( 
	Operation		*op,
	SlapReply		*rs,
	struct berval		*ndn,
	Entry 			*e_parent,
	Entry			**ep )
{
	monitor_info_t	*mi = ( monitor_info_t * )op->o_bd->be_private;

	Connection		*c;
	int			connindex;
	monitor_entry_t 	*mp;
	int			rc = SLAP_CB_CONTINUE;
	monitor_subsys_t	*ms;

	assert( mi != NULL );
	assert( e_parent != NULL );
	assert( ep != NULL );

	ms = (( monitor_entry_t *)e_parent->e_private)->mp_info;

	*ep = NULL;

	if ( ndn == NULL ) {
		Entry	*e = NULL,
			*e_tmp = NULL;

		/* create all the children of e_parent */
		for ( c = connection_first( &connindex );
				c != NULL;
				c = connection_next( c, &connindex ) )
		{
			if ( conn_create( mi, c, &e, ms ) != SLAP_CB_CONTINUE
					|| e == NULL )
			{
				for ( ; e_tmp != NULL; ) {
					mp = ( monitor_entry_t * )e_tmp->e_private;
					e = mp->mp_next;

					ch_free( mp );
					e_tmp->e_private = NULL;
					entry_free( e_tmp );

					e_tmp = e;
				}
				rc = rs->sr_err = LDAP_OTHER;
				break;
			}
			mp = ( monitor_entry_t * )e->e_private;
			mp->mp_next = e_tmp;
			e_tmp = e;
		}
		connection_done( c );
		*ep = e;

	} else {
		unsigned long 		connid;
		char			*next = NULL;
		static struct berval	nconn_bv = BER_BVC( "cn=connection " );

		rc = LDAP_NO_SUCH_OBJECT;
	       
		/* create exactly the required entry;
		 * the normalized DN must start with "cn=connection ",
		 * followed by the connection id, followed by
		 * the RDN separator "," */
		if ( ndn->bv_len <= nconn_bv.bv_len
				|| strncmp( ndn->bv_val, nconn_bv.bv_val, nconn_bv.bv_len ) != 0 )
		{
			return -1;
		}
		
		connid = strtol( &ndn->bv_val[ nconn_bv.bv_len ], &next, 10 );
		if ( next[ 0 ] != ',' ) {
			return ( rs->sr_err = LDAP_OTHER );
		}

		for ( c = connection_first( &connindex );
				c != NULL;
				c = connection_next( c, &connindex ) )
		{
			if ( c->c_connid == connid ) {
				rc = conn_create( mi, c, ep, ms );
				if ( rc != SLAP_CB_CONTINUE ) {
					rs->sr_err = rc;

				} else if ( *ep == NULL ) {
					rc = rs->sr_err = LDAP_OTHER;
				}

				break;
			}
		}
		
		connection_done( c );
	}

	return rc;
}


/* syncrepl.c -- Replication Engine which uses the LDAP Sync protocol */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
 * Portions Copyright 2003 by IBM Corporation.
 * Portions Copyright 2003 by Howard Chu, Symas Corporation.
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

#include "ldap_rq.h"

#define SYNCREPL_STR	"syncreplxxx"
#define CN_STR	"cn="

static const struct berval slap_syncrepl_bvc = BER_BVC(SYNCREPL_STR);
static const struct berval slap_syncrepl_cn_bvc = BER_BVC(CN_STR SYNCREPL_STR);

static int syncuuid_cmp( const void *, const void * );
static void avl_ber_bvfree( void * );
static void syncrepl_del_nonpresent( Operation *, syncinfo_t * );

/* callback functions */
static int dn_callback( struct slap_op *, struct slap_rep * );
static int nonpresent_callback( struct slap_op *, struct slap_rep * );
static int null_callback( struct slap_op *, struct slap_rep * );

static AttributeDescription *sync_descs[4];

struct runqueue_s syncrepl_rq;

void
init_syncrepl(syncinfo_t *si)
{
	int i, j, k, n;
	char **tmp;

	if ( !sync_descs[0] ) {
		sync_descs[0] = slap_schema.si_ad_objectClass;
		sync_descs[1] = slap_schema.si_ad_structuralObjectClass;
		sync_descs[2] = slap_schema.si_ad_entryCSN;
		sync_descs[3] = NULL;
	}

	for ( n = 0; si->si_attrs[ n ] != NULL; n++ ) /* empty */;

	if ( n ) {
		/* Delete Attributes */
		for ( i = 0; sync_descs[i] != NULL; i++ ) {
			for ( j = 0; si->si_attrs[j] != NULL; j++ ) {
				if ( strcmp( si->si_attrs[j], sync_descs[i]->ad_cname.bv_val )
					== 0 )
				{
					ch_free( si->si_attrs[j] );
					for ( k = j; si->si_attrs[k] != NULL; k++ ) {
						si->si_attrs[k] = si->si_attrs[k+1];
					}
				}
			}
		}
		for ( n = 0; si->si_attrs[ n ] != NULL; n++ ) /* empty */;
		tmp = ( char ** ) ch_realloc( si->si_attrs, (n + 4)*sizeof( char * ));
		if ( tmp == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, "out of memory\n", 0,0,0 );
#else
			Debug( LDAP_DEBUG_ANY, "out of memory\n", 0,0,0 );
#endif
		}

	} else {
		tmp = ( char ** ) ch_realloc( si->si_attrs, 5 * sizeof( char * ));
		if ( tmp == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, "out of memory\n", 0,0,0 );
#else
			Debug( LDAP_DEBUG_ANY, "out of memory\n", 0,0,0 );
#endif
		}
		tmp[ n++ ] = ch_strdup( "*" );
	}
	
	si->si_attrs = tmp;

	/* Add Attributes */
	for ( i = 0; sync_descs[ i ] != NULL; i++ ) {
		si->si_attrs[ n++ ] = ch_strdup ( sync_descs[i]->ad_cname.bv_val );
		si->si_attrs[ n ] = NULL;
	}
}

static int
ldap_sync_search(
	syncinfo_t *si,
	void *ctx )
{
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	LDAPControl c[2], *ctrls[3];
	struct timeval timeout;
	ber_int_t	msgid;
	int rc;

	/* setup LDAP SYNC control */
	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &ctx );

	if ( si->si_syncCookie.octet_str &&
		si->si_syncCookie.octet_str[0].bv_val )
	{
		ber_printf( ber, "{eO}",
			abs(si->si_type),
			&si->si_syncCookie.octet_str[0] );
	} else {
		ber_printf( ber, "{e}",
			abs(si->si_type) );
	}

	if ( (rc = ber_flatten2( ber, &c[0].ldctl_value, 0 )) == LBER_ERROR ) {
		ber_free_buf( ber );
		return rc;
	}

	c[0].ldctl_oid = LDAP_CONTROL_SYNC;
	c[0].ldctl_iscritical = si->si_type < 0;
	ctrls[0] = &c[0];

	if ( si->si_authzId ) {
		c[1].ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
		ber_str2bv( si->si_authzId, 0, 0, &c[1].ldctl_value );
		c[1].ldctl_iscritical = 1;
		ctrls[1] = &c[1];
		ctrls[2] = NULL;
	} else {
		ctrls[1] = NULL;
	}

	timeout.tv_sec = si->si_tlimit > 0 ? si->si_tlimit : 1;
	timeout.tv_usec = 0;

	rc = ldap_search_ext( si->si_ld, si->si_base.bv_val, si->si_scope,
		si->si_filterstr.bv_val, si->si_attrs, si->si_attrsonly,
		ctrls, NULL, si->si_tlimit < 0 ? NULL : &timeout,
		si->si_slimit, &msgid );
	ber_free_buf( ber );
	return rc;
}

static int
do_syncrep1(
	Operation *op,
	syncinfo_t *si )
{
	int	rc;
	int cmdline_cookie_found = 0;

	char syncrepl_cbuf[sizeof(CN_STR SYNCREPL_STR)];
	struct berval syncrepl_cn_bv;
	struct sync_cookie	*sc = NULL;
	struct sync_cookie	syncCookie = { NULL, -1, NULL };
	struct berval	*psub;
#ifdef HAVE_TLS
	void	*ssl;
#endif

	psub = &si->si_be->be_nsuffix[0];

	/* Init connection to master */
	rc = ldap_initialize( &si->si_ld, si->si_provideruri );
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_syncrep1: ldap_initialize failed (%s)\n",
			si->si_provideruri, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_syncrep1: ldap_initialize failed (%s)\n",
			si->si_provideruri, 0, 0 );
#endif
		return rc;
	}

	op->o_protocol = LDAP_VERSION3;
	ldap_set_option( si->si_ld, LDAP_OPT_PROTOCOL_VERSION, &op->o_protocol );

	/* Bind to master */

	if ( si->si_tls ) {
		rc = ldap_start_tls_s( si->si_ld, NULL, NULL );
		if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "do_syncrep1: "
				"%s: ldap_start_tls failed (%d)\n",
				si->si_tls == SYNCINFO_TLS_CRITICAL ? "Error" : "Warning",
				rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"%s: ldap_start_tls failed (%d)\n",
				si->si_tls == SYNCINFO_TLS_CRITICAL ? "Error" : "Warning",
				rc, 0 );
#endif
			if( si->si_tls == SYNCINFO_TLS_CRITICAL ) goto done;
		}
	}

	if ( si->si_bindmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		void *defaults;

		if ( si->si_secprops != NULL ) {
			rc = ldap_set_option( si->si_ld,
				LDAP_OPT_X_SASL_SECPROPS, si->si_secprops);

			if( rc != LDAP_OPT_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, "do_bind: Error: "
					"ldap_set_option(%s,SECPROPS,\"%s\") failed!\n",
					si->si_provideruri, si->si_secprops, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "Error: ldap_set_option "
					"(%s,SECPROPS,\"%s\") failed!\n",
					si->si_provideruri, si->si_secprops, 0 );
#endif
				goto done;
			}
		}

		defaults = lutil_sasl_defaults( si->si_ld, si->si_saslmech,
			si->si_realm, si->si_authcId, si->si_passwd, si->si_authzId );

		rc = ldap_sasl_interactive_bind_s( si->si_ld,
				si->si_binddn,
				si->si_saslmech,
				NULL, NULL,
				LDAP_SASL_QUIET,
				lutil_sasl_interact,
				defaults );

		lutil_sasl_freedefs( defaults );

		/* FIXME: different error behaviors according to
		 *	1) return code
		 *	2) on err policy : exit, retry, backoff ...
		 */
		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "do_syncrep1: "
				"ldap_sasl_interactive_bind_s failed (%d)\n",
				rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_syncrep1: "
				"ldap_sasl_interactive_bind_s failed (%d)\n",
				rc, 0, 0 );
#endif

			/* FIXME (see above comment) */
			/* if Kerberos credentials cache is not active, retry */
			if ( strcmp( si->si_saslmech, "GSSAPI" ) == 0 &&
				rc == LDAP_LOCAL_ERROR )
			{
				rc = LDAP_SERVER_DOWN;
			}

			goto done;
		}
#else /* HAVE_CYRUS_SASL */
		/* Should never get here, we trapped this at config time */
		assert(0);
		fprintf( stderr, "not compiled with SASL support\n" );
		rc = LDAP_OTHER;
		goto done;
#endif

	} else {
		rc = ldap_bind_s( si->si_ld,
			si->si_binddn, si->si_passwd, si->si_bindmethod );
		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "do_syncrep1: "
				"ldap_bind_s failed (%d)\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_syncrep1: "
				"ldap_bind_s failed (%d)\n", rc, 0, 0 );
#endif
			goto done;
		}
	}

	/* Set SSF to strongest of TLS, SASL SSFs */
	op->o_sasl_ssf = 0;
	op->o_tls_ssf = 0;
#ifdef HAVE_TLS
	if ( ldap_get_option( si->si_ld, LDAP_OPT_X_TLS_SSL_CTX, &ssl ) == LDAP_SUCCESS &&
	     ssl != NULL ) {
		op->o_tls_ssf = ldap_pvt_tls_get_strength( ssl );
	}
#endif /* HAVE_TLS */
	ldap_get_option( si->si_ld, LDAP_OPT_X_SASL_SSF, &op->o_sasl_ssf );
	op->o_transport_ssf = op->o_ssf = ( op->o_sasl_ssf > op->o_tls_ssf ) ?
		op->o_sasl_ssf : op->o_tls_ssf;

	/* get syncrepl cookie of shadow replica from subentry */
	assert( si->si_rid < 1000 );
	syncrepl_cn_bv.bv_val = syncrepl_cbuf;
	syncrepl_cn_bv.bv_len = snprintf(syncrepl_cbuf, sizeof(syncrepl_cbuf),
		CN_STR "syncrepl%ld", si->si_rid );
	build_new_dn( &op->o_req_ndn, psub, &syncrepl_cn_bv, op->o_tmpmemctx );
	op->o_req_dn = op->o_req_ndn;

	LDAP_STAILQ_FOREACH( sc, &slap_sync_cookie, sc_next ) {
		if ( si->si_rid == sc->rid ) {
			cmdline_cookie_found = 1;
			break;
		}
	}

	if ( cmdline_cookie_found ) {
		/* cookie is supplied in the command line */
		BerVarray cookie = NULL;
		struct berval cookie_bv;

		LDAP_STAILQ_REMOVE( &slap_sync_cookie, sc, sync_cookie, sc_next );
		slap_sync_cookie_free( &si->si_syncCookie, 0 );

		/* read stored cookie if it exists */
		backend_attribute( op, NULL, &op->o_req_ndn,
			slap_schema.si_ad_syncreplCookie, &cookie );

		if ( !cookie ) {
			/* no stored cookie */
			if ( sc->ctxcsn == NULL ||
				 sc->ctxcsn->bv_val == NULL ) {
				/* if cmdline cookie does not have ctxcsn */
				/* component, set it to an initial value */
				slap_init_sync_cookie_ctxcsn( sc );
			}
			slap_dup_sync_cookie( &si->si_syncCookie, sc );
			slap_sync_cookie_free( sc, 1 );
			sc = NULL;

		} else {
			/* stored cookie */
			struct berval newcookie = BER_BVNULL;
			ber_dupbv( &cookie_bv, &cookie[0] );
			ber_bvarray_add( &si->si_syncCookie.octet_str, &cookie_bv );
			slap_parse_sync_cookie( &si->si_syncCookie );
			ber_bvarray_free( si->si_syncCookie.octet_str );
			si->si_syncCookie.octet_str = NULL;
			ber_bvarray_free_x( cookie, op->o_tmpmemctx );
			if ( sc->sid != -1 ) {
				/* command line cookie wins */
				si->si_syncCookie.sid = sc->sid;
			}
			if ( sc->ctxcsn != NULL ) {
				/* command line cookie wins */
				if ( si->si_syncCookie.ctxcsn ) {
					ber_bvarray_free( si->si_syncCookie.ctxcsn );
					si->si_syncCookie.ctxcsn = NULL;
				}
				ber_dupbv( &cookie_bv, &sc->ctxcsn[0] );
				ber_bvarray_add( &si->si_syncCookie.ctxcsn, &cookie_bv );
			}
			if ( sc->rid != -1 ) {
				/* command line cookie wins */
				si->si_syncCookie.rid = sc->rid;
			}
			slap_sync_cookie_free( sc, 1 );
			sc = NULL;
			slap_compose_sync_cookie( NULL, &newcookie,
					&si->si_syncCookie.ctxcsn[0],
					si->si_syncCookie.sid, si->si_syncCookie.rid );
			ber_bvarray_add( &si->si_syncCookie.octet_str, &newcookie );
		}

	} else {
		/* no command line cookie is specified */
		if ( si->si_syncCookie.octet_str == NULL ) {
			BerVarray cookie = NULL;
			struct berval cookie_bv;
			/* try to read stored cookie */
			backend_attribute( op, NULL, &op->o_req_ndn,
				slap_schema.si_ad_syncreplCookie, &cookie );
			if ( cookie ) {
				ber_dupbv( &cookie_bv, &cookie[0] );
				ber_bvarray_add( &si->si_syncCookie.octet_str, &cookie_bv );
				slap_parse_sync_cookie( &si->si_syncCookie );
				ber_bvarray_free_x( cookie, op->o_tmpmemctx );
			}
		}
	}

	rc = ldap_sync_search( si, op->o_tmpmemctx );

	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, "do_syncrep1: "
			"ldap_search_ext: %s (%d)\n", ldap_err2string( rc ), rc, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_syncrep1: "
			"ldap_search_ext: %s (%d)\n", ldap_err2string( rc ), rc, 0 );
#endif
	}

done:
	if ( rc ) {
		if ( si->si_ld ) {
			ldap_unbind( si->si_ld );
			si->si_ld = NULL;
		}
	}

	return rc;
}

static int
do_syncrep2(
	Operation *op,
	syncinfo_t *si )
{
	LDAPControl	**rctrls = NULL;
	LDAPControl	*rctrlp;

	BerElementBuffer berbuf;
	BerElement	*ber = (BerElement *)&berbuf;

	LDAPMessage	*res = NULL;
	LDAPMessage	*msg = NULL;

	char		*retoid = NULL;
	struct berval	*retdata = NULL;

	Entry		*entry = NULL;

	int		syncstate;
	struct berval	syncUUID = BER_BVNULL;
	struct sync_cookie	syncCookie = { NULL, -1, NULL };
	struct sync_cookie	syncCookie_req = { NULL, -1, NULL };
	struct berval		cookie = BER_BVNULL;

	int	rc, err, i;
	ber_len_t	len;

	int rc_efree = 1;

	struct berval	*psub;
	Modifications	*modlist = NULL;

	const char		*text;
	int				match;

	struct timeval *tout_p = NULL;
	struct timeval tout = { 0, 0 };

	int		refreshDeletes = 0;
	int		refreshDone = 1;
	BerVarray syncUUIDs = NULL;
	ber_tag_t si_tag;

	if ( slapd_shutdown ) {
		rc = -2;
		goto done;
	}

	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, DETAIL1, "do_syncrep2\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=>do_syncrep2\n", 0, 0, 0 );
#endif

	psub = &si->si_be->be_nsuffix[0];

	slap_dup_sync_cookie( &syncCookie_req, &si->si_syncCookie );

	if ( abs(si->si_type) == LDAP_SYNC_REFRESH_AND_PERSIST ) {
		tout_p = &tout;
	} else {
		tout_p = NULL;
	}

	while (( rc = ldap_result( si->si_ld, LDAP_RES_ANY, LDAP_MSG_ONE,
		tout_p, &res )) > 0 )
	{
		if ( slapd_shutdown ) {
			rc = -2;
			goto done;
		}
		for( msg = ldap_first_message( si->si_ld, res );
			msg != NULL;
			msg = ldap_next_message( si->si_ld, msg ) )
		{
			switch( ldap_msgtype( msg ) ) {
			case LDAP_RES_SEARCH_ENTRY:
				ldap_get_entry_controls( si->si_ld, msg, &rctrls );
				/* we can't work without the control */
				if ( !rctrls ) {
					rc = -1;
					goto done;
				}
				rctrlp = *rctrls;
				ber_init2( ber, &rctrlp->ldctl_value, LBER_USE_DER );
				ber_scanf( ber, "{em" /*"}"*/, &syncstate, &syncUUID );
				if ( ber_peek_tag( ber, &len ) == LDAP_TAG_SYNC_COOKIE ) {
					ber_scanf( ber, /*"{"*/ "m}", &cookie );
					if ( cookie.bv_val ) {
						struct berval tmp_bv;
						ber_dupbv( &tmp_bv, &cookie );
						ber_bvarray_add( &syncCookie.octet_str, &tmp_bv );
					}
					if ( syncCookie.octet_str &&
							syncCookie.octet_str[0].bv_val )
						slap_parse_sync_cookie( &syncCookie );
				}
				if ( syncrepl_message_to_entry( si, op, msg,
					&modlist, &entry, syncstate ) == LDAP_SUCCESS ) {
					rc_efree = syncrepl_entry( si, op, entry, modlist,
						syncstate, &syncUUID, &syncCookie_req );
					if ( syncCookie.octet_str &&
						syncCookie.octet_str[0].bv_val )
					{
						syncrepl_updateCookie( si, op, psub, &syncCookie );
					}
				}
				ldap_controls_free( rctrls );
				if ( modlist ) {
					slap_mods_free( modlist );
				}
				if ( rc_efree && entry ) {
					entry_free( entry );
					entry = NULL;
				}
				break;

			case LDAP_RES_SEARCH_REFERENCE:
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR,
					"do_syncrep2 : reference received\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"do_syncrep2 : reference received\n", 0, 0, 0 );
#endif
				break;

			case LDAP_RES_SEARCH_RESULT:
				ldap_parse_result( si->si_ld, msg, &err, NULL, NULL, NULL,
					&rctrls, 0 );
				if ( rctrls ) {
					rctrlp = *rctrls;
					ber_init2( ber, &rctrlp->ldctl_value, LBER_USE_DER );

					ber_scanf( ber, "{" /*"}"*/);
					if ( ber_peek_tag( ber, &len ) == LDAP_TAG_SYNC_COOKIE ) {
						ber_scanf( ber, "m", &cookie );
						if ( cookie.bv_val ) {
							struct berval tmp_bv;
							ber_dupbv( &tmp_bv, &cookie );
							ber_bvarray_add( &syncCookie.octet_str, &tmp_bv);
						}
						if ( syncCookie.octet_str &&
							syncCookie.octet_str[0].bv_val )
						{
							slap_parse_sync_cookie( &syncCookie );
						}
					}
					if ( ber_peek_tag( ber, &len ) == LDAP_TAG_REFRESHDELETES )
					{
						ber_scanf( ber, "b", &refreshDeletes );
					}
					ber_scanf( ber, /*"{"*/ "}" );
				}
				if ( syncCookie_req.ctxcsn == NULL ) {
					match = -1;
				} else if ( syncCookie.ctxcsn == NULL ) {
					match = 1;
				} else {
					value_match( &match, slap_schema.si_ad_entryCSN,
						slap_schema.si_ad_entryCSN->ad_type->sat_ordering,
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						&syncCookie_req.ctxcsn[0], &syncCookie.ctxcsn[0],
						&text );
				}
				if ( syncCookie.octet_str && syncCookie.octet_str->bv_val &&
					match < 0 && err == LDAP_SUCCESS )
				{
					syncrepl_updateCookie( si, op, psub, &syncCookie );
				}
				if ( rctrls ) {
					ldap_controls_free( rctrls );
				}
				if (si->si_type != LDAP_SYNC_REFRESH_AND_PERSIST) {
					/* FIXME : different error behaviors according to
					 *	1) err code : LDAP_BUSY ...
					 *	2) on err policy : stop service, stop sync, retry
					 */
					if ( refreshDeletes == 0 && match < 0 &&
						err == LDAP_SUCCESS )
					{
						syncrepl_del_nonpresent( op, si );
					} else {
						avl_free( si->si_presentlist, avl_ber_bvfree );
						si->si_presentlist = NULL;
					}
				}
				rc = -2;
				goto done;
				break;

			case LDAP_RES_INTERMEDIATE:
				rc = ldap_parse_intermediate( si->si_ld, msg,
					&retoid, &retdata, NULL, 0 );
				if ( !rc && !strcmp( retoid, LDAP_SYNC_INFO ) ) {
					int		si_refreshDelete = 0;
					int		si_refreshPresent = 0;
					ber_init2( ber, retdata, LBER_USE_DER );

					switch ( si_tag = ber_peek_tag( ber, &len )) {
					ber_tag_t tag;
					case LDAP_TAG_SYNC_NEW_COOKIE:
						ber_scanf( ber, "tm", &tag, &cookie );
						break;
					case LDAP_TAG_SYNC_REFRESH_DELETE:
						si_refreshDelete = 1;
					case LDAP_TAG_SYNC_REFRESH_PRESENT:
						si_refreshPresent = 1;
						ber_scanf( ber, "t{" /*"}"*/, &tag );
						if ( ber_peek_tag( ber, &len ) == LDAP_TAG_SYNC_COOKIE )
						{
							ber_scanf( ber, "m", &cookie );
							if ( cookie.bv_val ) {
								struct berval tmp_bv;
								ber_dupbv( &tmp_bv, &cookie );
								ber_bvarray_add( &syncCookie.octet_str,
									&tmp_bv);
							}
							if ( syncCookie.octet_str &&
								syncCookie.octet_str[0].bv_val )
							{
								slap_parse_sync_cookie( &syncCookie );
							}
						}
						if ( ber_peek_tag( ber, &len ) ==
							LDAP_TAG_REFRESHDONE )
						{
							ber_scanf( ber, "b", &refreshDone );
						}
						ber_scanf( ber, /*"{"*/ "}" );
						break;
					case LDAP_TAG_SYNC_ID_SET:
						ber_scanf( ber, "t{" /*"}"*/, &tag );
						if ( ber_peek_tag( ber, &len ) ==
							LDAP_TAG_SYNC_COOKIE )
						{
							ber_scanf( ber, "m", &cookie );
							if ( cookie.bv_val ) {
								struct berval tmp_bv;
								ber_dupbv( &tmp_bv, &cookie );
								ber_bvarray_add( &syncCookie.octet_str,
									&tmp_bv );
							}
							if ( syncCookie.octet_str &&
								syncCookie.octet_str[0].bv_val )
							{
								slap_parse_sync_cookie( &syncCookie );
							}
						}
						if ( ber_peek_tag( ber, &len ) ==
							LDAP_TAG_REFRESHDELETES )
						{
							ber_scanf( ber, "b", &refreshDeletes );
						}
						ber_scanf( ber, "[W]", &syncUUIDs );
						ber_scanf( ber, /*"{"*/ "}" );
						for ( i = 0; syncUUIDs[i].bv_val; i++ ) {
							struct berval *syncuuid_bv;
							syncuuid_bv = ber_dupbv( NULL, &syncUUIDs[i] );
							avl_insert( &si->si_presentlist,
								(caddr_t) syncuuid_bv,
								syncuuid_cmp, avl_dup_error );
						}
						ber_memfree_x( syncUUIDs, op->o_tmpmemctx );
						break;
					default:
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR,
						"do_syncrep2 : unknown syncinfo tag (%ld)\n",
						(long) si_tag, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
						"do_syncrep2 : unknown syncinfo tag (%ld)\n",
						(long) si_tag, 0, 0 );
#endif
						ldap_memfree( retoid );
						ber_bvfree( retdata );
						continue;
					}

					if ( syncCookie_req.ctxcsn == NULL ) {
						match = -1;
					} else if ( syncCookie.ctxcsn == NULL ) {
						match = 1;
					} else {
						value_match( &match, slap_schema.si_ad_entryCSN,
							slap_schema.si_ad_entryCSN->ad_type->sat_ordering,
							SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
							&syncCookie_req.ctxcsn[0],
							&syncCookie.ctxcsn[0], &text );
					}

					if ( syncCookie.ctxcsn && syncCookie.ctxcsn[0].bv_val &&
						match < 0 )
					{
						syncrepl_updateCookie( si, op, psub, &syncCookie);
					}

					if ( si_refreshPresent == 1 ) {
						if ( match < 0 ) {
							syncrepl_del_nonpresent( op, si );
						}
					} 

					ldap_memfree( retoid );
					ber_bvfree( retdata );
					break;

				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR, "do_syncrep2 :"
						" unknown intermediate "
						"response\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY, "do_syncrep2 : "
						"unknown intermediate response (%d)\n",
						rc, 0, 0 );
#endif
					ldap_memfree( retoid );
					ber_bvfree( retdata );
					break;
				}
				break;

			default:
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, "do_syncrep2 : "
					"unknown message\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "do_syncrep2 : "
					"unknown message\n", 0, 0, 0 );
#endif
				break;

			}
			if ( syncCookie.octet_str ) {
				slap_sync_cookie_free( &syncCookie_req, 0 );
				slap_dup_sync_cookie( &syncCookie_req, &syncCookie );
				slap_sync_cookie_free( &syncCookie, 0 );
			}
		}
		ldap_msgfree( res );
		res = NULL;
	}

	if ( rc == -1 ) {
		const char *errstr;

		ldap_get_option( si->si_ld, LDAP_OPT_ERROR_NUMBER, &rc );
		errstr = ldap_err2string( rc );
		
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_syncrep2 : %s\n", errstr, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_syncrep2 : %s\n", errstr, 0, 0 );
#endif
	}

done:
	slap_sync_cookie_free( &syncCookie, 0 );
	slap_sync_cookie_free( &syncCookie_req, 0 );

	if ( res ) ldap_msgfree( res );

	if ( rc && si->si_ld ) {
		ldap_unbind( si->si_ld );
		si->si_ld = NULL;
	}

	return rc;
}

void *
do_syncrepl(
	void	*ctx,
	void	*arg )
{
	struct re_s* rtask = arg;
	syncinfo_t *si = ( syncinfo_t * ) rtask->arg;
	Connection conn = {0};
	Operation op = {0};
	int rc = LDAP_SUCCESS;
	int first = 0;
	int dostop = 0;
	ber_socket_t s;
	int i, defer = 1;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, DETAIL1, "do_syncrepl\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=>do_syncrepl\n", 0, 0, 0 );
#endif

	if ( si == NULL )
		return NULL;

	switch( abs( si->si_type )) {
	case LDAP_SYNC_REFRESH_ONLY:
	case LDAP_SYNC_REFRESH_AND_PERSIST:
		break;
	default:
		return NULL;
	}

	if ( slapd_shutdown && si->si_ld ) {
		ldap_get_option( si->si_ld, LDAP_OPT_DESC, &s );
		connection_client_stop( s );
		ldap_unbind( si->si_ld );
		si->si_ld = NULL;
		return NULL;
	}

	connection_fake_init( &conn, &op, ctx );

	op.o_dn = si->si_updatedn;
	op.o_ndn = si->si_updatedn;
	op.o_managedsait = 1;
	op.o_bd = si->si_be;

	op.o_sync_state.ctxcsn = NULL;
	op.o_sync_state.sid = -1;
	op.o_sync_state.octet_str = NULL;
	op.o_sync_slog_size = -1;
	LDAP_STAILQ_FIRST( &op.o_sync_slog_list ) = NULL;
	op.o_sync_slog_list.stqh_last = &LDAP_STAILQ_FIRST(&op.o_sync_slog_list);

	/* Establish session, do search */
	if ( !si->si_ld ) {
		first = 1;
		rc = do_syncrep1( &op, si );
	}

	/* Process results */
	if ( rc == LDAP_SUCCESS ) {
		ldap_get_option( si->si_ld, LDAP_OPT_DESC, &s );

		rc = do_syncrep2( &op, si );

		if ( abs(si->si_type) == LDAP_SYNC_REFRESH_AND_PERSIST ) {
			/* If we succeeded, enable the connection for further listening.
			 * If we failed, tear down the connection and reschedule.
			 */
			if ( rc == LDAP_SUCCESS ) {
				if ( first ) {
					rc = connection_client_setup( s, do_syncrepl,
						arg );
				} else {
					connection_client_enable( s );
				} 
			} else if ( !first ) {
				dostop = 1;
			}
		} else {
			if ( rc == -2 ) rc = 0;
		}
	}

	/* At this point, we have 4 cases:
	 * 1) for any hard failure, give up and remove this task
	 * 2) for ServerDown, reschedule this task to run
	 * 3) for Refresh and Success, reschedule to run
	 * 4) for Persist and Success, reschedule to defer
	 */
	ldap_pvt_thread_mutex_lock( &syncrepl_rq.rq_mutex );

	if ( ldap_pvt_runqueue_isrunning( &syncrepl_rq, rtask )) {
		ldap_pvt_runqueue_stoptask( &syncrepl_rq, rtask );
	}

	if ( dostop ) {
		connection_client_stop( s );
	}

	if ( rc == LDAP_SUCCESS ) {
		if ( si->si_type == LDAP_SYNC_REFRESH_ONLY ) {
			defer = 0;
		}
		rtask->interval.tv_sec = si->si_interval;
		ldap_pvt_runqueue_resched( &syncrepl_rq, rtask, defer );
		if ( si->si_retrynum ) {
			for ( i = 0; si->si_retrynum_init[i] != -2; i++ ) {
				si->si_retrynum[i] = si->si_retrynum_init[i];
			}
			si->si_retrynum[i] = -2;
		}
	} else {
		for ( i = 0; si->si_retrynum && si->si_retrynum[i] <= 0; i++ ) {
			if ( si->si_retrynum[i] == -1  || si->si_retrynum[i] == -2 )
				break;
		}

		if ( !si->si_retrynum || si->si_retrynum[i] == -2 ) {
			ldap_pvt_runqueue_remove( &syncrepl_rq, rtask );
		} else if ( si->si_retrynum[i] >= -1 ) {
			if ( si->si_retrynum[i] > 0 )
				si->si_retrynum[i]--;
			rtask->interval.tv_sec = si->si_retryinterval[i];
			ldap_pvt_runqueue_resched( &syncrepl_rq, rtask, 0 );
			slap_wake_listener();
		}
	}
	
	ldap_pvt_thread_mutex_unlock( &syncrepl_rq.rq_mutex );

	return NULL;
}

int
syncrepl_message_to_entry(
	syncinfo_t	*si,
	Operation	*op,
	LDAPMessage	*msg,
	Modifications	**modlist,
	Entry			**entry,
	int		syncstate
)
{
	Entry		*e = NULL;
	BerElement	*ber = NULL;
	Modifications	tmp;
	Modifications	*mod;
	Modifications	**modtail = modlist;

	const char	*text;
	char txtbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof txtbuf;

	struct berval	bdn = {0, NULL}, dn, ndn;
	int		rc;

	*modlist = NULL;

	if ( ldap_msgtype( msg ) != LDAP_RES_SEARCH_ENTRY ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"Message type should be entry (%d)", ldap_msgtype( msg ), 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"Message type should be entry (%d)", ldap_msgtype( msg ), 0, 0 );
#endif
		return -1;
	}

	op->o_tag = LDAP_REQ_ADD;

	rc = ldap_get_dn_ber( si->si_ld, msg, &ber, &bdn );

	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_message_to_entry : dn get failed (%d)", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"syncrepl_message_to_entry : dn get failed (%d)", rc, 0, 0 );
#endif
		return rc;
	}

	dnPrettyNormal( NULL, &bdn, &dn, &ndn, op->o_tmpmemctx );
	ber_dupbv( &op->o_req_dn, &dn );
	ber_dupbv( &op->o_req_ndn, &ndn );
	slap_sl_free( ndn.bv_val, op->o_tmpmemctx );
	slap_sl_free( dn.bv_val, op->o_tmpmemctx );

	if ( syncstate == LDAP_SYNC_PRESENT || syncstate == LDAP_SYNC_DELETE ) {
		return LDAP_SUCCESS;
	}

	if ( entry == NULL ) {
		return -1;
	}

	e = ( Entry * ) ch_calloc( 1, sizeof( Entry ) );
	*entry = e;
	e->e_name = op->o_req_dn;
	e->e_nname = op->o_req_ndn;

	while ( ber_remaining( ber ) ) {
		if ( (ber_scanf( ber, "{mW}", &tmp.sml_type, &tmp.sml_values ) ==
			LBER_ERROR ) || ( tmp.sml_type.bv_val == NULL ))
		{
			break;
		}

		mod  = (Modifications *) ch_malloc( sizeof( Modifications ));

		mod->sml_op = LDAP_MOD_REPLACE;
		mod->sml_next = NULL;
		mod->sml_desc = NULL;
		mod->sml_type = tmp.sml_type;
		mod->sml_values = tmp.sml_values;
		mod->sml_nvalues = NULL;

		*modtail = mod;
		modtail = &mod->sml_next;
	}

	if ( *modlist == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_message_to_entry: no attributes\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_message_to_entry: no attributes\n",
			0, 0, 0 );
#endif
	}

	rc = slap_mods_check( *modlist, 1, &text, txtbuf, textlen, NULL );

	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_message_to_entry: mods check (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_message_to_entry: mods check (%s)\n",
			text, 0, 0 );
#endif
		goto done;
	}
	
	rc = slap_mods2entry( *modlist, &e, 1, 1, &text, txtbuf, textlen);
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
   		LDAP_LOG( OPERATION, ERR,
			"syncrepl_message_to_entry: mods2entry (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_message_to_entry: mods2entry (%s)\n",
			text, 0, 0 );
#endif
	}

done:
	ber_free ( ber, 0 );
	if ( rc != LDAP_SUCCESS ) {
		entry_free( e );
		e = NULL;
	}

	return rc;
}

int
syncrepl_entry(
	syncinfo_t* si,
	Operation *op,
	Entry* e,
	Modifications* modlist,
	int syncstate,
	struct berval* syncUUID,
	struct sync_cookie* syncCookie_req )
{
	Backend *be = op->o_bd;
	slap_callback	cb = { NULL };
	struct berval	*syncuuid_bv = NULL;
	struct berval	syncUUID_strrep = BER_BVNULL;
	struct berval	uuid_bv = BER_BVNULL;

	SlapReply	rs = {REP_RESULT};
	Filter f = {0};
	AttributeAssertion ava = {0};
	int rc = LDAP_SUCCESS;
	int ret = LDAP_SUCCESS;
	const char *text;

	struct berval pdn = BER_BVNULL;
	struct berval org_req_dn = BER_BVNULL;
	struct berval org_req_ndn = BER_BVNULL;
	struct berval org_dn = BER_BVNULL;
	struct berval org_ndn = BER_BVNULL;
	int	org_managedsait;

	if (( syncstate == LDAP_SYNC_PRESENT || syncstate == LDAP_SYNC_ADD )) {
		syncuuid_bv = ber_dupbv( NULL, syncUUID );
		avl_insert( &si->si_presentlist, (caddr_t) syncuuid_bv,
			syncuuid_cmp, avl_dup_error );
	}

	if ( syncstate == LDAP_SYNC_PRESENT ) {
		return e ? 1 : 0;
	}

	f.f_choice = LDAP_FILTER_EQUALITY;
	f.f_ava = &ava;
	ava.aa_desc = slap_schema.si_ad_entryUUID;
	slap_uuidstr_from_normalized( &syncUUID_strrep, syncUUID, op->o_tmpmemctx );
	ava.aa_value = *syncUUID;
	op->ors_filter = &f;

	op->ors_filterstr.bv_len = (sizeof("entryUUID=")-1) + syncUUID->bv_len;
	op->ors_filterstr.bv_val = (char *) slap_sl_malloc(
		op->ors_filterstr.bv_len + 1, op->o_tmpmemctx ); 
	AC_MEMCPY( op->ors_filterstr.bv_val, "entryUUID=", sizeof("entryUUID=")-1 );
	AC_MEMCPY( &op->ors_filterstr.bv_val[sizeof("entryUUID=")-1],
		syncUUID->bv_val, syncUUID->bv_len );
	op->ors_filterstr.bv_val[op->ors_filterstr.bv_len] = '\0';

	op->o_tag = LDAP_REQ_SEARCH;
	op->ors_scope = LDAP_SCOPE_SUBTREE;

	/* get syncrepl cookie of shadow replica from subentry */
	op->o_req_dn = si->si_base;
	op->o_req_ndn = si->si_base;

	op->o_time = slap_get_time();
	op->ors_tlimit = SLAP_NO_LIMIT;
	op->ors_slimit = 1;

	/* set callback function */
	op->o_callback = &cb;
	cb.sc_response = dn_callback;
	cb.sc_private = si;

	si->si_syncUUID_ndn.bv_val = NULL;

	if ( limits_check( op, &rs ) == 0 ) {
		rc = be->be_search( op, &rs );
	}

	if ( op->ors_filterstr.bv_val ) {
		slap_sl_free( op->ors_filterstr.bv_val, op->o_tmpmemctx );
	}

	cb.sc_response = null_callback;
	cb.sc_private = si;

	if ( rc == LDAP_SUCCESS && si->si_syncUUID_ndn.bv_val ) {
		char *subseq_ptr;

		if ( syncstate != LDAP_SYNC_DELETE ) {
			op->o_no_psearch = 1;
		}

		ber_dupbv( &op->o_sync_csn, syncCookie_req->ctxcsn );
		if ( op->o_sync_csn.bv_val ) {
			subseq_ptr = strstr( op->o_sync_csn.bv_val, "#0000" );
			subseq_ptr += 4;
			*subseq_ptr = '1';
		}
		
		op->o_req_dn = si->si_syncUUID_ndn;
		op->o_req_ndn = si->si_syncUUID_ndn;
		op->o_tag = LDAP_REQ_DELETE;
		rc = be->be_delete( op, &rs );

		org_req_dn = op->o_req_dn;
		org_req_ndn = op->o_req_ndn;
		org_dn = op->o_dn;
		org_ndn = op->o_ndn;
		org_managedsait = get_manageDSAit( op );
		op->o_dn = op->o_bd->be_rootdn;
		op->o_ndn = op->o_bd->be_rootndn;
		op->o_managedsait = 1;

		while ( rs.sr_err == LDAP_SUCCESS && op->o_delete_glue_parent ) {
			op->o_delete_glue_parent = 0;
			if ( !be_issuffix( op->o_bd, &op->o_req_ndn )) {
				slap_callback cb = { NULL };
				cb.sc_response = slap_null_cb;
				dnParent( &op->o_req_ndn, &pdn );
				op->o_req_dn = pdn;
				op->o_req_ndn = pdn;
				op->o_callback = &cb;
				op->o_bd->be_delete( op, &rs );
			} else {
				break;
		    }
		}

		op->o_managedsait = org_managedsait;
		op->o_dn = org_dn;
		op->o_ndn = org_ndn;
		op->o_req_dn = org_req_dn;
		op->o_req_ndn = org_req_ndn;
		op->o_delete_glue_parent = 0;

		op->o_no_psearch = 0;
	}

	switch ( syncstate ) {
	case LDAP_SYNC_ADD:
	case LDAP_SYNC_MODIFY:
		if ( rc == LDAP_SUCCESS ||
			 rc == LDAP_REFERRAL ||
			 rc == LDAP_NO_SUCH_OBJECT ||
			 rc == LDAP_NOT_ALLOWED_ON_NONLEAF )
		{
			attr_delete( &e->e_attrs, slap_schema.si_ad_entryUUID );
			attr_merge_one( e, slap_schema.si_ad_entryUUID,
				syncUUID, &ava.aa_value );

			op->o_tag = LDAP_REQ_ADD;
			op->ora_e = e;
			op->o_req_dn = e->e_name;
			op->o_req_ndn = e->e_nname;
			rc = be->be_add( op, &rs );

			if ( rc != LDAP_SUCCESS ) {
				if ( rc == LDAP_ALREADY_EXISTS ) {
					Modifications *mod;
					Modifications *modtail = modlist;

					assert( modlist );

					for ( mod = modlist; mod != NULL; mod = mod->sml_next ) {
						modtail = mod;
					}

					mod = (Modifications *)ch_calloc(1, sizeof(Modifications));
					ber_dupbv( &uuid_bv, syncUUID );
					mod->sml_op = LDAP_MOD_REPLACE;
					mod->sml_desc = slap_schema.si_ad_entryUUID;
					mod->sml_type = mod->sml_desc->ad_cname;
					ber_bvarray_add( &mod->sml_values, &uuid_bv );
					modtail->sml_next = mod;
					
					op->o_tag = LDAP_REQ_MODIFY;
					op->orm_modlist = modlist;
					op->o_req_dn = e->e_name;
					op->o_req_ndn = e->e_nname;

					rc = be->be_modify( op, &rs );
					if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
						LDAP_LOG( OPERATION, ERR,
							"syncrepl_entry : be_modify failed (%d)\n",
							rc, 0, 0 );
#else
						Debug( LDAP_DEBUG_ANY,
							"syncrepl_entry : be_modify failed (%d)\n",
							rc, 0, 0 );
#endif
					}
					ret = 1;
					goto done;
				} else if ( rc == LDAP_REFERRAL || rc == LDAP_NO_SUCH_OBJECT ) {
					syncrepl_add_glue( op, e );
					ret = 0;
					goto done;
				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR,
						"syncrepl_entry : be_add failed (%d)\n",
						rc, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
						"syncrepl_entry : be_add failed (%d)\n",
						rc, 0, 0 );
#endif
					ret = 1;
					goto done;
				}
			} else {
				be_entry_release_w( op, e );
				ret = 0;
				goto done;
			}
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"syncrepl_entry : be_search failed (%d)\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"syncrepl_entry : be_search failed (%d)\n", rc, 0, 0 );
#endif
			ret = 1;
			goto done;
		}

	case LDAP_SYNC_DELETE :
		/* Already deleted */
		ret = 0;
		goto done;

	default :
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_entry : unknown syncstate\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"syncrepl_entry : unknown syncstate\n", 0, 0, 0 );
#endif
		ret = 1;
		goto done;
	}

done :

	if ( syncUUID_strrep.bv_val ) {
		ber_memfree_x( syncUUID_strrep.bv_val, op->o_tmpmemctx );
	}
	if ( si->si_syncUUID_ndn.bv_val ) {
		ber_memfree_x( si->si_syncUUID_ndn.bv_val, op->o_tmpmemctx );
	}
	return ret;
}

static struct berval gcbva[] = {
	BER_BVC("top"),
	BER_BVC("glue"),
	BER_BVNULL
};

static void
syncrepl_del_nonpresent(
	Operation *op,
	syncinfo_t *si )
{
	Backend* be = op->o_bd;
	slap_callback	cb = { NULL };
	SlapReply	rs = {REP_RESULT};
	struct nonpresent_entry *np_list, *np_prev;
	int rc;
	Modifications *ml;
	Modifications *mlnext;
	Modifications *mod;
	Modifications *modlist = NULL;
	Modifications **modtail = &modlist;
	Attribute	*attr;

	struct berval pdn = BER_BVNULL;
	struct berval org_req_dn = BER_BVNULL;
	struct berval org_req_ndn = BER_BVNULL;
	struct berval org_dn = BER_BVNULL;
	struct berval org_ndn = BER_BVNULL;
	int	org_managedsait;

	op->o_req_dn = si->si_base;
	op->o_req_ndn = si->si_base;

	cb.sc_response = nonpresent_callback;
	cb.sc_private = si;

	op->o_callback = &cb;
	op->o_tag = LDAP_REQ_SEARCH;
	op->ors_scope = si->si_scope;
	op->ors_deref = LDAP_DEREF_NEVER;
	op->o_time = slap_get_time();
	op->ors_tlimit = SLAP_NO_LIMIT;
	op->ors_slimit = SLAP_NO_LIMIT;
	op->ors_attrsonly = 0;
	op->ors_attrs = NULL;
	op->ors_filter = str2filter_x( op, si->si_filterstr.bv_val );
	op->ors_filterstr = si->si_filterstr;

	op->o_nocaching = 1;
	op->o_managedsait = 0;

	if ( limits_check( op, &rs ) == 0 ) {
		be->be_search( op, &rs );
	}

	op->o_managedsait = 1;
	op->o_nocaching = 0;

	if ( op->ors_filter ) filter_free_x( op, op->ors_filter );

	if ( !LDAP_LIST_EMPTY( &si->si_nonpresentlist ) ) {
		np_list = LDAP_LIST_FIRST( &si->si_nonpresentlist );
		while ( np_list != NULL ) {
			LDAP_LIST_REMOVE( np_list, npe_link );
			np_prev = np_list;
			np_list = LDAP_LIST_NEXT( np_list, npe_link );
			op->o_tag = LDAP_REQ_DELETE;
			op->o_callback = &cb;
			cb.sc_response = null_callback;
			cb.sc_private = si;
			op->o_req_dn = *np_prev->npe_name;
			op->o_req_ndn = *np_prev->npe_nname;
			rc = op->o_bd->be_delete( op, &rs );

			if ( rc == LDAP_NOT_ALLOWED_ON_NONLEAF ) {
				mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
				mod->sml_op = LDAP_MOD_REPLACE;
				mod->sml_desc = slap_schema.si_ad_objectClass;
				mod->sml_type = mod->sml_desc->ad_cname;
				mod->sml_values = &gcbva[0];
				*modtail = mod;
				modtail = &mod->sml_next;

				mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
				mod->sml_op = LDAP_MOD_REPLACE;
				mod->sml_desc = slap_schema.si_ad_structuralObjectClass;
				mod->sml_type = mod->sml_desc->ad_cname;
				mod->sml_values = &gcbva[1];
				*modtail = mod;
				modtail = &mod->sml_next;

				op->o_tag = LDAP_REQ_MODIFY;
				op->orm_modlist = modlist;

				rc = be->be_modify( op, &rs );

				for ( ml = modlist; ml != NULL; ml = mlnext ) {
					mlnext = ml->sml_next;
					free( ml );
				}
			}

			org_req_dn = op->o_req_dn;
			org_req_ndn = op->o_req_ndn;
			org_dn = op->o_dn;
			org_ndn = op->o_ndn;
			org_managedsait = get_manageDSAit( op );
			op->o_dn = op->o_bd->be_rootdn;
			op->o_ndn = op->o_bd->be_rootndn;
			op->o_managedsait = 1;

			while ( rs.sr_err == LDAP_SUCCESS &&
					op->o_delete_glue_parent ) {
				op->o_delete_glue_parent = 0;
				if ( !be_issuffix( op->o_bd, &op->o_req_ndn )) {
					slap_callback cb = { NULL };
					cb.sc_response = slap_null_cb;
					dnParent( &op->o_req_ndn, &pdn );
					op->o_req_dn = pdn;
					op->o_req_ndn = pdn;
					op->o_callback = &cb;
					/* give it a root privil ? */
					op->o_bd->be_delete( op, &rs );
				} else {
					break;
			    }
			}

			op->o_managedsait = org_managedsait;
			op->o_dn = org_dn;
			op->o_ndn = org_ndn;
			op->o_req_dn = org_req_dn;
			op->o_req_ndn = org_req_ndn;
			op->o_delete_glue_parent = 0;

			ber_bvfree( np_prev->npe_name );
			ber_bvfree( np_prev->npe_nname );
			op->o_req_dn.bv_val = NULL;
			op->o_req_ndn.bv_val = NULL;
			ch_free( np_prev );
		}
	}

	return;
}

void
syncrepl_add_glue(
	Operation* op,
	Entry *e )
{
	Backend *be = op->o_bd;
	slap_callback cb = { NULL };
	Attribute	*a;
	int	rc;
	int suffrdns;
	int i;
	struct berval dn = {0, NULL};
	struct berval ndn = {0, NULL};
	Entry	*glue;
	SlapReply	rs = {REP_RESULT};
	char	*ptr, *comma;

	op->o_tag = LDAP_REQ_ADD;
	op->o_callback = &cb;
	cb.sc_response = null_callback;
	cb.sc_private = NULL;

	dn = e->e_name;
	ndn = e->e_nname;

	/* count RDNs in suffix */
	if ( be->be_nsuffix[0].bv_len ) {
		for (i=0, ptr=be->be_nsuffix[0].bv_val; ptr; ptr=strchr( ptr, ',' )) {
			ptr++;
			i++;
		}
		suffrdns = i;
	} else {
		/* suffix is "" */
		suffrdns = 0;
	}

	/* Start with BE suffix */
	for ( i = 0, ptr = NULL; i < suffrdns; i++ ) {
		comma = strrchr(dn.bv_val, ',');
		if ( ptr ) *ptr = ',';
		if ( comma ) *comma = '\0';
		ptr = comma;
	}
	if ( ptr ) {
		*ptr++ = ',';
		dn.bv_len -= ptr - dn.bv_val;
		dn.bv_val = ptr;
	}
	/* the normalizedDNs are always the same length, no counting
	 * required.
	 */
	if ( ndn.bv_len > be->be_nsuffix[0].bv_len ) {
		ndn.bv_val += ndn.bv_len - be->be_nsuffix[0].bv_len;
		ndn.bv_len = be->be_nsuffix[0].bv_len;
	}

	while ( ndn.bv_val > e->e_nname.bv_val ) {
		glue = (Entry *) ch_calloc( 1, sizeof(Entry) );
		ber_dupbv( &glue->e_name, &dn );
		ber_dupbv( &glue->e_nname, &ndn );

		a = ch_calloc( 1, sizeof( Attribute ));
		a->a_desc = slap_schema.si_ad_objectClass;

		a->a_vals = ch_calloc( 3, sizeof( struct berval ));
		ber_dupbv( &a->a_vals[0], &gcbva[0] );
		ber_dupbv( &a->a_vals[1], &gcbva[1] );
		ber_dupbv( &a->a_vals[2], &gcbva[2] );

		a->a_nvals = a->a_vals;

		a->a_next = glue->e_attrs;
		glue->e_attrs = a;

		a = ch_calloc( 1, sizeof( Attribute ));
		a->a_desc = slap_schema.si_ad_structuralObjectClass;

		a->a_vals = ch_calloc( 2, sizeof( struct berval ));
		ber_dupbv( &a->a_vals[0], &gcbva[1] );
		ber_dupbv( &a->a_vals[1], &gcbva[2] );

		a->a_nvals = a->a_vals;

		a->a_next = glue->e_attrs;
		glue->e_attrs = a;

		op->o_req_dn = glue->e_name;
		op->o_req_ndn = glue->e_nname;
		op->ora_e = glue;
		rc = be->be_add ( op, &rs );
		if ( rc == LDAP_SUCCESS ) {
			be_entry_release_w( op, glue );
		} else {
		/* incl. ALREADY EXIST */
			entry_free( glue );
		}

		/* Move to next child */
		for (ptr = dn.bv_val-2; ptr > e->e_name.bv_val && *ptr != ','; ptr--) {
			/* empty */
		}
		if ( ptr == e->e_name.bv_val ) break;
		dn.bv_val = ++ptr;
		dn.bv_len = e->e_name.bv_len - (ptr-e->e_name.bv_val);
		for( ptr = ndn.bv_val-2;
			ptr > e->e_nname.bv_val && *ptr != ',';
			ptr--)
		{
			/* empty */
		}
		ndn.bv_val = ++ptr;
		ndn.bv_len = e->e_nname.bv_len - (ptr-e->e_nname.bv_val);
	}

	op->o_req_dn = e->e_name;
	op->o_req_ndn = e->e_nname;
	op->ora_e = e;
	rc = be->be_add ( op, &rs );
	if ( rc == LDAP_SUCCESS ) {
		be_entry_release_w( op, e );
	} else {
		entry_free( e );
	}

	return;
}

static struct berval ocbva[] = {
	BER_BVC("top"),
	BER_BVC("subentry"),
	BER_BVC("syncConsumerSubentry"),
	BER_BVNULL
};

static struct berval cnbva[] = {
	BER_BVNULL,
	BER_BVNULL
};

static struct berval ssbva[] = {
	BER_BVC("{}"),
	BER_BVNULL
};

static struct berval scbva[] = {
	BER_BVNULL,
	BER_BVNULL
};

void
syncrepl_updateCookie(
	syncinfo_t *si,
	Operation *op,
	struct berval *pdn,
	struct sync_cookie *syncCookie )
{
	Backend *be = op->o_bd;
	Modifications *ml;
	Modifications *mlnext;
	Modifications *mod;
	Modifications *modlist = NULL;
	Modifications **modtail = &modlist;

	const char	*text;
	char txtbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof txtbuf;

	Entry* e = NULL;
	int rc;

	char syncrepl_cbuf[sizeof(CN_STR SYNCREPL_STR)];
	struct berval slap_syncrepl_dn_bv = BER_BVNULL;
	struct berval slap_syncrepl_cn_bv = BER_BVNULL;
	
	slap_callback cb = { NULL };
	SlapReply	rs = {REP_RESULT};

	slap_sync_cookie_free( &si->si_syncCookie, 0 );
	slap_dup_sync_cookie( &si->si_syncCookie, syncCookie );

	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_desc = slap_schema.si_ad_objectClass;
	mod->sml_type = mod->sml_desc->ad_cname;
	mod->sml_values = ocbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	ber_dupbv( &cnbva[0], (struct berval *) &slap_syncrepl_bvc );
	assert( si->si_rid < 1000 );
	cnbva[0].bv_len = snprintf( cnbva[0].bv_val,
		slap_syncrepl_bvc.bv_len + 1,
		"syncrepl%ld", si->si_rid );
	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_desc = slap_schema.si_ad_cn;
	mod->sml_type = mod->sml_desc->ad_cname;
	mod->sml_values = cnbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	if ( scbva[0].bv_val ) ch_free( scbva[0].bv_val );
	ber_dupbv( &scbva[0], &si->si_syncCookie.octet_str[0] );
	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_desc = slap_schema.si_ad_syncreplCookie;
	mod->sml_type = mod->sml_desc->ad_cname;
	mod->sml_values = scbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_desc = slap_schema.si_ad_subtreeSpecification;
	mod->sml_type = mod->sml_desc->ad_cname;
	mod->sml_values = ssbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	mlnext = mod;

	op->o_tag = LDAP_REQ_ADD;
	rc = slap_mods_opattrs( op, modlist, modtail,
		 &text, txtbuf, textlen );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		ml->sml_op = LDAP_MOD_REPLACE;
	}

	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_updateCookie: mods opattrs (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_updateCookie: mods opattrs (%s)\n",
			 text, 0, 0 );
#endif
	}

	e = ( Entry * ) ch_calloc( 1, sizeof( Entry ));

	slap_syncrepl_cn_bv.bv_val = syncrepl_cbuf;
	assert( si->si_rid < 1000 );
	slap_syncrepl_cn_bv.bv_len = snprintf( slap_syncrepl_cn_bv.bv_val,
		slap_syncrepl_cn_bvc.bv_len + 1,
		"cn=syncrepl%ld", si->si_rid );

	build_new_dn( &slap_syncrepl_dn_bv, pdn, &slap_syncrepl_cn_bv,
		op->o_tmpmemctx );
	ber_dupbv( &e->e_name, &slap_syncrepl_dn_bv );
	ber_dupbv( &e->e_nname, &slap_syncrepl_dn_bv );

	if ( slap_syncrepl_dn_bv.bv_val ) {
		slap_sl_free( slap_syncrepl_dn_bv.bv_val, op->o_tmpmemctx );
	}

	e->e_attrs = NULL;

	rc = slap_mods2entry( modlist, &e, 1, 1, &text, txtbuf, textlen );

	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_updateCookie: mods2entry (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_updateCookie: mods2entry (%s)\n",
			 text, 0, 0 );
#endif
	}

	cb.sc_response = null_callback;
	cb.sc_private = si;

	op->o_callback = &cb;
	op->o_req_dn = e->e_name;
	op->o_req_ndn = e->e_nname;

	/* update persistent cookie */
update_cookie_retry:
	op->o_tag = LDAP_REQ_MODIFY;
	op->orm_modlist = modlist;
	rc = be->be_modify( op, &rs );

	if ( rc != LDAP_SUCCESS ) {
		if ( rc == LDAP_REFERRAL ||
			 rc == LDAP_NO_SUCH_OBJECT ) {
			op->o_tag = LDAP_REQ_ADD;
			op->ora_e = e;
			rc = be->be_add( op, &rs );
			if ( rc != LDAP_SUCCESS ) {
				if ( rc == LDAP_ALREADY_EXISTS ) {
					goto update_cookie_retry;
				} else if ( rc == LDAP_REFERRAL ||
							rc == LDAP_NO_SUCH_OBJECT ) {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR,
						"cookie will be non-persistent\n",
						0, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
						"cookie will be non-persistent\n",
						0, 0, 0 );
#endif
				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR,
						"be_add failed (%d)\n",
						rc, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
						"be_add failed (%d)\n",
						rc, 0, 0 );
#endif
				}
			} else {
				be_entry_release_w( op, e );
				goto done;
			}
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"be_modify failed (%d)\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"be_modify failed (%d)\n", rc, 0, 0 );
#endif
		}
	}

	if ( e != NULL ) {
		entry_free( e );
	}

done :

	if ( cnbva[0].bv_val ) {
		ch_free( cnbva[0].bv_val );
		cnbva[0].bv_val = NULL;
	}
	if ( scbva[0].bv_val ) {
		ch_free( scbva[0].bv_val );
		scbva[0].bv_val = NULL;
	}

	if ( mlnext->sml_next ) {
		slap_mods_free( mlnext->sml_next );
		mlnext->sml_next = NULL;
	}

	for (ml = modlist ; ml != NULL; ml = mlnext ) {
		mlnext = ml->sml_next;
		free( ml );
	}

	return;
}

int
syncrepl_isupdate( Operation *op )
{
	return ( syncrepl_isupdate_dn( op->o_bd, &op->o_ndn ));
}

int
syncrepl_isupdate_dn(
	Backend*		be,
	struct berval*	ndn )
{
	syncinfo_t*	si;
	int			ret = 0;

	if ( !LDAP_STAILQ_EMPTY( &be->be_syncinfo )) {
		LDAP_STAILQ_FOREACH( si, &be->be_syncinfo, si_next ) {
			if ( ( ret = dn_match( &si->si_updatedn, ndn ) ) ) {
				return ret;
			}
		}
	}
	return 0;
}

static int
dn_callback(
	Operation*	op,
	SlapReply*	rs )
{
	syncinfo_t *si = op->o_callback->sc_private;

	if ( rs->sr_type == REP_SEARCH ) {
		if ( si->si_syncUUID_ndn.bv_val != NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"dn_callback : consistency error - entryUUID is not unique\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"dn_callback : consistency error - entryUUID is not unique\n", 0, 0, 0 );
#endif
		} else {
			ber_dupbv_x( &si->si_syncUUID_ndn, &rs->sr_entry->e_nname, op->o_tmpmemctx );
		}
	} else if ( rs->sr_type == REP_RESULT ) {
		if ( rs->sr_err == LDAP_SIZELIMIT_EXCEEDED ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"dn_callback : consistency error - entryUUID is not unique\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"dn_callback : consistency error - entryUUID is not unique\n", 0, 0, 0 );
#endif
		}
	}

	return LDAP_SUCCESS;
}

static int
nonpresent_callback(
	Operation*	op,
	SlapReply*	rs )
{
	syncinfo_t *si = op->o_callback->sc_private;
	Attribute *a;
	int count = 0;
	struct berval* present_uuid = NULL;
	struct nonpresent_entry *np_entry;

	if ( rs->sr_type == REP_RESULT ) {
		count = avl_free( si->si_presentlist, avl_ber_bvfree );
		si->si_presentlist = NULL;

	} else if ( rs->sr_type == REP_SEARCH ) {
		a = attr_find( rs->sr_entry->e_attrs, slap_schema.si_ad_entryUUID );

		if ( a == NULL ) return 0;

		present_uuid = avl_find( si->si_presentlist, &a->a_nvals[0],
			syncuuid_cmp );

		if ( present_uuid == NULL ) {
			np_entry = (struct nonpresent_entry *)
				ch_calloc( 1, sizeof( struct nonpresent_entry ));
			np_entry->npe_name = ber_dupbv( NULL, &rs->sr_entry->e_name );
			np_entry->npe_nname = ber_dupbv( NULL, &rs->sr_entry->e_nname );
			LDAP_LIST_INSERT_HEAD( &si->si_nonpresentlist, np_entry, npe_link );

		} else {
			avl_delete( &si->si_presentlist,
					&a->a_nvals[0], syncuuid_cmp );
			ch_free( present_uuid->bv_val );
			ch_free( present_uuid );
		}
	}
	return LDAP_SUCCESS;
}

static int
null_callback(
	Operation*	op,
	SlapReply*	rs )
{
	if ( rs->sr_err != LDAP_SUCCESS &&
		rs->sr_err != LDAP_REFERRAL &&
		rs->sr_err != LDAP_ALREADY_EXISTS &&
		rs->sr_err != LDAP_NO_SUCH_OBJECT &&
		rs->sr_err != LDAP_NOT_ALLOWED_ON_NONLEAF )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"null_callback : error code 0x%x\n",
			rs->sr_err, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"null_callback : error code 0x%x\n",
			rs->sr_err, 0, 0 );
#endif
	}
	return LDAP_SUCCESS;
}

Entry *
slap_create_syncrepl_entry(
	Backend *be,
	struct berval *context_csn,
	struct berval *rdn,
	struct berval *cn )
{
	Entry* e;

	struct berval bv;

	e = ( Entry * ) ch_calloc( 1, sizeof( Entry ));

	attr_merge( e, slap_schema.si_ad_objectClass, ocbva, NULL );

	attr_merge_one( e, slap_schema.si_ad_structuralObjectClass,
		&ocbva[1], NULL );

	attr_merge_one( e, slap_schema.si_ad_cn, cn, NULL );

	if ( context_csn ) {
		attr_merge_one( e, slap_schema.si_ad_syncreplCookie,
			context_csn, NULL );
	}

	bv.bv_val = "{}";
	bv.bv_len = sizeof("{}")-1;
	attr_merge_one( e, slap_schema.si_ad_subtreeSpecification, &bv, NULL );

	build_new_dn( &e->e_name, &be->be_nsuffix[0], rdn, NULL );
	ber_dupbv( &e->e_nname, &e->e_name );

	return e;
}

struct berval *
slap_uuidstr_from_normalized(
	struct berval* uuidstr,
	struct berval* normalized,
	void *ctx )
{
	struct berval *new;
	unsigned char nibble;
	int i, d = 0;

	if ( normalized == NULL ) return NULL;
	if ( normalized->bv_len != 16 ) return NULL;

	if ( uuidstr ) {
		new = uuidstr;
	} else {
		new = (struct berval *)slap_sl_malloc( sizeof(struct berval), ctx );
	}

	new->bv_len = 36;

	if (( new->bv_val = slap_sl_malloc( new->bv_len + 1, ctx )) == NULL) {
		if ( !uuidstr ) slap_sl_free( new, ctx );
		return NULL;
	}

	for ( i = 0; i < 16; i++ ) {
		if ( i == 4 || i == 6 || i == 8 || i == 10 ) {
			new->bv_val[(i<<1)+d] = '-';
			d += 1;
		}

		nibble = (normalized->bv_val[i] >> 4) & 0xF;
		if ( nibble < 10 ) {
			new->bv_val[(i<<1)+d] = nibble + '0';
		} else {
			new->bv_val[(i<<1)+d] = nibble - 10 + 'a';
		}

		nibble = (normalized->bv_val[i]) & 0xF;
		if ( nibble < 10 ) {
			new->bv_val[(i<<1)+d+1] = nibble + '0';
		} else {
			new->bv_val[(i<<1)+d+1] = nibble - 10 + 'a';
		}
	}

	new->bv_val[new->bv_len] = '\0';
	return new;
}

static int
syncuuid_cmp( const void* v_uuid1, const void* v_uuid2 )
{
	const struct berval *uuid1 = v_uuid1;
	const struct berval *uuid2 = v_uuid2;
	int rc = uuid1->bv_len - uuid2->bv_len;
	if ( rc ) return rc;
	return ( memcmp( uuid1->bv_val, uuid2->bv_val, uuid1->bv_len ) );
}

static void
avl_ber_bvfree( void *bv )
{
	if( bv == NULL ) return;
	if ( ((struct berval *)bv)->bv_val != NULL ) {
		ch_free( ((struct berval *)bv)->bv_val );
	}
	ch_free( (char *) bv );
}

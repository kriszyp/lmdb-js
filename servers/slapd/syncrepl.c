/* $OpenLDAP$ */
/*
 * Replication Engine which uses the LDAP Sync protocol
 */
/* Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <db.h>

#include "ldap_pvt.h"
#include "lutil.h"
#include "slap.h"
#include "lutil_ldap.h"

#include "ldap_rq.h"

static const struct berval slap_syncrepl_bvc = BER_BVC("syncreplxxx");
static const struct berval slap_syncrepl_cn_bvc = BER_BVC("cn=syncreplxxx");

static void
syncrepl_del_nonpresent( LDAP *, Operation * );

/* callback functions */
static int cookie_callback( struct slap_op *, struct slap_rep * );
static int dn_callback( struct slap_op *, struct slap_rep * );
static int nonpresent_callback( struct slap_op *, struct slap_rep * );
static int null_callback( struct slap_op *, struct slap_rep * );
static int contextcsn_callback( Operation*, SlapReply* );

static AttributeDescription **sync_descs;

struct runqueue_s syncrepl_rq;

void
init_syncrepl()
{
	sync_descs = ch_malloc( 4 * sizeof( AttributeDescription * ));
	sync_descs[0] = slap_schema.si_ad_objectClass;
	sync_descs[1] = slap_schema.si_ad_structuralObjectClass;
	sync_descs[2] = slap_schema.si_ad_entryCSN;
	sync_descs[3] = NULL;
}

int
ldap_sync_search(
	syncinfo_t *si,
	LDAP *ld,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	int *msgidp )
{
	BerElement	*ber;
	int timelimit;
	ber_int_t id;

	int rc;
	BerElement	*sync_ber = NULL;
	struct berval *sync_bvalp = NULL;
	LDAPControl c[2];
	LDAPControl **ctrls;
	int err;
	struct timeval timeout;

    /* setup LDAP SYNC control */
    sync_ber = ber_alloc_t( LBER_USE_DER );
    ber_set_option( sync_ber, LBER_OPT_BER_MEMCTX, NULL );

    if ( si->syncCookie ) {
        ber_printf( sync_ber, "{eO}", abs(si->type), si->syncCookie );
    } else {
        ber_printf( sync_ber, "{e}", abs(si->type) );
    }

    if ( ber_flatten( sync_ber, &sync_bvalp ) == LBER_ERROR ) {
        ber_free( sync_ber, 1 );
        return LBER_ERROR;
    }
    ber_free( sync_ber, 1 );

    ctrls = (LDAPControl**) sl_calloc( 3, sizeof(LDAPControl*), NULL );

    c[0].ldctl_oid = LDAP_CONTROL_SYNC;
    c[0].ldctl_value = (*sync_bvalp);
    c[0].ldctl_iscritical = si->type < 0;
    ctrls[0] = &c[0];

    if ( si->authzId ) {
        c[1].ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
        c[1].ldctl_value.bv_val = si->authzId;
        c[1].ldctl_value.bv_len = strlen( si->authzId );
        c[1].ldctl_iscritical = 1;
        ctrls[1] = &c[1];
    } else {
        ctrls[1] = NULL;
    }

    ctrls[2] = NULL;

    err = ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, ctrls );

    ber_bvfree( sync_bvalp );
    ch_free( ctrls );

    if ( err != LDAP_OPT_SUCCESS )
        fprintf( stderr, "Could not set controls : %d\n", err );

	timeout.tv_sec = si->tlimit > 0 ? si->tlimit : 1;

	rc = ldap_search_ext( ld, si->base, si->scope, si->filterstr,
						  si->attrs, si->attrsonly, sctrls, cctrls,
						  si->tlimit < 0 ? NULL : &timeout,
						  si->slimit, msgidp );

	return rc;
}

void *
do_syncrepl(
	void	*ctx,
	void	*arg )
{
	struct re_s* rtask = arg;
	syncinfo_t *si = ( syncinfo_t * ) rtask->arg;
	Backend *be = si->be;

	SlapReply	rs = {REP_RESULT};

	LDAPControl	c[2];
	LDAPControl	**sctrls = NULL;
	LDAPControl	**rctrls = NULL;
	LDAPControl	*rctrlp = NULL;
	BerElement	*sync_ber = NULL;
	struct berval	*sync_bvalp = NULL;

	BerElement	*ctrl_ber = NULL;
	BerElement	*res_ber = NULL;

	LDAP	*ld = NULL;
	LDAPMessage	*res = NULL;
	LDAPMessage	*msg = NULL;

	ber_int_t	msgid;

	int		nresponses, nreferences, nextended, npartial;
	int		nresponses_psearch;

	int		cancel_msgid = -1;
	char		*retoid = NULL;
	struct berval	*retdata = NULL;

	int		sync_info_arrived = 0;
	Entry		*entry = NULL;

	int		syncstate;
	struct berval	syncUUID = { 0, NULL };
	struct berval	syncCookie = { 0, NULL };
	struct berval	syncCookie_req = { 0, NULL };

	int	rc;
	int	err;
	ber_len_t	len;
	int	syncinfo_arrived = 0;

	char **tmp = NULL;
	AttributeDescription** descs = NULL;

	Connection conn;
	Operation op = {0};
	slap_callback	cb;

	void *memctx = NULL;
	ber_len_t memsiz;
	
	int i, j, k, n;
	int rc_efree;

	struct berval base_bv = { 0, NULL };
	struct berval pbase = { 0, NULL };
	struct berval nbase = { 0, NULL };
	struct berval psubrdn = { 0, NULL };
	struct berval nsubrdn = { 0, NULL };
	struct berval psub = { 0, NULL };
	struct berval nsub = { 0, NULL };
	Modifications	*modlist = NULL;
	Modifications	*ml, *mlnext;
	char *def_filter_str = NULL;

	struct berval slap_syncrepl_cn_bv = BER_BVNULL;

	const char		*text;
	int				match;

	struct timeval *tout_p = NULL;
	struct timeval tout = { 10, 0 };

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, DETAIL1, "do_syncrepl\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=>do_syncrepl\n", 0, 0, 0 );
#endif

	if ( si == NULL )
		return NULL;

	if ( abs(si->type) != LDAP_SYNC_REFRESH_ONLY &&
	     abs(si->type) != LDAP_SYNC_REFRESH_AND_PERSIST ) {
		return NULL;
	}

	si->sync_mode = LDAP_SYNC_STATE_MODE;

	/* Init connection to master */

	rc = ldap_initialize( &ld, si->provideruri );
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_syncrepl: "
			"ldap_initialize failed (%s)\n",
			si->provideruri, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_syncrepl: "
			"ldap_initialize failed (%s)\n",
			si->provideruri, 0, 0 );
#endif
	}

	op.o_protocol = LDAP_VERSION3;
	ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &op.o_protocol );

	/* Bind to master */

	if ( si->tls ) {
		rc = ldap_start_tls_s( ld, NULL, NULL );
		if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "do_syncrepl: "
				"%s: ldap_start_tls failed (%d)\n",
				si->tls == TLS_CRITICAL ? "Error" : "Warning",
				rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"%s: ldap_start_tls failed (%d)\n",
				si->tls == TLS_CRITICAL ? "Error" : "Warning",
				rc, 0 );
#endif
			if( si->tls == TLS_CRITICAL )
				return NULL;
		}
	}

	if ( si->bindmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		void *defaults;

		if ( si->secprops != NULL ) {
			int err = ldap_set_option( ld,
					LDAP_OPT_X_SASL_SECPROPS, si->secprops);

			if( err != LDAP_OPT_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, "do_bind: Error: "
					"ldap_set_option(%s,SECPROPS,\"%s\") failed!\n",
					si->provideruri, si->secprops, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "Error: ldap_set_option "
					"(%s,SECPROPS,\"%s\") failed!\n",
					si->provideruri, si->secprops, NULL );
#endif
				return NULL;
			}
		}

		defaults = lutil_sasl_defaults( ld,
				si->saslmech,
			       	si->realm,
			       	si->authcId,
			       	si->passwd,
			       	si->authzId );

		rc = ldap_sasl_interactive_bind_s( ld,
				si->binddn,
				si->saslmech,
				NULL, NULL,
				LDAP_SASL_QUIET,
				lutil_sasl_interact,
				defaults );

		/* FIXME : different error behaviors according to
			1) return code
			2) on err policy : exit, retry, backoff ...
		*/
		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "do_syncrepl: "
				"ldap_sasl_interactive_bind_s failed (%d)\n",
				rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_syncrepl: "
				"ldap_sasl_interactive_bind_s failed (%d)\n",
				rc, 0, 0 );
#endif
			return NULL;
		}
#else /* HAVE_CYRUS_SASL */
		fprintf( stderr, "not compiled with SASL support\n" );
		return NULL;
#endif
	} else {
		rc = ldap_bind_s( ld, si->binddn, si->passwd, si->bindmethod );
		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "do_syncrepl: "
				"ldap_bind_s failed (%d)\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_syncrepl: "
				"ldap_bind_s failed (%d)\n", rc, 0, 0 );
#endif
			return NULL;
		}
	}

	/* set thread context in syncinfo */
	si->ctx = ctx;

	/* set memory context */
#define SLAB_SIZE 1048576
	memsiz = SLAB_SIZE;
	memctx = sl_mem_create( memsiz, ctx );
	op.o_tmpmemctx = memctx;
	op.o_tmpmfuncs = &sl_mfuncs;

	op.o_si = si;
	op.o_tag = LDAP_REQ_SEARCH;
	op.o_dn = si->updatedn;
	op.o_ndn = si->updatedn;
	op.o_callback = &cb;
	op.o_time = slap_get_time();
	op.o_managedsait = 1;
	op.o_threadctx = si->ctx;
	op.o_bd = be;
	op.o_conn = &conn;
	op.o_connid = op.o_conn->c_connid;
	op.ors_scope = LDAP_SCOPE_BASE;
	op.ors_deref = LDAP_DEREF_NEVER;
	op.ors_slimit = 0;
	op.ors_tlimit = 0;
	op.ors_attrsonly = 0;
	op.ors_attrs = NULL;
	op.ors_filter = str2filter_x( &op, def_filter_str = "(objectClass=*)" );
	ber_str2bv( def_filter_str, 0, 0, &op.ors_filterstr );

	si->conn = &conn;
	conn.c_send_ldap_result = slap_send_ldap_result;
	conn.c_send_search_entry = slap_send_search_entry;
	conn.c_send_search_reference = slap_send_search_reference;

	/* get syncrepl cookie of shadow replica from subentry */
	ber_str2bv( si->base, 0, 0, &base_bv ); 
	dnPrettyNormal( 0, &base_bv, &pbase, &nbase, op.o_tmpmemctx );

	ber_dupbv( &slap_syncrepl_cn_bv, (struct berval *) &slap_syncrepl_cn_bvc );
	slap_syncrepl_cn_bv.bv_len = snprintf( slap_syncrepl_cn_bv.bv_val,
										slap_syncrepl_cn_bvc.bv_len,
										"cn=syncrepl%d", si->id );
	build_new_dn( &op.o_req_dn, &pbase, &slap_syncrepl_cn_bv, op.o_tmpmemctx );
	build_new_dn( &op.o_req_ndn, &nbase, &slap_syncrepl_cn_bv, op.o_tmpmemctx );

	/* set callback function */
	cb.sc_response = cookie_callback;
	cb.sc_private = si;

	/* search subentry to retrieve cookie */
	si->syncCookie = NULL;
	be->be_search( &op, &rs );

	if ( op.o_req_dn.bv_val )
		ch_free( op.o_req_dn.bv_val );
	if ( op.o_req_ndn.bv_val )
		ch_free( op.o_req_ndn.bv_val );
	if ( op.ors_filter )
		filter_free( op.ors_filter );
	if ( op.ors_filterstr.bv_val )
		ch_free( op.ors_filterstr.bv_val );
	if ( slap_syncrepl_cn_bv.bv_val )
		ch_free( slap_syncrepl_cn_bv.bv_val );
	if ( pbase.bv_val )
		ch_free( pbase.bv_val );
	if ( nbase.bv_val )
		ch_free( nbase.bv_val );

	ber_dupbv( &syncCookie_req, si->syncCookie );

	psub = be->be_nsuffix[0];

	for ( n = 0; si->attrs[ n ] != NULL; n++ ) ;

	if ( n != 0 ) {
		/* Delete Attributes */
		descs = sync_descs;
		for ( i = 0; descs[i] != NULL; i++ ) {
			for ( j = 0; si->attrs[j] != NULL; j++ ) {
				if ( !strcmp( si->attrs[j], descs[i]->ad_cname.bv_val )) {
					ch_free( si->attrs[j] );
					for ( k = j; si->attrs[k] != NULL; k++ ) {
						si->attrs[k] = si->attrs[k+1];
					}
				}
			}
		}
		for ( n = 0; si->attrs[ n ] != NULL; n++ );
		tmp = ( char ** ) ch_realloc( si->attrs, ( n + 4 ) * sizeof( char * ));
		if ( tmp == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, "out of memory\n", 0,0,0 );
#else
			Debug( LDAP_DEBUG_ANY, "out of memory\n", 0,0,0 );
#endif
		}
	} else {
		tmp = ( char ** ) ch_realloc( si->attrs, 5 * sizeof( char * ));
		if ( tmp == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, "out of memory\n", 0,0,0 );
#else
			Debug( LDAP_DEBUG_ANY, "out of memory\n", 0,0,0 );
#endif
		}
		tmp[ n++ ] = ch_strdup( "*" );
	}
	
	descs = sync_descs;
	si->attrs = tmp;

	/* Add Attributes */

	for ( i = 0; descs[ i ] != NULL; i++ ) {
		si->attrs[ n++ ] = ch_strdup ( descs[i]->ad_cname.bv_val );
		si->attrs[ n ] = NULL;
	}

	rc = ldap_sync_search( si, ld, NULL, NULL, &msgid );
	if( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "syncrepl: ldap_search_ext: %s (%d)\n",
							ldap_err2string( rc ), rc );
		return NULL;
	}

	if ( abs(si->type) == LDAP_SYNC_REFRESH_AND_PERSIST ){
		tout_p = &tout;
	} else {
		tout_p = NULL;
	}

	while (( rc = ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ONE, tout_p, &res )) >= 0 ) {

		if ( rc == 0 ) {
			if ( slapd_abrupt_shutdown ) {
				break;
			} else {
				continue;
			}
		}

		for ( msg = ldap_first_message( ld, res );
		      msg != NULL;
		      msg = ldap_next_message( ld, msg ) )
		{
			syncCookie.bv_len = 0; syncCookie.bv_val = NULL;
			switch( ldap_msgtype( msg ) ) {
			case LDAP_RES_SEARCH_ENTRY:
				entry = syncrepl_message_to_entry( si, ld, &op, msg,
					&modlist, &syncstate, &syncUUID, &syncCookie );
				rc_efree = syncrepl_entry( si, ld, &op, entry, modlist,
						syncstate, &syncUUID, &syncCookie, !syncinfo_arrived );
				if ( syncCookie.bv_len ) {
					syncrepl_updateCookie( si, ld, &op, &psub, &syncCookie );
				}
				if ( modlist ) {
					slap_mods_free( modlist );
				}
				if ( rc_efree ) {
					entry_free( entry );
				}
				break;

			case LDAP_RES_SEARCH_REFERENCE:
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR,
					"do_syncrepl : reference received\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"do_syncrepl : reference received\n", 0, 0, 0 );
#endif
				break;

			case LDAP_RES_SEARCH_RESULT:
				ldap_parse_result( ld, msg, &err, NULL, NULL, NULL, &rctrls, 0 );
				if ( rctrls ) {
					rctrlp = *rctrls;
					ctrl_ber = ber_alloc_t( LBER_USE_DER );
					ber_set_option( ctrl_ber, LBER_OPT_BER_MEMCTX, &op.o_tmpmemctx );
					ber_write( ctrl_ber, rctrlp->ldctl_value.bv_val, rctrlp->ldctl_value.bv_len, 0 );
					ber_reset( ctrl_ber, 1 );

					ber_scanf( ctrl_ber, "{" /*"}"*/);
					if ( ber_peek_tag( ctrl_ber, &len )
						== LDAP_SYNC_TAG_COOKIE ) {
						ber_scanf( ctrl_ber, "o", &syncCookie );
					}
				}
				value_match( &match, slap_schema.si_ad_entryCSN,
							slap_schema.si_ad_entryCSN->ad_type->sat_ordering,
							SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
							&syncCookie_req, &syncCookie, &text );
				if (si->type == LDAP_SYNC_REFRESH_AND_PERSIST) {
					/* FIXME : different error behaviors according to
						1) err code : LDAP_BUSY ...
						2) on err policy : stop service, stop sync, retry
					*/
					if ( syncCookie.bv_len && match < 0) {
						syncrepl_updateCookie( si, ld, &op, &psub, &syncCookie );
					}
					if ( ctrl_ber )
						ber_free( ctrl_ber, 1 );
					goto done;
				} else {
					/* FIXME : different error behaviors according to
						1) err code : LDAP_BUSY ...
						2) on err policy : stop service, stop sync, retry
					*/
					if ( syncCookie.bv_len && match < 0 ) {
						syncrepl_updateCookie( si, ld, &op, &psub, &syncCookie);
					}
					if ( si->sync_mode == LDAP_SYNC_STATE_MODE && match < 0 ) {
							syncrepl_del_nonpresent( ld, &op );
					}
					if ( ctrl_ber )
						ber_free( ctrl_ber, 1 );
					goto done;
				}
				break;

			case LDAP_RES_INTERMEDIATE:
				rc = ldap_parse_intermediate( ld, msg,
					&retoid, &retdata, NULL, 0 );
				if ( !rc && !strcmp( retoid, LDAP_SYNC_INFO ) ) {
					sync_info_arrived = 1;
					res_ber = ber_init( retdata );
					ber_scanf( res_ber, "{e" /*"}"*/, &syncstate );

					if ( ber_peek_tag( res_ber, &len )
								== LDAP_SYNC_TAG_COOKIE ) {
						ber_scanf( res_ber, /*"{"*/ "o}", &syncCookie );
					} else {
						if ( syncstate == LDAP_SYNC_NEW_COOKIE ) {
#ifdef NEW_LOGGING
							LDAP_LOG( OPERATION, ERR,
								"do_syncrepl : cookie required\n", 0, 0, 0 );
#else
							Debug( LDAP_DEBUG_ANY,
								"do_syncrepl : cookie required\n", 0, 0, 0 );
#endif
						}
					}

					value_match( &match, slap_schema.si_ad_entryCSN,
								slap_schema.si_ad_entryCSN->ad_type->sat_ordering,
								SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
								&syncCookie_req, &syncCookie, &text );

					if ( syncCookie.bv_len && match < 0 ) {
						syncrepl_updateCookie( si, ld, &op, &psub, &syncCookie);
					}

					if ( syncstate == LDAP_SYNC_STATE_MODE_DONE ) {
						if ( match < 0 ) {
							syncrepl_del_nonpresent( ld, &op );
						}
						si->sync_mode = LDAP_SYNC_LOG_MODE;
					} else if ( syncstate == LDAP_SYNC_LOG_MODE_DONE ) {
						si->sync_mode = LDAP_SYNC_PERSIST_MODE;
					} else if ( syncstate == LDAP_SYNC_REFRESH_DONE ) {
						si->sync_mode = LDAP_SYNC_PERSIST_MODE;
					} else if ( syncstate != LDAP_SYNC_NEW_COOKIE ||
								syncstate != LDAP_SYNC_LOG_MODE_DONE ) {
#ifdef NEW_LOGGING
						LDAP_LOG( OPERATION, ERR,
							"do_syncrepl : unknown sync info\n", 0, 0, 0 );
#else
						Debug( LDAP_DEBUG_ANY,
							"do_syncrepl : unknown sync info\n", 0, 0, 0 );
#endif
					}

					ldap_memfree( retoid );
					ber_bvfree( retdata );
					ber_free( res_ber, 1 );
					break;
				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR,"do_syncrepl :"
						" unknown intermediate "
						"response\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY, "do_syncrepl : "
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
				LDAP_LOG( OPERATION, ERR, "do_syncrepl : "
					"unknown message\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "do_syncrepl : "
					"unknown message\n", 0, 0, 0 );
#endif
				break;

			}
			if ( syncCookie.bv_val )
				ch_free( syncCookie.bv_val );
			if ( syncUUID.bv_val )
				ch_free( syncUUID.bv_val );
		}
		ldap_msgfree( res );
	}

	if ( rc == -1 ) {
		int errno;
		const char *errstr;

		ldap_get_option( ld, LDAP_OPT_ERROR_NUMBER, &errno );
		errstr = ldap_err2string( errno );
		
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_syncrepl : %s\n", errstr, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_syncrepl : %s\n", errstr, 0, 0 );
#endif
	}

done:
	if ( syncCookie.bv_val )
		ch_free( syncCookie.bv_val );
	if ( syncCookie_req.bv_val )
		ch_free( syncCookie_req.bv_val );
	if ( syncUUID.bv_val )
		ch_free( syncUUID.bv_val );

	if ( res )
		ldap_msgfree( res );

	ldap_unbind( ld );

	ldap_pvt_thread_mutex_lock( &syncrepl_rq.rq_mutex );
	ldap_pvt_runqueue_stoptask( &syncrepl_rq, rtask );
	if ( si->type == LDAP_SYNC_REFRESH_ONLY ) {
		ldap_pvt_runqueue_resched( &syncrepl_rq, rtask );
	} else {
		ldap_pvt_runqueue_remove( &syncrepl_rq, rtask );
	}
	ldap_pvt_thread_mutex_unlock( &syncrepl_rq.rq_mutex );

	return NULL;
}

Entry*
syncrepl_message_to_entry(
	syncinfo_t	*si,
	LDAP		*ld,
	Operation	*op,
	LDAPMessage	*msg,
	Modifications	**modlist,
	int		*syncstate,
	struct berval	*syncUUID,
	struct berval	*syncCookie
)
{
	Entry		*e;
	BerElement	*ber = NULL;
	BerElement	*tmpber;
	struct berval	bv = {0, NULL};
	Modifications	tmp;
	Modifications	*mod;
	Modifications	**modtail = modlist;
	Backend		*be = op->o_bd;

	const char	*text;
	char txtbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof txtbuf;

	struct berval	**bvals = NULL;
	char		*dn;
	struct berval	bdn = {0, NULL};
	Attribute	*attr;
	struct berval	empty_bv = { 0, NULL };
	int		rc;
	char		*a;

	ber_len_t	len;
	LDAPControl*	rctrlp;
	LDAPControl**	rctrls = NULL;
	BerElement*	ctrl_ber;

	ber_tag_t	tag;

	Modifications *ml = NULL;
	AttributeDescription** descs;
	int i;

	*modlist = NULL;

	if ( ldap_msgtype( msg ) != LDAP_RES_SEARCH_ENTRY ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"Message type should be entry (%d)", ldap_msgtype( msg ), 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"Message type should be entry (%d)", ldap_msgtype( msg ), 0, 0 );
#endif
		return NULL;
	}

	op->o_tag = LDAP_REQ_ADD;

	rc = ldap_get_dn_ber( ld, msg, &ber, &bdn );

	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_message_to_entry : dn get failed (%d)", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"syncrepl_message_to_entry : dn get failed (%d)", rc, 0, 0 );
#endif
		return NULL;
	}

	e = ( Entry * ) ch_calloc( 1, sizeof( Entry ));
	dnPrettyNormal( NULL, &bdn, &e->e_name, &e->e_nname, NULL );

	e->e_attrs = NULL;

	while ( ber_remaining( ber ) ) {
		tag = ber_scanf( ber, "{mW}", &tmp.sml_type, &tmp.sml_values );

		if ( tag == LBER_ERROR ) break;
		if ( tmp.sml_type.bv_val == NULL ) break;

		mod  = (Modifications *) ch_malloc( sizeof( Modifications ));

		mod->sml_op = LDAP_MOD_REPLACE;
		mod->sml_next = NULL;
		mod->sml_desc = NULL;
		mod->sml_type = tmp.sml_type;
		mod->sml_bvalues = tmp.sml_bvalues;
		mod->sml_nvalues = NULL;

		*modtail = mod;
		modtail = &mod->sml_next;
	}

	if ( ber_scanf( ber, "}") == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
				"syncrepl_message_to_entry: ber_scanf failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_message_to_entry: ber_scanf failed\n",
				0, 0, 0 );
#endif
		return NULL;
	}

	ber_free( ber, 0 );
	tmpber = ldap_get_message_ber( msg );
	ber = ber_dup( tmpber );

	ber_scanf( ber, "{xx" );

	rc = ldap_pvt_get_controls( ber, &rctrls );
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_message_to_entry : control get failed (%d)", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"syncrepl_message_to_entry : control get failed (%d)", rc, 0, 0 );
#endif
		return NULL;
	}

	if ( rctrls ) {
		rctrlp = *rctrls;
		ctrl_ber = ber_alloc_t( LBER_USE_DER );
		ber_set_option( ctrl_ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );
		ber_write( ctrl_ber, rctrlp->ldctl_value.bv_val, rctrlp->ldctl_value.bv_len, 0 );
		ber_reset( ctrl_ber, 1 );
		ber_scanf( ctrl_ber, "{eo", syncstate, syncUUID );
		if ( ber_peek_tag( ctrl_ber, &len ) == LDAP_SYNC_TAG_COOKIE ) {
			ber_scanf( ctrl_ber, "o}", syncCookie );
		}
		ber_free( ctrl_ber, 1 );
		ldap_controls_free( rctrls );
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,"syncrepl_message_to_entry : "
			" rctrls absent\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_message_to_entry :"
			" rctrls absent\n", 0, 0, 0 );
#endif
	}

	if ( *syncstate == LDAP_SYNC_PRESENT || *syncstate == LDAP_SYNC_DELETE ) {
		goto done;
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

	ml = *modlist;
	while ( ml != NULL ) {
		AttributeDescription *ad = NULL;
        rc = slap_bv2ad( &ml->sml_type, &ml->sml_desc, &text );

		if( rc != LDAP_SUCCESS ) {
			e = NULL;
			goto done;
		}

		ad = ml->sml_desc;
		ml->sml_desc = NULL;
		ml = ml->sml_next;
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
		return NULL;
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

	return e;
}

int
syncuuid_cmp( const void* v_uuid1, const void* v_uuid2 )
{
	const struct berval *uuid1 = v_uuid1;
	const struct berval *uuid2 = v_uuid2;
	int rc = uuid1->bv_len - uuid2->bv_len;
	if ( rc ) return rc;
	return ( strcmp( uuid1->bv_val, uuid2->bv_val ) );
}

int
syncrepl_entry(
	syncinfo_t* si,
	LDAP *ld,
	Operation *op,
	Entry* e,
	Modifications* modlist,
	int syncstate,
	struct berval* syncUUID,
	struct berval* syncCookie,
	int refresh
)
{
	Backend *be = op->o_bd;
	slap_callback	cb;
	struct berval	csn_bv = {0, NULL};
	struct berval	*syncuuid_bv = NULL;
	char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];

	SlapReply	rs = {REP_RESULT};
	int rc = LDAP_SUCCESS;

	struct berval base_bv = {0, NULL};

	char *filterstr;
	Filter *filter;

	Attribute *a;

	if ( refresh &&
			( syncstate == LDAP_SYNC_PRESENT || syncstate == LDAP_SYNC_ADD )) {
		syncuuid_bv = ber_dupbv( NULL, syncUUID );
		avl_insert( &si->presentlist, (caddr_t) syncuuid_bv,
						syncuuid_cmp, avl_dup_error );
	}

	if ( syncstate == LDAP_SYNC_PRESENT ) {
		if ( e ) {
			return 1;
		} else {
			return 0;
		}
	}

	filterstr = (char *) sl_malloc( strlen("entryUUID=") + syncUUID->bv_len + 1,
									op->o_tmpmemctx ); 
	strcpy( filterstr, "entryUUID=" );
	strcat( filterstr, syncUUID->bv_val );

	si->e = e;
	si->syncUUID_ndn = NULL;

	filter = str2filter( filterstr );
	ber_str2bv( filterstr, strlen(filterstr), 1, &op->ors_filterstr );
	ch_free( filterstr );
	op->ors_filter = filter;
	op->ors_scope = LDAP_SCOPE_SUBTREE;

	/* get syncrepl cookie of shadow replica from subentry */
	ber_str2bv( si->base, strlen(si->base), 1, &base_bv ); 
	dnPrettyNormal( 0, &base_bv, &op->o_req_dn, &op->o_req_ndn, op->o_tmpmemctx );
	ch_free( base_bv.bv_val );

	/* set callback function */
	op->o_callback = &cb;
	cb.sc_response = dn_callback;
	cb.sc_private = si;

	si->syncUUID_ndn = NULL;

	rc = be->be_search( op, &rs );

	if ( op->o_req_dn.bv_val )
		ch_free( op->o_req_dn.bv_val );
	if ( op->o_req_ndn.bv_val )
		ch_free( op->o_req_ndn.bv_val );
	if ( op->ors_filter )
		filter_free( op->ors_filter );
	if ( op->ors_filterstr.bv_val )
		ch_free( op->ors_filterstr.bv_val );

	cb.sc_response = null_callback;
	cb.sc_private = si;

	if ( rc == LDAP_SUCCESS && si->syncUUID_ndn && si->sync_mode != LDAP_SYNC_LOG_MODE ) {
		op->o_req_dn = *si->syncUUID_ndn;
		op->o_req_ndn = *si->syncUUID_ndn;
		op->o_tag = LDAP_REQ_DELETE;
		rc = be->be_delete( op, &rs );
	}

	if ( si->syncUUID_ndn ) {
		ber_bvfree( si->syncUUID_ndn );
	}

	switch ( syncstate ) {
	case LDAP_SYNC_ADD :
	case LDAP_SYNC_MODIFY :

		if ( rc == LDAP_SUCCESS ||
			 rc == LDAP_REFERRAL ||
			 rc == LDAP_NO_SUCH_OBJECT ) {

			attr_delete( &e->e_attrs, slap_schema.si_ad_entryUUID );
			attr_merge_normalize_one( e, slap_schema.si_ad_entryUUID, syncUUID, op->o_tmpmemctx );

			op->o_tag = LDAP_REQ_ADD;
			op->ora_e = e;
			op->o_req_dn = e->e_name;
			op->o_req_ndn = e->e_nname;
			rc = be->be_add( op, &rs );

			if ( rc != LDAP_SUCCESS ) {
				if ( rc == LDAP_ALREADY_EXISTS ) {	
					op->o_tag = LDAP_REQ_MODIFY;
					op->orm_modlist = modlist;
					op->o_req_dn = e->e_name;
					op->o_req_ndn = e->e_nname;
					rc = be->be_modify( op, &rs );
					si->e = NULL;
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
					return 1;
				} else if ( rc == LDAP_REFERRAL ||
							rc == LDAP_NO_SUCH_OBJECT ) {
					syncrepl_add_glue( si, ld, op, e,
						modlist, syncstate,
						syncUUID, syncCookie);
					si->e = NULL;
					return 0;
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
					si->e = NULL;
					return 1;
				}
			} else {
				si->e = NULL;
				be_entry_release_w( op, e );
				return 0;
			}
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"syncrepl_entry : be_search failed (%d)\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"syncrepl_entry : be_search failed (%d)\n", rc, 0, 0 );
#endif
			si->e = NULL;
			return 1;
		}

	case LDAP_SYNC_DELETE :
		if ( si->sync_mode == LDAP_SYNC_LOG_MODE ) {
			op->o_req_dn = *si->syncUUID_ndn;
			op->o_req_ndn = *si->syncUUID_ndn;
			op->o_tag = LDAP_REQ_DELETE;
			rc = be->be_delete( op, &rs );
		}
		/* Already deleted otherwise */
		return 1;

	default :
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_entry : unknown syncstate\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"syncrepl_entry : unknown syncstate\n", 0, 0, 0 );
#endif
		return 1;
	}
}

static void
syncrepl_del_nonpresent(
	LDAP *ld,
	Operation *op
)
{
	Backend* be = op->o_bd;
	syncinfo_t *si = op->o_si;
	slap_callback	cb;
	struct berval	base_bv = {0, NULL};
	Filter *filter;
	SlapReply	rs = {REP_RESULT};
	struct berval	filterstr_bv = {0, NULL};
	struct nonpresent_entry *np_list, *np_prev;

	ber_str2bv( si->base, strlen(si->base), 1, &base_bv ); 
	dnPrettyNormal(0, &base_bv, &op->o_req_dn, &op->o_req_ndn, op->o_tmpmemctx );
	ch_free( base_bv.bv_val );

	filter = str2filter( si->filterstr );

	cb.sc_response = nonpresent_callback;
	cb.sc_private = si;

	op->o_callback = &cb;
	op->o_tag = LDAP_REQ_SEARCH;
	op->ors_scope = si->scope;
	op->ors_deref = LDAP_DEREF_NEVER;
	op->ors_slimit = 0;
	op->ors_tlimit = 0;
	op->ors_attrsonly = 0;
	op->ors_attrs = NULL;
	op->ors_filter = filter;
	ber_str2bv( si->filterstr, strlen( si->filterstr ), 1, &op->ors_filterstr );

	op->o_nocaching = 1;
	be->be_search( op, &rs );
	op->o_nocaching = 0;

	if ( op->o_req_dn.bv_val )
		ch_free( op->o_req_dn.bv_val );
	if ( op->o_req_ndn.bv_val )
		ch_free( op->o_req_ndn.bv_val );
	if ( op->ors_filter )
		filter_free( op->ors_filter );
	if ( op->ors_filterstr.bv_val )
		ch_free( op->ors_filterstr.bv_val );

	if ( !LDAP_LIST_EMPTY( &si->nonpresentlist ) ) {
		np_list = LDAP_LIST_FIRST( &si->nonpresentlist );
		while ( np_list != NULL ) {
			LDAP_LIST_REMOVE( np_list, np_link );
			np_prev = np_list;
			np_list = LDAP_LIST_NEXT( np_list, np_link );
			op->o_tag = LDAP_REQ_DELETE;
			op->o_callback = &cb;
			cb.sc_response = null_callback;
			cb.sc_private = si;
			op->o_req_dn = *np_prev->dn;
			op->o_req_ndn = *np_prev->ndn;
			op->o_bd->be_delete( op, &rs );
			ber_bvfree( np_prev->dn );
			ber_bvfree( np_prev->ndn );
			op->o_req_dn.bv_val = NULL;
			op->o_req_ndn.bv_val = NULL;
			ch_free( np_prev );
		}
	}

	return;
}


void
syncrepl_add_glue(
	syncinfo_t *si,
	LDAP *ld,
	Operation* op,
	Entry *e,
	Modifications* modlist,
	int syncstate,
	struct berval* syncUUID,
	struct berval* syncCookie
)
{
	Backend *be = op->o_bd;
	struct berval	uuid_bv = {0, NULL};
	slap_callback cb;
	Attribute	*a;
	int	rc;
	char	uuidbuf[ LDAP_LUTIL_UUIDSTR_BUFSIZE ];
	int levels = 0;
	int i, j, k;
	struct berval dn = {0, NULL};
	struct berval pdn = {0, NULL};
	struct berval ndn = {0, NULL};
	struct berval rdn = {0, NULL};
	Entry	*glue;
	SlapReply	rs = {REP_RESULT};
	Connection *conn = op->o_conn;
	char* ptr;

	op->o_tag = LDAP_REQ_ADD;
	op->o_callback = &cb;
	cb.sc_response = null_callback;
	cb.sc_private = si;

	ber_dupbv( &dn, &e->e_nname );
	ber_dupbv( &pdn, &e->e_nname );

	ptr = dn.bv_val;
	while ( !be_issuffix ( be, &pdn )) {
		dnParent( &dn, &pdn );
		dn.bv_val = pdn.bv_val;
		dn.bv_len = pdn.bv_len;
		levels++;
	}
	ch_free( ptr );

	for ( i = 0; i <= levels; i++ ) {
		glue = (Entry*) ch_calloc( 1, sizeof(Entry) );
		ber_dupbv( &dn, &e->e_nname );
		j = levels - i;

		ptr = dn.bv_val;
		for ( k = 0; k < j; k++ ) {
			dnParent( &dn, &pdn );
			dn.bv_val = pdn.bv_val;
			dn.bv_len = pdn.bv_len;
		}

		dnPrettyNormal( 0, &dn, &pdn, &ndn, op->o_tmpmemctx );
		ber_dupbv( &glue->e_name, &pdn );
		ber_dupbv( &glue->e_nname, &ndn );
		ch_free( ptr );
		ch_free( pdn.bv_val );
		ch_free( ndn.bv_val );

		a = ch_calloc( 1, sizeof( Attribute ));
		a->a_desc = slap_schema.si_ad_objectClass;

		a->a_vals = ch_calloc( 3, sizeof( struct berval ));
		ber_str2bv( "top", strlen("top"), 1, &a->a_vals[0] );
		ber_str2bv( "glue", strlen("glue"), 1, &a->a_vals[1] );
		a->a_vals[2].bv_len = 0;
		a->a_vals[2].bv_val = NULL;

		a->a_nvals = ch_calloc( 3, sizeof( struct berval ));
		ber_str2bv( "top", strlen("top"), 1, &a->a_nvals[0] );
		ber_str2bv( "glue", strlen("glue"), 1, &a->a_nvals[1] );
		a->a_nvals[2].bv_len = 0;
		a->a_nvals[2].bv_val = NULL;

		a->a_next = glue->e_attrs;
		glue->e_attrs = a;

		a = ch_calloc( 1, sizeof( Attribute ));
		a->a_desc = slap_schema.si_ad_structuralObjectClass;

		a->a_vals = ch_calloc( 2, sizeof( struct berval ));
		ber_str2bv( "glue", strlen("glue"), 1, &a->a_vals[0] );
		a->a_vals[1].bv_len = 0;
		a->a_vals[1].bv_val = NULL;

		a->a_nvals = ch_calloc( 2, sizeof( struct berval ));
		ber_str2bv( "glue", strlen("glue"), 1, &a->a_nvals[0] );
		a->a_nvals[1].bv_len = 0;
		a->a_nvals[1].bv_val = NULL;

		a->a_next = glue->e_attrs;
		glue->e_attrs = a;

		if ( !strcmp( e->e_nname.bv_val, glue->e_nname.bv_val )) {
			op->o_req_dn = e->e_name;
			op->o_req_ndn = e->e_nname;
			op->ora_e = e;
			rc = be->be_add ( op, &rs );
			if ( rc == LDAP_SUCCESS )
				be_entry_release_w( op, e );
			else 
				entry_free( e );
			entry_free( glue );
		} else {
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
		}
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
	BER_BVC("subentry"),
	BER_BVNULL
};

void
syncrepl_updateCookie(
	syncinfo_t *si,
	LDAP *ld,
	Operation *op,
	struct berval *pdn,
	struct berval *syncCookie
)
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

	struct berval slap_syncrepl_dn_bv = BER_BVNULL;
	struct berval slap_syncrepl_cn_bv = BER_BVNULL;
	
	slap_callback cb;
	SlapReply	rs = {REP_RESULT};

	/* update in memory cookie */
	if ( si->syncCookie != NULL ) {
		ber_bvfree( si->syncCookie );
	}
	si->syncCookie = ber_dupbv( NULL, syncCookie );
	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_desc = slap_schema.si_ad_objectClass;
	mod->sml_type = mod->sml_desc->ad_cname;
	mod->sml_bvalues = ocbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	ber_dupbv( &cnbva[0], (struct berval *) &slap_syncrepl_bvc );
	cnbva[0].bv_len = snprintf( cnbva[0].bv_val,
								slap_syncrepl_bvc.bv_len,
								"syncrepl%d", si->id );
	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_desc = slap_schema.si_ad_cn;
	mod->sml_type = mod->sml_desc->ad_cname;
	mod->sml_bvalues = cnbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	ber_dupbv( &scbva[0], si->syncCookie );
	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_desc = slap_schema.si_ad_syncreplCookie;
	mod->sml_type = mod->sml_desc->ad_cname;
	mod->sml_bvalues = scbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_desc = slap_schema.si_ad_subtreeSpecification;
	mod->sml_type = mod->sml_desc->ad_cname;
	mod->sml_bvalues = ssbva;
	*modtail = mod;
	modtail = &mod->sml_next;

#if 0
	rc = slap_mods_check( modlist, 1, &text, txtbuf, textlen, NULL );

	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
				"syncrepl_updateCookie: mods check (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_updateCookie: mods check (%s)\n",
			 text, 0, 0 );
#endif
	}
#endif

	op->o_tag = LDAP_REQ_ADD;
	rc = slap_mods_opattrs( op, modlist, modtail,
							 &text,txtbuf, textlen );

	for ( ml = modlist; ml != NULL; ml = mlnext ) {
		mlnext = ml->sml_next;
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

	ber_dupbv( &slap_syncrepl_cn_bv, (struct berval *) &slap_syncrepl_cn_bvc );
	slap_syncrepl_cn_bv.bv_len = snprintf( slap_syncrepl_cn_bv.bv_val,
										slap_syncrepl_cn_bvc.bv_len,
										"cn=syncrepl%d", si->id );

	build_new_dn( &slap_syncrepl_dn_bv, pdn, &slap_syncrepl_cn_bv, NULL );
	dnPrettyNormal( NULL, &slap_syncrepl_dn_bv, &e->e_name, &e->e_nname, NULL );

	if ( slap_syncrepl_cn_bv.bv_val )
		ch_free( slap_syncrepl_cn_bv.bv_val );
	if ( slap_syncrepl_dn_bv.bv_val )
		ch_free( slap_syncrepl_dn_bv.bv_val );

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

	if ( cnbva[0].bv_val )
		ch_free( cnbva[0].bv_val );

	for ( ; ml != NULL; ml = mlnext ) {
		mlnext = ml->sml_next;
		free( ml );
	}

	return;
}

void
avl_ber_bvfree( void *bv )
{
	if( bv == NULL ) {
		return;
	}
	if ( ((struct berval *)bv)->bv_val != NULL ) {
		ch_free ( ((struct berval *)bv)->bv_val );
	}
	ch_free ( (char *) bv );
}

static int
cookie_callback(
	Operation* op,
	SlapReply* rs
)
{
	syncinfo_t *si = op->o_callback->sc_private;
	Attribute *a;

	if ( rs->sr_type != REP_SEARCH ) return LDAP_SUCCESS;

	a = attr_find( rs->sr_entry->e_attrs, slap_schema.si_ad_syncreplCookie );

	if ( a == NULL ) {
		si->syncCookie = NULL;
	} else {
		si->syncCookie = ber_dupbv( NULL, &a->a_vals[0] );
	}
	return LDAP_SUCCESS;
}

static int
dn_callback(
	Operation*	op,
	SlapReply*	rs
)
{
	syncinfo_t *si = op->o_callback->sc_private;

	if ( rs->sr_type == REP_SEARCH ) {
		if ( si->syncUUID_ndn != NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"dn_callback : multiple entries match dn\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"dn_callback : multiple entries match dn\n", 0, 0, 0 );
#endif
		} else {
			if ( rs->sr_entry == NULL ) {
				si->syncUUID_ndn = NULL;
			} else {
				si->syncUUID_ndn = ber_dupbv( NULL, &rs->sr_entry->e_nname );
			}
		}
	}

	return LDAP_SUCCESS;
}

static int
nonpresent_callback(
	Operation*	op,
	SlapReply*	rs
)
{
	syncinfo_t *si = op->o_callback->sc_private;
	Attribute *a;
	int count = 0;
	struct berval* present_uuid = NULL;
	slap_callback cb;
	SlapReply	rs_cb = {REP_RESULT};
	struct nonpresent_entry *np_entry;

	if ( rs->sr_type == REP_RESULT ) {
		count = avl_free( si->presentlist, avl_ber_bvfree );
		si->presentlist = NULL;
		return LDAP_SUCCESS;
	} else if ( rs->sr_type == REP_SEARCH ) {
		a = attr_find( rs->sr_entry->e_attrs, slap_schema.si_ad_entryUUID );

		if ( a == NULL )
			return 0;

		present_uuid = avl_find( si->presentlist, &a->a_vals[0], syncuuid_cmp );

		if ( present_uuid == NULL ) {
			np_entry = (struct nonpresent_entry *)
						ch_calloc( 1, sizeof( struct nonpresent_entry ));
			np_entry->dn = ber_dupbv( NULL, &rs->sr_entry->e_name );
			np_entry->ndn = ber_dupbv( NULL, &rs->sr_entry->e_nname );
			LDAP_LIST_INSERT_HEAD( &si->nonpresentlist, np_entry, np_link );
		} else {
			avl_delete( &si->presentlist,
					&a->a_vals[0], syncuuid_cmp );
			ch_free( present_uuid->bv_val );
			ch_free( present_uuid );
		}
		return LDAP_SUCCESS;
	} else {
		return LDAP_SUCCESS;
	}

}

static int
null_callback(
	Operation*	op,
	SlapReply*	rs
)
{
	syncinfo_t *si = op->o_callback->sc_private;

	if ( rs->sr_err != LDAP_SUCCESS &&
		 rs->sr_err != LDAP_REFERRAL &&
		 rs->sr_err != LDAP_ALREADY_EXISTS &&
		 rs->sr_err != LDAP_NO_SUCH_OBJECT ) {
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
	struct berval *cn
)
{
	Entry* e;
	int rc;

	struct berval bv;

	e = ( Entry * ) ch_calloc( 1, sizeof( Entry ));

	attr_merge( e, slap_schema.si_ad_objectClass, ocbva, NULL );

	attr_merge_one( e, slap_schema.si_ad_structuralObjectClass, &ocbva[1], NULL );

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

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
/* Modified by Howard Chu
 *
 * Copyright (c) 2003 by Howard Chu, Symas Corporation
 *
 * Modifications provided under the terms of the OpenLDAP public license.
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

#ifdef LDAP_SLAPI
#include "slapi.h"
#endif

#define SYNCREPL_STR	"syncreplxxx"
#define CN_STR	"cn="

static const struct berval slap_syncrepl_bvc = BER_BVC(SYNCREPL_STR);
static const struct berval slap_syncrepl_cn_bvc = BER_BVC(CN_STR SYNCREPL_STR);

static void
syncrepl_del_nonpresent( LDAP *, Operation *, syncinfo_t * );

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

	for ( n = 0; si->attrs[ n ] != NULL; n++ ) ;

	if ( n ) {
		/* Delete Attributes */
		for ( i = 0; sync_descs[i] != NULL; i++ ) {
			for ( j = 0; si->attrs[j] != NULL; j++ ) {
				if ( !strcmp( si->attrs[j], sync_descs[i]->ad_cname.bv_val )) {
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
	
	si->attrs = tmp;

	/* Add Attributes */

	for ( i = 0; sync_descs[ i ] != NULL; i++ ) {
		si->attrs[ n++ ] = ch_strdup ( sync_descs[i]->ad_cname.bv_val );
		si->attrs[ n ] = NULL;
	}
}

static int
ldap_sync_search(
	syncinfo_t *si,
	LDAP *ld,
	void *ctx,
	int *msgidp )
{
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	LDAPControl c[2], *ctrls[3];
	struct timeval timeout;
	int rc;

	/* setup LDAP SYNC control */
	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &ctx );

	if ( si->syncCookie ) {
		ber_printf( ber, "{eO}", abs(si->type), si->syncCookie );
	} else {
		ber_printf( ber, "{e}", abs(si->type) );
	}

	if ( (rc = ber_flatten2( ber, &c[0].ldctl_value, 0 )) == LBER_ERROR ) {
		ber_free_buf( ber );
		return rc;
	}

	c[0].ldctl_oid = LDAP_CONTROL_SYNC;
	c[0].ldctl_iscritical = si->type < 0;
	ctrls[0] = &c[0];

	if ( si->authzId ) {
		c[1].ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
		ber_str2bv( si->authzId, 0, 0, &c[1].ldctl_value );
		c[1].ldctl_iscritical = 1;
		ctrls[1] = &c[1];
		ctrls[2] = NULL;
	} else {
		ctrls[1] = NULL;
	}

	timeout.tv_sec = si->tlimit > 0 ? si->tlimit : 1;
	timeout.tv_usec = 0;

	rc = ldap_search_ext( ld, si->base.bv_val, si->scope, si->filterstr.bv_val,
						  si->attrs, si->attrsonly, ctrls, NULL,
						  si->tlimit < 0 ? NULL : &timeout,
						  si->slimit, msgidp );
	ber_free_buf( ber );

	return rc;
}

static const Listener dummy_list = { {0, ""}, {0, ""} };

void *
do_syncrepl(
	void	*ctx,
	void	*arg )
{
	struct re_s* rtask = arg;
	syncinfo_t *si = ( syncinfo_t * ) rtask->arg;
	Backend *be;

	LDAPControl	**rctrls = NULL;
	LDAPControl	*rctrlp = NULL;

	BerElement	*res_ber = NULL;

	LDAP	*ld = NULL;
	LDAPMessage	*res = NULL;
	LDAPMessage	*msg = NULL;

	ber_int_t	msgid;

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

	Connection conn = {0};
	Operation op = {0};
	slap_callback	cb;

	void *memctx = NULL;
	ber_len_t memsiz;
	
	int rc_efree;

	struct berval psub = { 0, NULL };
	Modifications	*modlist = NULL;

	char syncrepl_cbuf[sizeof(CN_STR SYNCREPL_STR)];
	struct berval syncrepl_cn_bv = {sizeof(syncrepl_cbuf)-1, syncrepl_cbuf};

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
		LDAP_LOG( OPERATION, ERR,
			"do_syncrepl: ldap_initialize failed (%s)\n",
			si->provideruri, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_syncrepl: ldap_initialize failed (%s)\n",
			si->provideruri, 0, 0 );
#endif
		return NULL;
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

		lutil_sasl_freedefs( defaults );

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

	be = si->be;

	si->conn = &conn;
	conn.c_connid = -1;
	conn.c_send_ldap_result = slap_send_ldap_result;
	conn.c_send_search_entry = slap_send_search_entry;
	conn.c_send_search_reference = slap_send_search_reference;
	conn.c_listener = (Listener *)&dummy_list;
	conn.c_peer_name = slap_empty_bv;

	/* set memory context */
#define SLAB_SIZE 1048576
	memsiz = SLAB_SIZE;
	memctx = sl_mem_create( memsiz, ctx );
	op.o_tmpmemctx = memctx;
	op.o_tmpmfuncs = &sl_mfuncs;

	op.o_dn = si->updatedn;
	op.o_ndn = si->updatedn;
	op.o_callback = &cb;
	op.o_time = slap_get_time();
	op.o_threadctx = si->ctx;
	op.o_managedsait = 1;
	op.o_bd = be;
	op.o_conn = &conn;
	op.o_connid = op.o_conn->c_connid;
#if defined( LDAP_SLAPI )
	op.o_pb = slapi_pblock_new();
	slapi_x_create_object_extensions( SLAPI_X_EXT_OPERATION, &op );
#endif /* defined( LDAP_SLAPI ) */

	/* get syncrepl cookie of shadow replica from subentry */

	snprintf(syncrepl_cbuf, sizeof(syncrepl_cbuf), CN_STR "syncrepl%d",
		si->id );
	build_new_dn( &op.o_req_ndn, &si->base, &syncrepl_cn_bv, op.o_tmpmemctx );
	op.o_req_dn = op.o_req_ndn;

	si->syncCookie = NULL;
	backend_attribute( &op, NULL, &op.o_req_ndn,
		slap_schema.si_ad_syncreplCookie, &si->syncCookie );

	ber_dupbv( &syncCookie_req, si->syncCookie );

	psub = be->be_nsuffix[0];

	rc = ldap_sync_search( si, ld, memctx, &msgid );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "do_syncrepl: "
				"ldap_search_ext: %s (%d)\n", ldap_err2string( rc ), rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_syncrepl: "
				"ldap_search_ext: %s (%d)\n", ldap_err2string( rc ), rc, 0 );
#endif
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
					BerElementBuffer berbuf;
					BerElement	*ctrl_ber;
					rctrlp = *rctrls;
					ctrl_ber = (BerElement *)&berbuf;
					ber_init2( ctrl_ber, &rctrlp->ldctl_value, LBER_USE_DER );

					ber_scanf( ctrl_ber, "{" /*"}"*/);
					if ( ber_peek_tag( ctrl_ber, &len )
						== LDAP_SYNC_TAG_COOKIE ) {
						ber_scanf( ctrl_ber, "o", &syncCookie );
					}
					ldap_controls_free( rctrls );
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
							syncrepl_del_nonpresent( ld, &op, si );
					}
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
							syncrepl_del_nonpresent( ld, &op, si );
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
			if ( syncCookie.bv_val ) {
				ch_free( syncCookie.bv_val );
				syncCookie.bv_val = NULL;
			}
			if ( syncUUID.bv_val ) {
				ch_free( syncUUID.bv_val );
				syncUUID.bv_val = NULL;
			}
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
#if defined( LDAP_SLAPI )
	if ( op.o_pb ) slapi_pblock_destroy( op.o_pb );
	slapi_x_free_object_extensions( SLAPI_X_EXT_OPERATION, &op );
#endif /* defined( LDAP_SLAPI ) */

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
	Entry		*e = NULL;
	BerElement	*ber = NULL;
	Modifications	tmp;
	Modifications	*mod;
	Modifications	**modtail = modlist;

	const char	*text;
	char txtbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof txtbuf;

	struct berval	bdn = {0, NULL};
	int		rc;

	ber_len_t	len;
	LDAPControl*	rctrlp;
	LDAPControl**	rctrls = NULL;

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

	rc = ldap_get_entry_controls( ld, msg, &rctrls );
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"syncrepl_message_to_entry : control get failed (%d)", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"syncrepl_message_to_entry : control get failed (%d)", rc, 0, 0 );
#endif
		goto done;
	}

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

	e = ( Entry * ) sl_calloc( 1, sizeof( Entry ), op->o_tmpmemctx);
	dnPrettyNormal( NULL, &bdn, &e->e_name, &e->e_nname, op->o_tmpmemctx );

	while ( ber_remaining( ber ) ) {
		if ( (ber_scanf( ber, "{mW}", &tmp.sml_type, &tmp.sml_values ) ==
			LBER_ERROR ) || ( tmp.sml_type.bv_val == NULL )) break;

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

	if ( rctrls ) {
		BerElementBuffer berbuf;
		BerElement	*ctrl_ber;

		rctrlp = *rctrls;
		ctrl_ber = (BerElement *)&berbuf;
		ber_init2( ctrl_ber, &rctrlp->ldctl_value, LBER_USE_DER );
		ber_scanf( ctrl_ber, "{eo", syncstate, syncUUID );
		if ( ber_peek_tag( ctrl_ber, &len ) == LDAP_SYNC_TAG_COOKIE ) {
			ber_scanf( ctrl_ber, "o}", syncCookie );
		}
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
		rc = 1;
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
	struct berval	*syncuuid_bv = NULL;

	SlapReply	rs = {REP_RESULT};
	int rc = LDAP_SUCCESS;

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

	op->ors_filterstr.bv_len = strlen("entryUUID=") + syncUUID->bv_len;
	op->ors_filterstr.bv_val = (char *) sl_malloc( op->ors_filterstr.bv_len + 1,
									op->o_tmpmemctx ); 
	strcpy( op->ors_filterstr.bv_val, "entryUUID=" );
	strcat( op->ors_filterstr.bv_val, syncUUID->bv_val );

	si->e = e;
	si->syncUUID_ndn = NULL;

	op->ors_filter = str2filter_x( op, op->ors_filterstr.bv_val );
	op->ors_scope = LDAP_SCOPE_SUBTREE;

	/* get syncrepl cookie of shadow replica from subentry */
	op->o_req_dn = si->base;
	op->o_req_ndn = si->base;

	/* set callback function */
	op->o_callback = &cb;
	cb.sc_response = dn_callback;
	cb.sc_private = si;

	si->syncUUID_ndn = NULL;

	rc = be->be_search( op, &rs );

	if ( op->ors_filter )
		filter_free_x( op, op->ors_filter );
	if ( op->ors_filterstr.bv_val )
		sl_free( op->ors_filterstr.bv_val, op->o_tmpmemctx );

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
	Operation *op,
	syncinfo_t *si
)
{
	Backend* be = op->o_bd;
	slap_callback	cb;
	SlapReply	rs = {REP_RESULT};
	struct nonpresent_entry *np_list, *np_prev;

	op->o_req_dn = si->base;
	op->o_req_ndn = si->base;

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
	op->ors_filter = str2filter_x( op, si->filterstr.bv_val );
	op->ors_filterstr = si->filterstr;

	op->o_nocaching = 1;
	be->be_search( op, &rs );
	op->o_nocaching = 0;

	if ( op->ors_filter )
		filter_free_x( op, op->ors_filter );

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


static struct berval gcbva[] = {
	BER_BVC("top"),
	BER_BVC("glue")
};

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
	slap_callback cb;
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
	cb.sc_private = si;

	dn = e->e_name;
	ndn = e->e_nname;

	/* count RDNs in suffix */
	if ( be->be_nsuffix[0].bv_len ) {
		for (i=0, ptr=be->be_nsuffix[0].bv_val; ptr; ptr=strchr( ptr, ',' )) {
			ptr++;
			i++;
		}
		suffrdns = i+1;
	} else {
		/* suffix is "" */
		suffrdns = 0;
	}

	/* advance to first child: count RDN separators since the prettyDNs
	 * may not be exactly the same length
	 */
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
		comma = ndn.bv_val + ndn.bv_len - be->be_nsuffix[0].bv_len - 1;
		*comma = '\0';
		ptr = strrchr( ndn.bv_val, ',' ) + 1;
		*comma = ',';
		ndn.bv_len -= ptr - ndn.bv_val;
		ndn.bv_val = ptr;
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
		a->a_vals[2].bv_len = 0;
		a->a_vals[2].bv_val = NULL;

		a->a_nvals = a->a_vals;

		a->a_next = glue->e_attrs;
		glue->e_attrs = a;

		a = ch_calloc( 1, sizeof( Attribute ));
		a->a_desc = slap_schema.si_ad_structuralObjectClass;

		a->a_vals = ch_calloc( 2, sizeof( struct berval ));
		ber_dupbv( &a->a_vals[0], &gcbva[1] );
		a->a_vals[1].bv_len = 0;
		a->a_vals[1].bv_val = NULL;

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
		for (ptr = dn.bv_val-2; ptr > e->e_name.bv_val && *ptr != ','; ptr--);
		if ( ptr == e->e_name.bv_val ) break;
		dn.bv_val = ptr+1;
		dn.bv_len = e->e_name.bv_len - (ptr-e->e_name.bv_val);
		for (ptr = ndn.bv_val-2; ptr > e->e_nname.bv_val && *ptr != ','; ptr--);
		ndn.bv_val = ptr+1;
		ndn.bv_len = e->e_nname.bv_len - (ptr-e->e_nname.bv_val);
	}

	op->o_req_dn = e->e_name;
	op->o_req_ndn = e->e_nname;
	op->ora_e = e;
	rc = be->be_add ( op, &rs );
	if ( rc == LDAP_SUCCESS )
		be_entry_release_w( op, e );
	else 
		entry_free( e );

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

	char syncrepl_cbuf[sizeof(CN_STR SYNCREPL_STR)];
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

	if ( scbva[0].bv_val ) ch_free( scbva[0].bv_val );
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

	mlnext = mod;

	op->o_tag = LDAP_REQ_ADD;
	rc = slap_mods_opattrs( op, modlist, modtail,
							 &text,txtbuf, textlen );

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
	slap_syncrepl_cn_bv.bv_len = snprintf( slap_syncrepl_cn_bv.bv_val,
										slap_syncrepl_cn_bvc.bv_len,
										"cn=syncrepl%d", si->id );

	build_new_dn( &slap_syncrepl_dn_bv, pdn, &slap_syncrepl_cn_bv, op->o_tmpmemctx );
	ber_dupbv( &e->e_name, &slap_syncrepl_dn_bv );
	ber_dupbv( &e->e_nname, &slap_syncrepl_dn_bv );

	if ( slap_syncrepl_dn_bv.bv_val )
		sl_free( slap_syncrepl_dn_bv.bv_val, op->o_tmpmemctx );

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

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

#ifdef LDAP_SYNCREPL

#include "ldap_rq.h"

static Entry*
syncrepl_message_to_entry ( LDAP *, Operation *, LDAPMessage *,
		Modifications **, int*, struct berval *, struct berval * );

static int
syncrepl_entry( LDAP *, Operation*, Entry*, Modifications*,
		int, struct berval*, struct berval*, int );

static int
syncrepl_del_nonpresent( LDAP *, Operation * );

static void
syncrepl_add_glue( LDAP *, Operation*, Entry*, Modifications*, int,
		   struct berval*, struct berval* );

static void
syncrepl_updateCookie( LDAP *, Operation *, struct berval *, struct berval * );

static int
slap_mods_check_syncrepl( Operation *, Modifications **,
			  const char **, char *, size_t, void *ctx );

static int
slap_mods_opattrs_syncrepl( Operation *, Modifications *, Modifications **,
				const char **, char *, size_t );

static int
slap_mods2entry_syncrepl( Modifications *, Entry **, int,
			  const char **, char *, size_t );

/* callback functions */
static int cookie_callback( struct slap_op *, struct slap_rep * );
static int dn_callback( struct slap_op *, struct slap_rep * );
static int nonpresent_callback( struct slap_op *, struct slap_rep * );
static int null_callback( struct slap_op *, struct slap_rep * );

static AttributeDescription **add_descs;
static AttributeDescription **add_descs_lastmod;
static AttributeDescription **del_descs;
static AttributeDescription **del_descs_lastmod;

struct runqueue_s syncrepl_rq;

void
init_syncrepl()
{
	add_descs = ch_malloc( 2 * sizeof( AttributeDescription * ));
	add_descs[0] = slap_schema.si_ad_objectClass;
	add_descs[1] = NULL;

	add_descs_lastmod = ch_malloc( 7 * sizeof( AttributeDescription * ));
	add_descs_lastmod[0] = slap_schema.si_ad_objectClass;
	add_descs_lastmod[1] = slap_schema.si_ad_creatorsName;
	add_descs_lastmod[2] = slap_schema.si_ad_modifiersName;
	add_descs_lastmod[3] = slap_schema.si_ad_createTimestamp;
	add_descs_lastmod[4] = slap_schema.si_ad_modifyTimestamp;
	add_descs_lastmod[5] = slap_schema.si_ad_entryCSN;
	add_descs_lastmod[6] = NULL;

	del_descs = ch_malloc( 9 * sizeof( AttributeDescription * ));
	del_descs[0] = slap_schema.si_ad_structuralObjectClass;
	del_descs[1] = slap_schema.si_ad_subschemaSubentry;
	del_descs[2] = slap_schema.si_ad_hasSubordinates;
	del_descs[3] = slap_schema.si_ad_creatorsName;
	del_descs[4] = slap_schema.si_ad_modifiersName;
	del_descs[5] = slap_schema.si_ad_createTimestamp;
	del_descs[6] = slap_schema.si_ad_modifyTimestamp;
	del_descs[7] = slap_schema.si_ad_entryCSN;
	del_descs[8] = NULL;

	del_descs_lastmod = ch_malloc( 4 * sizeof( AttributeDescription * ));
	del_descs_lastmod[0] = slap_schema.si_ad_structuralObjectClass;
	del_descs_lastmod[1] = slap_schema.si_ad_subschemaSubentry;
	del_descs_lastmod[2] = slap_schema.si_ad_hasSubordinates;
	del_descs_lastmod[3] = NULL;
}

void *
do_syncrepl(
	void	*ctx,
	void	*arg )
{
	struct re_s* rtask = arg;
	Backend *be = rtask->arg;
	syncinfo_t *si = ( syncinfo_t * ) be->syncinfo;

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

	int	rc;
	int	err;
	ber_len_t	len;
	int	syncinfo_arrived = 0;
	int	cancel_response = 0;

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
	struct berval sub_bv = { 0, NULL };
	struct berval psubrdn = { 0, NULL };
	struct berval nsubrdn = { 0, NULL };
	struct berval psub = { 0, NULL };
	struct berval nsub = { 0, NULL };
	char substr[64];
	Modifications	*modlist = NULL;
	Modifications	*ml, *mlnext;
	char *def_filter_str = NULL;

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

	/* Init connection to master */

	if ( ldap_is_ldap_url( si->masteruri )) {
		rc = ldap_initialize( &ld, si->masteruri );
		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, "do_syncrepl: "
				"ldap_initialize failed (%s)\n",
				si->masteruri, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_syncrepl: "
				"ldap_initialize failed (%s)\n",
				si->masteruri, 0, 0 );
#endif
		}
	} else {
		ld = ldap_init( si->mastername, si->masterport );
		if ( ld == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, "do_syncrepl: "
				"ldap_init failed (%s:%d)\n",
				si->mastername, si->masterport, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_syncrepl: "
				"ldap_init failed (%s:%d)\n",
				si->mastername, si->masterport, 0 );
#endif
		}
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
					si->mastername, si->secprops, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "Error: ldap_set_option "
					"(%s,SECPROPS,\"%s\") failed!\n",
					si->mastername, si->secprops, NULL );
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
				LDAP_SASL_AUTOMATIC,
				lutil_sasl_interact,
				defaults );

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

	si->ctx = ctx;

	op.o_tmpmemctx = NULL; /* FIXME : to use per-thread mem context */
	op.o_tmpmfuncs = &ch_mfuncs;
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
	op.ors_slimit = -1;
	op.ors_tlimit = -1;
	op.ors_attrsonly = 0;
	op.ors_attrs = NULL;
	op.ors_filter = str2filter( def_filter_str = "(objectClass=*)" );
	ber_str2bv( def_filter_str, strlen( def_filter_str ), 1,
				&op.ors_filterstr );

	si->conn = &conn;
	conn.c_send_ldap_result = slap_send_ldap_result;
	conn.c_send_search_entry = slap_send_search_entry;
	conn.c_send_search_reference = slap_send_search_reference;

	/* get syncrepl cookie of shadow replica from subentry */
	ber_str2bv( si->base, strlen(si->base), 1, &base_bv ); 
	dnPrettyNormal( 0, &base_bv, &pbase, &nbase, op.o_tmpmemctx );

	sprintf( substr, "cn=syncrepl%d", si->id );
	ber_str2bv( substr, strlen(substr), 1, &sub_bv );
	dnPrettyNormal( 0, &sub_bv, &psubrdn, &nsubrdn, op.o_tmpmemctx );

	build_new_dn( &op.o_req_dn, &pbase, &psubrdn );
	build_new_dn( &op.o_req_ndn, &nbase, &nsubrdn );

	ch_free( base_bv.bv_val );
	ch_free( pbase.bv_val );
	ch_free( nbase.bv_val );
	ch_free( sub_bv.bv_val );
	ch_free( psubrdn.bv_val );
	ch_free( nsubrdn.bv_val );

	/* set callback function */
	cb.sc_response = cookie_callback;
	cb.sc_private = si;

	/* search subentry to retrieve cookie */
	si->syncCookie = NULL;
	be->be_search( &op, &rs );

	ch_free( op.o_req_dn.bv_val );
	ch_free( op.o_req_ndn.bv_val );
	filter_free( op.ors_filter );
	ch_free( op.ors_filterstr.bv_val );

	psub = be->be_nsuffix[0];

	/* setup LDAP SYNC control */
	sync_ber = ber_alloc_t( LBER_USE_DER );
	ber_set_option( sync_ber, LBER_OPT_BER_MEMCTX, op.o_tmpmemctx );

	if ( si->syncCookie ) {
		ber_printf( sync_ber, "{eO}", abs(si->type), si->syncCookie );
	} else {
		ber_printf( sync_ber, "{e}", abs(si->type) );
	}

	if ( ber_flatten( sync_ber, &sync_bvalp ) == LBER_ERROR ) {
		ber_free( sync_ber, 1 );
		return NULL;
	}
	ber_free( sync_ber, 1 );

	sctrls = (LDAPControl**) sl_calloc( 3, sizeof(LDAPControl*), op.o_tmpmemctx );

	c[0].ldctl_oid = LDAP_CONTROL_SYNC;
	c[0].ldctl_value = (*sync_bvalp);
	c[0].ldctl_iscritical = si->type < 0;
	sctrls[0] = &c[0];

	if ( si->authzId ) {
		c[1].ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
		c[1].ldctl_value.bv_val = si->authzId;
		c[1].ldctl_value.bv_len = strlen( si->authzId );
		c[1].ldctl_iscritical = 1;
		sctrls[1] = &c[1];
	} else {
		sctrls[1] = NULL;
	}

	sctrls[2] = NULL;

	err = ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, sctrls );

	ber_bvfree( sync_bvalp );
	ch_free( sctrls );

        if ( err != LDAP_OPT_SUCCESS )
		fprintf( stderr, "Could not set controls : %d\n", err );

	/* Delete Attributes */
	if ( si->lastmod == LASTMOD_REQ ) {
		descs = del_descs_lastmod;
	} else {
		descs = del_descs;
	}

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

	/* Add Attributes */

	for ( n = 0; si->attrs[ n ] != NULL; n++ ) ;
	
	if ( si->lastmod == LASTMOD_REQ ) {
		descs = add_descs_lastmod;
	} else {
		descs = add_descs;
	}

	for ( i = 0; descs[i] != NULL; i++ ) {
		tmp = ( char ** ) ch_realloc( si->attrs,
				( n + 2 ) * sizeof( char * ));
		if ( tmp == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, "out of memory\n", 0,0,0 );
#else
			Debug( LDAP_DEBUG_ANY, "out of memory\n", 0,0,0 );
#endif
		}
		si->attrs = tmp;
		si->attrs[ n++ ] = ch_strdup ( descs[i]->ad_cname.bv_val );
		si->attrs[ n ] = NULL;
	}

	/* Send LDAP SYNC search */

	rc = ldap_search_ext( ld, si->base, si->scope, si->filterstr,
				si->attrs, si->attrsonly, NULL, NULL,
				NULL, -1, &msgid );

        if( rc != LDAP_SUCCESS ) {
                fprintf( stderr, "syncrepl: ldap_search_ext: %s (%d)\n",
		                        ldap_err2string( rc ), rc );
                return NULL;
	}

	while (( rc = ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ONE, NULL, &res )) > 0 ) {

		for ( msg = ldap_first_message( ld, res );
		      msg != NULL;
		      msg = ldap_next_message( ld, msg ) )
		{
			switch( ldap_msgtype( msg ) ) {
			case LDAP_RES_SEARCH_ENTRY:
				entry = syncrepl_message_to_entry( ld, &op, msg,
					&modlist, &syncstate, &syncUUID, &syncCookie );
				rc_efree = syncrepl_entry( ld, &op, entry, modlist,
						syncstate, &syncUUID, &syncCookie, !syncinfo_arrived );
				if ( syncCookie.bv_len ) {
					syncrepl_updateCookie( ld, &op, &psub, &syncCookie );
				}
				if ( rc_efree )
					entry_free( entry );
				for ( ml = modlist; ml != NULL; ml = mlnext ) {
					mlnext = ml->sml_next;
					ber_memfree( ml );
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
					ber_set_option( ctrl_ber, LBER_OPT_BER_MEMCTX, op.o_tmpmemctx );
					ber_write( ctrl_ber, rctrlp->ldctl_value.bv_val, rctrlp->ldctl_value.bv_len, 0 );
					ber_reset( ctrl_ber, 1 );

					ber_scanf( ctrl_ber, "{" );
					if ( ber_peek_tag( ctrl_ber, &len )
						== LDAP_SYNC_TAG_COOKIE ) {
						ber_scanf( ctrl_ber, "o", &syncCookie );
					}
				}
				if (si->type == LDAP_SYNC_REFRESH_AND_PERSIST) {
					if ( cancel_response ) {
						if ( syncCookie.bv_len ) {
							ber_bvfree( si->syncCookie );
							si->syncCookie = ber_dupbv( NULL, &syncCookie );
						}
						if ( ctrl_ber )
							ber_free( ctrl_ber, 1 );
						goto done;
					}
					else {
						if ( ctrl_ber )
							ber_free( ctrl_ber, 1 );
						break;
					}
				} else {
					if ( syncCookie.bv_len ) {
						syncrepl_updateCookie( ld, &op, &psub, &syncCookie );
					}
					syncrepl_del_nonpresent( ld, &op );
					if ( ctrl_ber )
						ber_free( ctrl_ber, 1 );
					goto done;
				}
				break;

			case LDAP_RES_INTERMEDIATE_RESP:
				ldap_parse_intermediate_resp_result( ld, msg,
						&retoid, &retdata, 0 );
				if ( !strcmp( retoid, LDAP_SYNC_INFO ) ) {
					sync_info_arrived = 1;
					res_ber = ber_init( retdata );
					ber_scanf( res_ber, "{e", &syncstate );

					if ( syncstate == LDAP_SYNC_REFRESH_DONE ) {
						syncrepl_del_nonpresent( ld, &op );
					} else if ( syncstate != LDAP_SYNC_NEW_COOKIE ) {
#ifdef NEW_LOGGING
						LDAP_LOG( OPERATION, ERR,
							"do_syncrepl : unknown sync info\n", 0, 0, 0 );
#else
						Debug( LDAP_DEBUG_ANY,
							"do_syncrepl : unknown sync info\n", 0, 0, 0 );
#endif
					}

					if ( ber_peek_tag( res_ber, &len )
								== LDAP_SYNC_TAG_COOKIE ) {
						ber_scanf( res_ber, "o}", &syncCookie );
						if ( syncCookie.bv_len ) {
							ber_bvfree( si->syncCookie );
							si->syncCookie = ber_dupbv( NULL, &syncCookie );
						}
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
						"unknown intermediate "
						"response\n", 0, 0, 0 );
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
		}
		ldap_msgfree( res );
	}

	if ( rc == -1 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_syncrepl : unknown result\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_syncrepl : unknown result\n", 0, 0, 0 );
#endif
	}

done:
	if ( syncCookie.bv_val )
		ch_free( syncCookie.bv_val );
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

static Entry*
syncrepl_message_to_entry(
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

	syncinfo_t *si = ( syncinfo_t * ) be->syncinfo;

	ber_len_t	len;
	LDAPControl*	rctrlp;
	LDAPControl**	rctrls = NULL;
	BerElement*	ctrl_ber;

	ber_tag_t	tag;

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
	dnPrettyNormal( NULL, &bdn, &e->e_name, &e->e_nname, op->o_tmpmemctx );

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
		mod->sml_nvalues = tmp.sml_bvalues;

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

	rc = ldap_int_get_controls( ber, &rctrls );

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
		ber_set_option( ctrl_ber, LBER_OPT_BER_MEMCTX, op->o_tmpmemctx );
		ber_write( ctrl_ber, rctrlp->ldctl_value.bv_val, rctrlp->ldctl_value.bv_len, 0 );
		ber_reset( ctrl_ber, 1 );
		ber_scanf( ctrl_ber, "{eo", syncstate, syncUUID );
		if ( ber_peek_tag( ctrl_ber, &len ) == LDAP_SYNC_TAG_COOKIE ) {
			ber_scanf( ctrl_ber, "o}", syncCookie );
		}
		ber_free( ctrl_ber, 1 );
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,"syncrepl_message_to_entry : "
			" rctrls absent\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_message_to_entry :"
			" rctrls absent\n", 0, 0, 0 );
#endif
	}

	if ( *syncstate == LDAP_SYNC_PRESENT ) {
		e = NULL;
		goto done;
	} else if ( *syncstate == LDAP_SYNC_DELETE ) {
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

	rc = slap_mods_check_syncrepl( op, modlist, &text, txtbuf, textlen, NULL );

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
	
	rc = slap_mods_opattrs_syncrepl( op, *modlist, modtail,
					 &text,txtbuf, textlen );
	
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
				"syncrepl_message_to_entry: mods opattrs (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_message_to_entry: mods opattrs (%s)\n",
				text, 0, 0 );
#endif
		return NULL;
	}

	rc = slap_mods2entry_syncrepl( *modlist, &e, 1, &text, txtbuf, textlen );
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

static int
syncrepl_entry(
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
	syncinfo_t *si = ( syncinfo_t * ) be->syncinfo;
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
		if ( e )
			return 1;
		else
			return 0;
	}

	filterstr = (char *) sl_malloc( strlen("entryUUID=") + syncUUID->bv_len + 1,
									op->o_tmpmemctx ); 
	strcpy( filterstr, "entryUUID=" );
	strcat( filterstr, syncUUID->bv_val );

	si->e = e;
	si->syncUUID = syncUUID;
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

	be->be_search( op, &rs );

	ch_free( op->o_req_dn.bv_val );
	ch_free( op->o_req_ndn.bv_val );
	filter_free( op->ors_filter );
	ch_free( op->ors_filterstr.bv_val );

	cb.sc_response = null_callback;

	rc = LDAP_SUCCESS;

	if ( si->syncUUID_ndn ) {
		op->o_req_dn = *si->syncUUID_ndn;
		op->o_req_ndn = *si->syncUUID_ndn;
		op->o_tag = LDAP_REQ_DELETE;
		rc = be->be_delete( op, &rs );
	}

	switch ( syncstate ) {
	case LDAP_SYNC_ADD :
	case LDAP_SYNC_MODIFY :

		if ( rc == LDAP_SUCCESS ||
			 rc == LDAP_REFERRAL ||
			 rc == LDAP_NO_SUCH_OBJECT ||
			 rc == DB_NOTFOUND ) {

			if ( !attr_find( e->e_attrs, slap_schema.si_ad_entryUUID )) {
				attr_merge_one( e, slap_schema.si_ad_entryUUID, syncUUID, syncUUID );
			}

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
				} else if ( rc == LDAP_REFERRAL ||
							rc == LDAP_NO_SUCH_OBJECT ||
							rc == DB_NOTFOUND ) {
					syncrepl_add_glue(ld, op, e,
						modlist, syncstate,
						syncUUID, syncCookie);
				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR,
						"be_modify failed (%d)\n",
						rc, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
						"be_modify failed (%d)\n",
						rc, 0, 0 );
#endif
				}
			} else {
				return 0;
			}
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"be_modify/be_delete failed (%d)\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"be_modify/be_delete failed (%d)\n", rc, 0, 0 );
#endif
		}

		si->e = NULL;
		return 1;

	case LDAP_SYNC_DELETE :
		/* Already deleted */
		return 1;

	default :
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"unknown syncstate\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"unknown syncstate\n", 0, 0, 0 );
#endif
		return 1;
	}
}

static int
syncrepl_del_nonpresent(
	LDAP *ld,
	Operation *op
)
{
	Backend* be = op->o_bd;
	syncinfo_t *si = ( syncinfo_t * ) be->syncinfo;
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
	op->ors_slimit = -1;
	op->ors_tlimit = -1;
	op->ors_attrsonly = 0;
	op->ors_attrs = NULL;
	op->ors_filter = filter;
	ber_str2bv( si->filterstr, strlen( si->filterstr ), 1, &op->ors_filterstr );

	be->be_search( op, &rs );

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

	if ( op->o_req_dn.bv_val )
		ch_free( op->o_req_dn.bv_val );
	if ( op->o_req_ndn.bv_val )
		ch_free( op->o_req_ndn.bv_val );
	filter_free( op->ors_filter );
	ch_free( op->ors_filterstr.bv_val );
}


static void
syncrepl_add_glue(
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
	syncinfo_t *si = op->o_callback->sc_private;
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

	op->o_tag = LDAP_REQ_ADD;
	op->o_callback = &cb;
	cb.sc_response = null_callback;
	cb.sc_private = si;

	ber_dupbv( &dn, &e->e_nname );
	ber_dupbv( &pdn, &e->e_nname );

	while ( !be_issuffix ( be, &pdn )) {
		dnParent( &dn, &pdn );
		ch_free( dn.bv_val );
		ber_dupbv( &dn, &pdn );
		levels++;
	}

	for ( i = 0; i <= levels; i++ ) {
		glue = (Entry*) ch_calloc( 1, sizeof(Entry) );
		ch_free( dn.bv_val );
		ch_free( pdn.bv_val );
		ber_dupbv( &dn, &e->e_nname );
		ber_dupbv( &pdn, &e->e_nname );
		j = levels - i;
		for ( k = 0; k < j; k++ ) {
			dnParent( &dn, &pdn );
			ch_free( dn.bv_val );
			ber_dupbv( &dn, &pdn );
		}

		dnPrettyNormal( 0, &dn, &pdn, &ndn, op->o_tmpmemctx );
		ber_dupbv( &glue->e_name, &pdn );
		ber_dupbv( &glue->e_nname, &ndn );
		ch_free( dn.bv_val );
		ch_free( pdn.bv_val );
		ch_free( ndn.bv_val );

		a = ch_calloc( 1, sizeof( Attribute ));
		a->a_desc = slap_schema.si_ad_objectClass;
		a->a_vals = ch_calloc( 3, sizeof( struct berval ));
		ber_str2bv( "top", strlen("top"), 1, &a->a_vals[0] );
		ber_str2bv( "glue", strlen("glue"), 1, &a->a_vals[1] );
		a->a_vals[2].bv_len = 0;
		a->a_vals[2].bv_val = NULL;
		a->a_next = glue->e_attrs;
		glue->e_attrs = a;

		a = ch_calloc( 1, sizeof( Attribute ));
		a->a_desc = slap_schema.si_ad_structuralObjectClass;
		a->a_vals = ch_calloc( 2, sizeof( struct berval ));
		ber_str2bv( "glue", strlen("glue"), 1, &a->a_vals[0] );
		a->a_vals[1].bv_len = 0;
		a->a_vals[1].bv_val = NULL;
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

static void
syncrepl_updateCookie(
	LDAP *ld,
	Operation *op,
	struct berval *pdn,
	struct berval *syncCookie
)
{
	Backend *be = op->o_bd;
	syncinfo_t *si = ( syncinfo_t * ) be->syncinfo;
	Modifications *ml;
	Modifications *mlnext;
	Modifications *mod;
	Modifications *modlist;
	Modifications **modtail = &modlist;

	struct berval* ocbva = NULL;
	struct berval* cnbva = NULL;
	struct berval* ssbva = NULL;
	struct berval* scbva = NULL;

	char substr[64];
	char rdnstr[67];
	const char	*text;
	char txtbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof txtbuf;

	Entry* e;
	int rc;

	struct berval sub_bv = { 0, NULL };
	struct berval psubrdn = { 0, NULL };
	
	slap_callback cb;
	SlapReply	rs = {REP_RESULT};

	ocbva = ( struct berval * ) ch_calloc( 4, sizeof( struct berval ));
	cnbva = ( struct berval * ) ch_calloc( 2, sizeof( struct berval ));
	ssbva = ( struct berval * ) ch_calloc( 2, sizeof( struct berval ));
	scbva = ( struct berval * ) ch_calloc( 2, sizeof( struct berval ));

	/* update in memory cookie */
	if ( si->syncCookie != NULL ) {
		ber_bvfree( si->syncCookie );
	}
	si->syncCookie = ber_dupbv( NULL, syncCookie );
	ber_str2bv( "top", strlen("top"), 1, &ocbva[0] );
	ber_str2bv( "subentry", strlen("subentry"), 1, &ocbva[1] );
	ber_str2bv( "syncConsumerSubentry",
			strlen("syncConsumerSubentry"), 1, &ocbva[2] );
	ocbva[3].bv_len = 0;
	ocbva[3].bv_val = NULL;

	mod = (Modifications *) ch_malloc( sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_next = NULL;
	mod->sml_desc = NULL;
	ber_str2bv( "objectClass", strlen("objectClass"), 1, &mod->sml_type );
	mod->sml_bvalues = ocbva;
	mod->sml_nvalues = ocbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	sprintf( substr, "syncrepl%d", si->id );
	sprintf( rdnstr, "cn=%s", substr );
	ber_str2bv( substr, strlen( substr ), 1, &cnbva[0] );
	ber_str2bv( rdnstr, strlen( rdnstr ), 1, &psubrdn );
	cnbva[1].bv_len = 0;
	cnbva[1].bv_val = NULL;
	mod = (Modifications *) ch_malloc( sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_next = NULL;
	mod->sml_desc = NULL;
	ber_str2bv( "cn", strlen("cn"), 1, &mod->sml_type );
	mod->sml_bvalues = cnbva;
	mod->sml_nvalues = cnbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	ber_dupbv( &scbva[0], si->syncCookie );
	scbva[1].bv_len = 0;
	scbva[1].bv_val = NULL;
	mod = (Modifications *) ch_malloc( sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_next = NULL;
	mod->sml_desc = NULL;
	ber_str2bv( "syncreplCookie", strlen("syncreplCookie"),
						1, &mod->sml_type );
	mod->sml_bvalues = scbva;
	mod->sml_nvalues = scbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	ber_str2bv( "{}", strlen("{}"), 1, &ssbva[0] );
	ssbva[1].bv_len = 0;
	ssbva[1].bv_val = NULL;
	mod = (Modifications *) ch_malloc( sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_next = NULL;
	mod->sml_desc = NULL;
	ber_str2bv( "subtreeSpecification",
			strlen("subtreeSpecification"), 1, &mod->sml_type );
	mod->sml_bvalues = ssbva;
	mod->sml_nvalues = ssbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	rc = slap_mods_check_syncrepl( op, &modlist, &text, txtbuf, textlen, NULL );

	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
				"syncrepl_updateCookie: mods check (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "syncrepl_updateCookie: mods check (%s)\n",
			 text, 0, 0 );
#endif
	}

	op->o_tag = LDAP_REQ_ADD;
	rc = slap_mods_opattrs_syncrepl( op, modlist, modtail, &text,txtbuf, textlen );

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

	build_new_dn( &sub_bv, pdn, &psubrdn );
	dnPrettyNormal( NULL, &sub_bv, &e->e_name, &e->e_nname, op->o_tmpmemctx );
	ch_free( sub_bv.bv_val );
	ch_free( psubrdn.bv_val );

	e->e_attrs = NULL;

	rc = slap_mods2entry_syncrepl( modlist, &e, 1, &text, txtbuf, textlen );

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
			 rc == LDAP_NO_SUCH_OBJECT ||
			 rc == DB_NOTFOUND ) {
			op->o_tag = LDAP_REQ_ADD;
			op->ora_e = e;
			rc = be->be_add( op, &rs );
			if ( rc != LDAP_SUCCESS ) {
				if ( rc == LDAP_ALREADY_EXISTS ) {
					goto update_cookie_retry;
				} else if ( rc == LDAP_REFERRAL ||
							rc == LDAP_NO_SUCH_OBJECT ||
							rc == DB_NOTFOUND ) {
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

	if ( e != NULL )
		entry_free( e );

done :

	for ( ml = modlist; ml != NULL; ml = mlnext ) {
		mlnext = ml->sml_next;
		free( ml );
	}

	return;
}


static
int slap_mods_check_syncrepl(
	Operation *op,
	Modifications **mlp,
	const char **text,
	char *textbuf,
	size_t textlen,
	void *ctx )
{
	int rc;
	Backend *be = op->o_bd;
	syncinfo_t *si = ( syncinfo_t * ) be->syncinfo;
	AttributeDescription** descs;
	int i;
	Modifications *prevml = NULL;
	Modifications *nextml = NULL;
	Modifications *ml = *mlp;

	while ( ml != NULL ) {
		AttributeDescription *ad = NULL;

		/* convert to attribute description */
		rc = slap_bv2ad( &ml->sml_type, &ml->sml_desc, text );

		if( rc != LDAP_SUCCESS ) {
			snprintf( textbuf, textlen, "%s: %s",
						ml->sml_type.bv_val, *text );
			*text = textbuf;
			return rc;
		}

		ad = ml->sml_desc;

		if ( si->lastmod == LASTMOD_REQ ) {
			descs = del_descs_lastmod;
		} else {
			descs = del_descs;
		}

		for ( i = 0; descs[i] != NULL; i++ ) {
			if ( ad == descs[i] ) {
				if ( prevml == NULL ) {
					mlp = &ml->sml_next;
					prevml = NULL;
				} else {
					prevml->sml_next = ml->sml_next;
				}
				slap_mod_free( &ml->sml_mod, 0 );
				nextml = ml->sml_next;
				free( ml );
				ml = nextml;
				continue;
			}
		}

		if( slap_syntax_is_binary( ad->ad_type->sat_syntax )
				&& !slap_ad_is_binary( ad )) {
			/* attribute requires binary transfer */
			snprintf( textbuf, textlen,
					"%s: requires ;binary transfer",
					ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if( !slap_syntax_is_binary( ad->ad_type->sat_syntax )
					&& slap_ad_is_binary( ad )) {
			/* attribute requires binary transfer */
			snprintf( textbuf, textlen,
					"%s: disallows ;binary transfer",
					ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if( slap_ad_is_tag_range( ad )) {
			/* attribute requires binary transfer */
			snprintf( textbuf, textlen,
					"%s: inappropriate use of tag range option",
					ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if ( is_at_obsolete( ad->ad_type ) &&
				( ml->sml_op == LDAP_MOD_ADD || ml->sml_values != NULL ) ) {
			/*
			 * attribute is obsolete,
			 * only allow replace/delete with no values
			 */
			snprintf( textbuf, textlen,
					"%s: attribute is obsolete",
					ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_CONSTRAINT_VIOLATION;
		}

		/*
		 * check values
		 */
		if( ml->sml_values != NULL ) {
			ber_len_t nvals;
			slap_syntax_validate_func *validate =
			ad->ad_type->sat_syntax->ssyn_validate;
			slap_syntax_transform_func *pretty =
			ad->ad_type->sat_syntax->ssyn_pretty;

			if( !pretty && !validate ) {
				*text = "no validator for syntax";
				snprintf( textbuf, textlen,
						"%s: no validator for syntax %s",
						ml->sml_type.bv_val,
						ad->ad_type->sat_syntax->ssyn_oid );
				*text = textbuf;
				return LDAP_INVALID_SYNTAX;
			}

			/*
			 * check that each value is valid per syntax
			 * and pretty if appropriate
			 */
			for( nvals = 0; ml->sml_values[nvals].bv_val; nvals++ ) {
				struct berval pval = {0, NULL};
				if( pretty ) {
					rc = pretty( ad->ad_type->sat_syntax,
							&ml->sml_values[nvals], &pval, ctx );
				} else {
					rc = validate( ad->ad_type->sat_syntax,
							&ml->sml_values[nvals] );
				}

				if( rc != 0 ) {
					snprintf( textbuf, textlen,
							"%s: value #%ld invalid per syntax",
							ml->sml_type.bv_val, (long) nvals );
					*text = textbuf;
					return LDAP_INVALID_SYNTAX;
				}

				if( pretty ) {
					ber_memfree( ml->sml_values[nvals].bv_val );
					ml->sml_values[nvals] = pval;
				}
			}

			/*
			 * a rough single value check... an additional check is needed
			 * to catch add of single value to existing single valued attribute
			 */
			if ((ml->sml_op == LDAP_MOD_ADD || ml->sml_op == LDAP_MOD_REPLACE)
					&& nvals > 1 && is_at_single_value( ad->ad_type )) {
				snprintf( textbuf, textlen,
						"%s: multiple values provided",
						ml->sml_type.bv_val );
				*text = textbuf;
				return LDAP_CONSTRAINT_VIOLATION;
			}

			if( nvals && ad->ad_type->sat_equality &&
					ad->ad_type->sat_equality->smr_normalize ) {
				ml->sml_nvalues = ch_malloc( (nvals+1)*sizeof(struct berval) );
				for( nvals = 0; ml->sml_values[nvals].bv_val; nvals++ ) {
					rc = ad->ad_type->sat_equality->smr_normalize( 0,
							ad->ad_type->sat_syntax, ad->ad_type->sat_equality,
							&ml->sml_values[nvals], &ml->sml_nvalues[nvals], ctx );
					if( rc ) {
#ifdef NEW_LOGGING
						LDAP_LOG( OPERATION, DETAIL1,
								"str2entry:  NULL (ssyn_normalize %d)\n", rc, 0, 0 );
#else
						Debug( LDAP_DEBUG_ANY,
								"<= str2entry NULL (ssyn_normalize %d)\n", rc, 0, 0 );
#endif
						snprintf( textbuf, textlen,
								"%s: value #%ld normalization failed",
								ml->sml_type.bv_val, (long) nvals );
						*text = textbuf;
						return rc;
					}
				}
				ml->sml_nvalues[nvals].bv_val = NULL;
				ml->sml_nvalues[nvals].bv_len = 0;
			}
		}
		prevml = ml;
		ml = ml->sml_next;
	}

	return LDAP_SUCCESS;
}

static
int slap_mods_opattrs_syncrepl(
	Operation *op,
	Modifications *mods,
	Modifications **modtail,
	const char **text,
	char *textbuf, size_t textlen )
{
	struct berval name = {0, NULL};
	struct berval timestamp = {0, NULL};
	struct berval csn = {0, NULL};
	struct berval nname = {0, NULL};
	char timebuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];
	char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];
	Modifications *mod;
	Backend *be = op->o_bd;
	syncinfo_t *si = ( syncinfo_t * ) be->syncinfo;

	int mop = LDAP_MOD_REPLACE;

	assert( modtail != NULL );
	assert( *modtail == NULL );

	if( si->lastmod == LASTMOD_GEN ) {
		struct tm *ltm;
		time_t now = slap_get_time();

		ldap_pvt_thread_mutex_lock( &gmtime_mutex );
		ltm = gmtime( &now );
		lutil_gentime( timebuf, sizeof(timebuf), ltm );

		csn.bv_len = lutil_csnstr( csnbuf, sizeof( csnbuf ), 0, 0 );
		ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
		csn.bv_val = csnbuf;

		timestamp.bv_val = timebuf;
		timestamp.bv_len = strlen(timebuf);

		if( op->o_dn.bv_len == 0 ) {
			name.bv_val = SLAPD_ANONYMOUS;
			name.bv_len = sizeof(SLAPD_ANONYMOUS)-1;
			nname = name;
		} else {
			name = op->o_dn;
			nname = op->o_ndn;
		}
	}

	if( op->o_tag == LDAP_REQ_ADD ) {
		struct berval tmpval = {0, NULL};

		if( global_schemacheck ) {
			int rc = mods_structural_class( mods, &tmpval,
									text, textbuf, textlen );
			if( rc != LDAP_SUCCESS ) {
				return rc;
			}

			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_structuralObjectClass;
			mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_values[0], &tmpval );
			mod->sml_values[1].bv_len = 0;
			mod->sml_values[1].bv_val = NULL;
			assert( mod->sml_values[0].bv_val );
			mod->sml_nvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_nvalues[0], &tmpval );
			mod->sml_nvalues[1].bv_len = 0;
			mod->sml_nvalues[1].bv_val = NULL;
			assert( mod->sml_nvalues[0].bv_val );
			*modtail = mod;
			modtail = &mod->sml_next;
		}

		if( si->lastmod == LASTMOD_GEN ) {
			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_creatorsName;
			mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_values[0], &name );
			mod->sml_values[1].bv_len = 0;
			mod->sml_values[1].bv_val = NULL;
			assert( mod->sml_values[0].bv_val );
			mod->sml_nvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_nvalues[0], &nname );
			mod->sml_nvalues[1].bv_len = 0;
			mod->sml_nvalues[1].bv_val = NULL;
			assert( mod->sml_nvalues[0].bv_val );
			*modtail = mod;
			modtail = &mod->sml_next;

			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_createTimestamp;
			mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_values[0], &timestamp );
			mod->sml_values[1].bv_len = 0;
			mod->sml_values[1].bv_val = NULL;
			assert( mod->sml_values[0].bv_val );
			mod->sml_nvalues = NULL;
			*modtail = mod;
			modtail = &mod->sml_next;
		}
	}

	if( si->lastmod == LASTMOD_GEN ) {
		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_entryCSN;
		mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_values[0], &csn );
		mod->sml_values[1].bv_len = 0;
		mod->sml_values[1].bv_val = NULL;
		assert( mod->sml_values[0].bv_val );
		mod->sml_nvalues = NULL;
		*modtail = mod;
		modtail = &mod->sml_next;

		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_modifiersName;
		mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_values[0], &name );
		mod->sml_values[1].bv_len = 0;
		mod->sml_values[1].bv_val = NULL;
		assert( mod->sml_values[0].bv_val );
		mod->sml_nvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_nvalues[0], &nname );
		mod->sml_nvalues[1].bv_len = 0;
		mod->sml_nvalues[1].bv_val = NULL;
		assert( mod->sml_nvalues[0].bv_val );
		*modtail = mod;
		modtail = &mod->sml_next;

		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_modifyTimestamp;
		mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_values[0], &timestamp );
		mod->sml_values[1].bv_len = 0;
		mod->sml_values[1].bv_val = NULL;
		assert( mod->sml_values[0].bv_val );
		mod->sml_nvalues = NULL;
		*modtail = mod;
		modtail = &mod->sml_next;
	}

	*modtail = NULL;
	return LDAP_SUCCESS;
}


static
int slap_mods2entry_syncrepl(
	Modifications *mods,
	Entry **e,
	int repl_user,
	const char **text,
	char *textbuf, size_t textlen )
{
	Attribute **tail = &(*e)->e_attrs;
	assert( *tail == NULL );

	*text = textbuf;

	for( ; mods != NULL; mods = mods->sml_next ) {
		Attribute *attr;

		assert( mods->sml_desc != NULL );

		attr = attr_find( (*e)->e_attrs, mods->sml_desc );

		if( attr != NULL ) {
#define SLURPD_FRIENDLY
#ifdef SLURPD_FRIENDLY
			ber_len_t i,j;

			if( !repl_user ) {
				snprintf( textbuf, textlen,
					"attribute '%s' provided more than once",
					mods->sml_desc->ad_cname.bv_val );
				return LDAP_TYPE_OR_VALUE_EXISTS;
			}

			for( i=0; attr->a_vals[i].bv_val; i++ ) {
				/* count them */
			}
			for( j=0; mods->sml_values[j].bv_val; j++ ) {
				/* count them */
			}
			j++;	/* NULL */
			
			attr->a_vals = ch_realloc( attr->a_vals,
				sizeof( struct berval ) * (i+j) );

			/* should check for duplicates */

			AC_MEMCPY( &attr->a_vals[i], mods->sml_values,
				sizeof( struct berval ) * j );

			if( attr->a_nvals ) {
				attr->a_nvals = ch_realloc( attr->a_nvals,
					sizeof( struct berval ) * (i+j) );

				AC_MEMCPY( &attr->a_nvals[i], mods->sml_nvalues,
					sizeof( struct berval ) * j );

				/* trim the mods array */
				ch_free( mods->sml_nvalues );
				mods->sml_nvalues = NULL;
			}

			continue;
#else
			snprintf( textbuf, textlen,
				"attribute '%s' provided more than once",
				mods->sml_desc->ad_cname.bv_val );
			return LDAP_TYPE_OR_VALUE_EXISTS;
#endif
		}

		if( mods->sml_values[1].bv_val != NULL ) {
			/* check for duplicates */
			int		i, j;
			MatchingRule *mr = mods->sml_desc->ad_type->sat_equality;

			/* check if the values we're adding already exist */
			if( mr == NULL || !mr->smr_match ) {
				for ( i = 0; mods->sml_bvalues[i].bv_val != NULL; i++ ) {
					/* test asserted values against themselves */
					for( j = 0; j < i; j++ ) {
						if ( bvmatch( &mods->sml_bvalues[i],
							&mods->sml_bvalues[j] ) ) {
							/* value exists already */
							snprintf( textbuf, textlen,
								"%s: value #%d provided more than once",
								mods->sml_desc->ad_cname.bv_val, j );
							return LDAP_TYPE_OR_VALUE_EXISTS;
						}
					}
				}

			} else {
				int		rc;
				const char	*text = NULL;
				char		textbuf[ SLAP_TEXT_BUFLEN ]  = { '\0' };
				
				rc = modify_check_duplicates( mods->sml_desc, mr,
						NULL, mods->sml_bvalues, 0,
						&text, textbuf, sizeof( textbuf ) );

				if ( rc != LDAP_SUCCESS ) {
					return rc;
				}
			}
		}

		attr = ch_calloc( 1, sizeof(Attribute) );

		/* move ad to attr structure */
		attr->a_desc = mods->sml_desc;

		/* move values to attr structure */
		/*	should check for duplicates */
		attr->a_vals = mods->sml_values;

		attr->a_nvals = mods->sml_nvalues;

		*tail = attr;
		tail = &attr->a_next;
	}

	return LDAP_SUCCESS;
}

void
avl_ber_bvfree( void *bv )
{
	if( bv == NULL ) {
		return;
	}
	if ( ((struct berval *)bv)->bv_val != NULL ) {
		ber_memfree ( ((struct berval *)bv)->bv_val );
	}
	ber_memfree ( (char *) bv );
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
		si->syncUUID_ndn = &rs->sr_entry->e_nname;
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
		 rs->sr_err != LDAP_NO_SUCH_OBJECT &&
		 rs->sr_err != DB_NOTFOUND ) {
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


char **
str2clist( char **out, char *in, const char *brkstr )
{
	char	*str;
	char	*s;
	char	*lasts;
	int	i, j;
	const char *text;
	char	**new;

	/* find last element in list */
	for (i = 0; out && out[i]; i++);
	
	/* protect the input string from strtok */
	str = ch_strdup( in );

	/* Count words in string */
	j=1;
	for ( s = str; *s; s++ ) {
		if ( strchr( brkstr, *s ) != NULL ) {
			j++;
		}
	}

	out = ch_realloc( out, ( i + j + 1 ) * sizeof( char * ) );
	new = out + i;
	for ( s = ldap_pvt_strtok( str, brkstr, &lasts );
		s != NULL;
		s = ldap_pvt_strtok( NULL, brkstr, &lasts ) )
	{
		*new = ch_strdup( s );
		new++;
	}

	*new = NULL;
	free( str );
	return( out );
}

#endif

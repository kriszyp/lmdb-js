/* $OpenLDAP$ */
/* 
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#include "../../libraries/liblber/lber-int.h"

#define SLAP_CTRL_FRONTEND			0x80000000U
#define SLAP_CTRL_FRONTEND_SEARCH	0x01000000U	/* for NOOP */

#define SLAP_CTRL_OPFLAGS			0x0000FFFFU
#define SLAP_CTRL_ABANDON			0x00000001U
#define SLAP_CTRL_ADD				0x00002002U
#define SLAP_CTRL_BIND				0x00000004U
#define SLAP_CTRL_COMPARE			0x00001008U
#define SLAP_CTRL_DELETE			0x00002010U
#define SLAP_CTRL_MODIFY			0x00002020U
#define SLAP_CTRL_RENAME			0x00002040U
#define SLAP_CTRL_SEARCH			0x00001080U
#define SLAP_CTRL_UNBIND			0x00000100U

#define SLAP_CTRL_INTROGATE	(SLAP_CTRL_COMPARE|SLAP_CTRL_SEARCH)
#define SLAP_CTRL_UPDATE \
	(SLAP_CTRL_ADD|SLAP_CTRL_DELETE|SLAP_CTRL_MODIFY|SLAP_CTRL_RENAME)
#define SLAP_CTRL_ACCESS	(SLAP_CTRL_INTROGATE|SLAP_CTRL_UPDATE)

typedef int (SLAP_CTRL_PARSE_FN) LDAP_P((
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text ));

static SLAP_CTRL_PARSE_FN parseProxyAuthz;
static SLAP_CTRL_PARSE_FN parseManageDSAit;
static SLAP_CTRL_PARSE_FN parseNoOp;
static SLAP_CTRL_PARSE_FN parsePagedResults;
static SLAP_CTRL_PARSE_FN parseValuesReturnFilter;
static SLAP_CTRL_PARSE_FN parsePermissiveModify;
static SLAP_CTRL_PARSE_FN parseDomainScope;

#ifdef LDAP_CONTROL_SUBENTRIES
static SLAP_CTRL_PARSE_FN parseSubentries;
#endif
#ifdef LDAP_CLIENT_UPDATE
static SLAP_CTRL_PARSE_FN parseClientUpdate;
#endif
#ifdef LDAP_SYNC
static SLAP_CTRL_PARSE_FN parseLdupSync;
#endif

#undef sc_mask /* avoid conflict with Irix 6.5 <sys/signal.h> */

static char *proxy_authz_extops[] = {
	LDAP_EXOP_MODIFY_PASSWD,
	LDAP_EXOP_X_WHO_AM_I,
	NULL
};

/*
 * all known request control OIDs should be added to this list
 */
char *slap_known_controls[] = {
	LDAP_CONTROL_MANAGEDSAIT,
	LDAP_CONTROL_PROXY_AUTHZ,

#ifdef LDAP_CONTROL_SUBENTRIES
	LDAP_CONTROL_SUBENTRIES,
#endif /* LDAP_CONTROL_SUBENTRIES */

	LDAP_CONTROL_NOOP,

#ifdef LDAP_CONTROL_DUPENT_REQUEST
	LDAP_CONTROL_DUPENT_REQUEST,
#endif /* LDAP_CONTROL_DUPENT_REQUEST */

#ifdef LDAP_CONTROL_PAGEDRESULTS
	LDAP_CONTROL_PAGEDRESULTS,
#endif

#ifdef LDAP_CONTROL_SORTREQUEST
	LDAP_CONTROL_SORTREQUEST,
#endif /* LDAP_CONTROL_SORTREQUEST */

#ifdef LDAP_CONTROL_VLVREQUEST
	LDAP_CONTROL_VLVREQUEST,
#endif /* LDAP_CONTROL_VLVREQUEST */

	LDAP_CONTROL_VALUESRETURNFILTER,
	NULL
};

static struct slap_control {
	char *sc_oid;
	slap_mask_t sc_mask;
	char **sc_extendedops;
	SLAP_CTRL_PARSE_FN *sc_parse;

} supportedControls[] = {
 	{ LDAP_CONTROL_VALUESRETURNFILTER,
 		SLAP_CTRL_SEARCH, NULL,
		parseValuesReturnFilter },
#ifdef LDAP_CONTROL_PAGEDRESULTS
	{ LDAP_CONTROL_PAGEDRESULTS,
		SLAP_CTRL_SEARCH, NULL,
		parsePagedResults },
#endif
#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
	{ LDAP_CONTROL_X_DOMAIN_SCOPE,
		SLAP_CTRL_FRONTEND|SLAP_CTRL_SEARCH, NULL,
		parseDomainScope },
#endif
#ifdef LDAP_CONTROL_X_PERMISSIVE_MODIFY
	{ LDAP_CONTROL_X_PERMISSIVE_MODIFY,
		SLAP_CTRL_MODIFY, NULL,
		parsePermissiveModify },
#endif
#ifdef LDAP_CONTROL_SUBENTRIES
	{ LDAP_CONTROL_SUBENTRIES,
		SLAP_CTRL_SEARCH, NULL,
		parseSubentries },
#endif
	{ LDAP_CONTROL_NOOP,
		SLAP_CTRL_ACCESS, NULL,
		parseNoOp },
#ifdef LDAP_CLIENT_UPDATE
	{ LDAP_CONTROL_CLIENT_UPDATE,
		SLAP_CTRL_SEARCH, NULL,
		parseClientUpdate },
#endif
#ifdef LDAP_SYNC
	{ LDAP_CONTROL_SYNC,
		SLAP_CTRL_SEARCH, NULL,
		parseLdupSync },
#endif
	{ LDAP_CONTROL_MANAGEDSAIT,
		SLAP_CTRL_ACCESS, NULL,
		parseManageDSAit },
	{ LDAP_CONTROL_PROXY_AUTHZ,
		SLAP_CTRL_FRONTEND|SLAP_CTRL_ACCESS, proxy_authz_extops,
		parseProxyAuthz },
	{ NULL, 0, NULL, 0 }
};

char *
get_supported_ctrl(int index)
{
	return supportedControls[index].sc_oid;
}

slap_mask_t
get_supported_ctrl_mask(int index)
{
	return supportedControls[index].sc_mask;
}

static struct slap_control *
find_ctrl( const char *oid )
{
	int i;
	for( i=0; supportedControls[i].sc_oid; i++ ) {
		if( strcmp( oid, supportedControls[i].sc_oid ) == 0 ) {
			return &supportedControls[i];
		}
	}
	return NULL;
}

int get_ctrls(
	Connection *conn,
	Operation *op,
	int sendres )
{
	int nctrls = 0;
	ber_tag_t tag;
	ber_len_t len;
	char *opaque;
	BerElement *ber = op->o_ber;
	struct slap_control *sc;
	int rc = LDAP_SUCCESS;
	const char *errmsg = NULL;

	len = ber_pvt_ber_remaining(ber);

	if( len == 0) {
		/* no controls */
		rc = LDAP_SUCCESS;
		return rc;
	}

	if(( tag = ber_peek_tag( ber, &len )) != LDAP_TAG_CONTROLS ) {
		if( tag == LBER_ERROR ) {
			rc = SLAPD_DISCONNECT;
			errmsg = "unexpected data in PDU";
		}

		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY,
		"get_ctrls: conn %lu\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"=> get_ctrls\n", 0, 0, 0 );
#endif

	if( op->o_protocol < LDAP_VERSION3 ) {
		rc = SLAPD_DISCONNECT;
		errmsg = "controls require LDAPv3";
		goto return_results;
	}

	/* one for first control, one for termination */
	op->o_ctrls = ch_malloc( 2 * sizeof(LDAPControl *) );

#if 0
	if( op->ctrls == NULL ) {
		rc = LDAP_NO_MEMORY;
		errmsg = "no memory";
		goto return_results;
	}
#endif

	op->o_ctrls[nctrls] = NULL;

	/* step through each element */
	for( tag = ber_first_element( ber, &len, &opaque );
		tag != LBER_ERROR;
		tag = ber_next_element( ber, &len, opaque ) )
	{
		LDAPControl *c;
		LDAPControl **tctrls;

		c = ch_calloc( 1, sizeof(LDAPControl) );

#if 0
		if( c == NULL ) {
			ldap_controls_free(op->o_ctrls);
			op->o_ctrls = NULL;

			rc = LDAP_NO_MEMORY;
			errmsg = "no memory";
			goto return_results;
		}
#endif

		/* allocate pointer space for current controls (nctrls)
		 * + this control + extra NULL
		 */
		tctrls = ch_realloc( op->o_ctrls,
			(nctrls+2) * sizeof(LDAPControl *));

#if 0
		if( tctrls == NULL ) {
			ch_free( c );
			ldap_controls_free(op->o_ctrls);
			op->o_ctrls = NULL;

			rc = LDAP_NO_MEMORY;
			errmsg = "no memory";
			goto return_results;
		}
#endif
		op->o_ctrls = tctrls;

		op->o_ctrls[nctrls++] = c;
		op->o_ctrls[nctrls] = NULL;

		tag = ber_scanf( ber, "{a" /*}*/, &c->ldctl_oid );

		if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, "get_ctrls: conn %lu get OID failed.\n",
				conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "=> get_ctrls: get oid failed.\n",
				0, 0, 0 );
#endif

			ldap_controls_free( op->o_ctrls );
			op->o_ctrls = NULL;
			rc = SLAPD_DISCONNECT;
			errmsg = "decoding controls error";
			goto return_results;

		} else if( c->ldctl_oid == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO,
				"get_ctrls: conn %lu got emtpy OID.\n",
				conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"get_ctrls: conn %lu got emtpy OID.\n",
				conn->c_connid, 0, 0 );
#endif

			ldap_controls_free( op->o_ctrls );
			op->o_ctrls = NULL;
			rc = LDAP_PROTOCOL_ERROR;
			errmsg = "OID field is empty";
			goto return_results;
		}

		tag = ber_peek_tag( ber, &len );

		if( tag == LBER_BOOLEAN ) {
			ber_int_t crit;
			tag = ber_scanf( ber, "b", &crit );

			if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, INFO, 
					"get_ctrls: conn %lu get crit failed.\n", 
					conn->c_connid, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE, "=> get_ctrls: get crit failed.\n",
					0, 0, 0 );
#endif
				ldap_controls_free( op->o_ctrls );
				op->o_ctrls = NULL;
				rc = SLAPD_DISCONNECT;
				errmsg = "decoding controls error";
				goto return_results;
			}

			c->ldctl_iscritical = (crit != 0);
			tag = ber_peek_tag( ber, &len );
		}

		if( tag == LBER_OCTETSTRING ) {
			tag = ber_scanf( ber, "o", &c->ldctl_value );

			if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, INFO, "get_ctrls: conn %lu: "
					"%s (%scritical): get value failed.\n",
					conn->c_connid, c->ldctl_oid,
					c->ldctl_iscritical ? "" : "non" );
#else
				Debug( LDAP_DEBUG_TRACE, "=> get_ctrls: conn %lu: "
					"%s (%scritical): get value failed.\n",
					conn->c_connid, c->ldctl_oid,
					c->ldctl_iscritical ? "" : "non" );
#endif
				ldap_controls_free( op->o_ctrls );
				op->o_ctrls = NULL;
				rc = SLAPD_DISCONNECT;
				errmsg = "decoding controls error";
				goto return_results;
			}
		}

#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"get_ctrls: conn %lu oid=\"%s\" (%scritical)\n",
			conn->c_connid, c->ldctl_oid, c->ldctl_iscritical ? "" : "non" );
#else
		Debug( LDAP_DEBUG_TRACE,
			"=> get_ctrls: oid=\"%s\" (%scritical)\n",
			c->ldctl_oid, c->ldctl_iscritical ? "" : "non", 0 );
#endif

		sc = find_ctrl( c->ldctl_oid );
		if( sc != NULL ) {
			/* recognized control */
			slap_mask_t tagmask;
			switch( op->o_tag ) {
			case LDAP_REQ_ADD:
				tagmask = SLAP_CTRL_ADD;
				break;
			case LDAP_REQ_BIND:
				tagmask = SLAP_CTRL_BIND;
				break;
			case LDAP_REQ_COMPARE:
				tagmask = SLAP_CTRL_COMPARE;
				break;
			case LDAP_REQ_DELETE:
				tagmask = SLAP_CTRL_DELETE;
				break;
			case LDAP_REQ_MODIFY:
				tagmask = SLAP_CTRL_MODIFY;
				break;
			case LDAP_REQ_RENAME:
				tagmask = SLAP_CTRL_RENAME;
				break;
			case LDAP_REQ_SEARCH:
				tagmask = SLAP_CTRL_SEARCH;
				break;
			case LDAP_REQ_UNBIND:
				tagmask = SLAP_CTRL_UNBIND;
				break;
			case LDAP_REQ_ABANDON:
				tagmask = SLAP_CTRL_ABANDON;
				break;
			case LDAP_REQ_EXTENDED:
				tagmask=~0L;
				assert( op->o_extendedop != NULL );
				if( sc->sc_extendedops != NULL ) {
					int i;
					for( i=0; sc->sc_extendedops[i] != NULL; i++ ) {
						if( strcmp( op->o_extendedop, sc->sc_extendedops[i] )
							== 0 )
						{
							tagmask=0L;
							break;
						}
					}
				}
				break;
			default:
				rc = LDAP_OTHER;
				errmsg = "controls internal error";
				goto return_results;
			}

			if (( sc->sc_mask & tagmask ) == tagmask ) {
				/* available extension */

				if( !sc->sc_parse ) {
					rc = LDAP_OTHER;
					errmsg = "not yet implemented";
					goto return_results;
				}

				rc = sc->sc_parse( conn, op, c, &errmsg );

				if( rc != LDAP_SUCCESS ) goto return_results;

				if ( sc->sc_mask & SLAP_CTRL_FRONTEND ) {
					/* kludge to disable backend_control() check */
					c->ldctl_iscritical = 0;

				} else if ( tagmask == SLAP_CTRL_SEARCH &&
					sc->sc_mask & SLAP_CTRL_FRONTEND_SEARCH )
				{
					/* kludge to disable backend_control() check */
					c->ldctl_iscritical = 0;
				}

			} else if( c->ldctl_iscritical ) {
				/* unavailable CRITICAL control */
				rc = LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
				errmsg = "critical extension is unavailable";
				goto return_results;
			}

		} else if( c->ldctl_iscritical ) {
			/* unrecognized CRITICAL control */
			rc = LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
			errmsg = "critical extension is not recognized";
			goto return_results;
		}
	}

return_results:
#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, RESULTS, 
		"get_ctrls: n=%d rc=%d err=\"%s\"\n",
		nctrls, rc, errmsg ? errmsg : "" );
#else
	Debug( LDAP_DEBUG_TRACE,
		"<= get_ctrls: n=%d rc=%d err=\"%s\"\n",
		nctrls, rc, errmsg ? errmsg : "");
#endif

	if( sendres && rc != LDAP_SUCCESS ) {
		if( rc == SLAPD_DISCONNECT ) {
			send_ldap_disconnect( conn, op, LDAP_PROTOCOL_ERROR, errmsg );
		} else {
			send_ldap_result( conn, op, rc,
				NULL, errmsg, NULL, NULL );
		}
	}

	return rc;
}

static int parseManageDSAit (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	if ( op->o_managedsait != SLAP_NO_CONTROL ) {
		*text = "manageDSAit control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		*text = "manageDSAit control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_managedsait = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	return LDAP_SUCCESS;
}

static int parseProxyAuthz (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	int rc;
	struct berval dn = { 0, NULL };

	if ( op->o_proxy_authz != SLAP_NO_CONTROL ) {
		*text = "proxy authorization control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_proxy_authz = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, 
		"parseProxyAuthz: conn %lu authzid=\"%s\"\n", 
		conn->c_connid,
		ctrl->ldctl_value.bv_len ?  ctrl->ldctl_value.bv_val : "anonymous",
		0 );
#else
	Debug( LDAP_DEBUG_ARGS,
		"parseProxyAuthz: conn %lu authzid=\"%s\"\n", 
		conn->c_connid,
		ctrl->ldctl_value.bv_len ?  ctrl->ldctl_value.bv_val : "anonymous",
		0 );
#endif

	if( ctrl->ldctl_value.bv_len == 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, RESULTS, 
			"parseProxyAuthz: conn=%lu anonymous\n", 
			conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"parseProxyAuthz: conn=%lu anonymous\n", 
			conn->c_connid, 0, 0 );
#endif

		/* anonymous */
		free( op->o_dn.bv_val );
		op->o_dn.bv_len = 0;
		op->o_dn.bv_val = ch_strdup( "" );

		free( op->o_ndn.bv_val );
		op->o_ndn.bv_len = 0;
		op->o_ndn.bv_val = ch_strdup( "" );

		return LDAP_SUCCESS;
	}

	rc = slap_sasl_getdn( conn,
		ctrl->ldctl_value.bv_val, ctrl->ldctl_value.bv_len,
		NULL, &dn, SLAP_GETDN_AUTHZID );

	if( rc != LDAP_SUCCESS || !dn.bv_len ) {
		if ( dn.bv_val ) {
			ch_free( dn.bv_val );
		}
		*text = "authzId mapping failed";
		return LDAP_PROXY_AUTHZ_FAILURE;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, RESULTS, 
		"parseProxyAuthz: conn=%lu \"%s\"\n", 
		conn->c_connid,
		dn.bv_len ? dn.bv_val : "(NULL)", 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"parseProxyAuthz: conn=%lu \"%s\"\n", 
		conn->c_connid,
		dn.bv_len ? dn.bv_val : "(NULL)", 0 );
#endif

	rc = slap_sasl_authorized( conn, &op->o_ndn, &dn );

	if( rc ) {
		ch_free( dn.bv_val );
		*text = "not authorized to assume identity";
		return LDAP_PROXY_AUTHZ_FAILURE;
	}

	ch_free( op->o_dn.bv_val );
	ch_free( op->o_ndn.bv_val );

	op->o_dn.bv_val = NULL;
	op->o_ndn = dn;

	/*
	 * NOTE: since slap_sasl_getdn() returns a normalized dn,
	 * from now on op->o_dn is normalized
	 */
	ber_dupbv( &op->o_dn, &dn );

	return LDAP_SUCCESS;
}

static int parseNoOp (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	if ( op->o_noop != SLAP_NO_CONTROL ) {
		*text = "noop control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		*text = "noop control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_noop = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	return LDAP_SUCCESS;
}

#ifdef LDAP_CONTROL_PAGEDRESULTS
static int parsePagedResults (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	ber_tag_t tag;
	ber_int_t size;
	BerElement *ber;
	struct berval cookie = { 0, NULL };

	if ( op->o_pagedresults != SLAP_NO_CONTROL ) {
		*text = "paged results control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		*text = "paged results control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	/* Parse the control value
	 *	realSearchControlValue ::= SEQUENCE {
	 *		size	INTEGER (0..maxInt),
	 *				-- requested page size from client
	 *				-- result set size estimate from server
	 *		cookie	OCTET STRING
	 * }
	 */
	ber = ber_init( &ctrl->ldctl_value );
	if( ber == NULL ) {
		*text = "internal error";
		return LDAP_OTHER;
	}

	tag = ber_scanf( ber, "{im}", &size, &cookie );
	(void) ber_free( ber, 1 );

	if( tag == LBER_ERROR ) {
		*text = "paged results control could not be decoded";
		return LDAP_PROTOCOL_ERROR;
	}

	if( size < 0 ) {
		*text = "paged results control size invalid";
		return LDAP_PROTOCOL_ERROR;
	}

	if( cookie.bv_len ) {
		PagedResultsCookie reqcookie;
		if( cookie.bv_len != sizeof( reqcookie ) ) {
			/* bad cookie */
			*text = "paged results cookie is invalid";
			return LDAP_PROTOCOL_ERROR;
		}

		AC_MEMCPY( &reqcookie, cookie.bv_val, sizeof( reqcookie ));

		if( reqcookie > op->o_pagedresults_state.ps_cookie ) {
			/* bad cookie */
			*text = "paged results cookie is invalid";
			return LDAP_PROTOCOL_ERROR;

		} else if( reqcookie < op->o_pagedresults_state.ps_cookie ) {
			*text = "paged results cookie is invalid or old";
			return LDAP_UNWILLING_TO_PERFORM;
		}
	} else {
		/* Initial request.  Initialize state. */
		op->o_pagedresults_state.ps_cookie = 0;
		op->o_pagedresults_state.ps_id = NOID;
	}

	op->o_pagedresults_size = size;

	op->o_pagedresults = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	return LDAP_SUCCESS;
}
#endif

int parseValuesReturnFilter (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	int		rc;
	BerElement	*ber;
	struct berval	fstr = { 0, NULL };
	const char *err_msg = "";

	if ( op->o_valuesreturnfilter != SLAP_NO_CONTROL ) {
		*text = "valuesReturnFilter control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		*text = "valuesReturnFilter control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	ber = ber_init( &(ctrl->ldctl_value) );
	if (ber == NULL) {
		*text = "internal error";
		return LDAP_OTHER;
	}
	
	rc = get_vrFilter( conn, ber, &(op->vrFilter), &err_msg);

	if( rc != LDAP_SUCCESS ) {
		text = &err_msg;
		if( rc == SLAPD_DISCONNECT ) {
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, *text );
		} else {
			send_ldap_result( conn, op, rc,
				NULL, *text, NULL, NULL );
		}
		if( fstr.bv_val != NULL) free( fstr.bv_val );
		if( op->vrFilter != NULL) vrFilter_free( op->vrFilter ); 

	} else {
		vrFilter2bv( op->vrFilter, &fstr );
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, 
		"parseValuesReturnFilter: conn %d	vrFilter: %s\n", 
		conn->c_connid, fstr.bv_len ? fstr.bv_val : "empty" , 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "	vrFilter: %s\n",
		fstr.bv_len ? fstr.bv_val : "empty", 0, 0 );
#endif

	op->o_valuesreturnfilter = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	return LDAP_SUCCESS;
}

#ifdef LDAP_CONTROL_SUBENTRIES
static int parseSubentries (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	if ( op->o_subentries != SLAP_NO_CONTROL ) {
		*text = "subentries control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	/* FIXME: should use BER library */
	if( ( ctrl->ldctl_value.bv_len != 3 )
		&& ( ctrl->ldctl_value.bv_val[0] != 0x01 )
		&& ( ctrl->ldctl_value.bv_val[1] != 0x01 ))
	{
		*text = "subentries control value encoding is bogus";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_subentries = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	op->o_subentries_visibility = (ctrl->ldctl_value.bv_val[2] != 0x00);

	return LDAP_SUCCESS;
}
#endif

#ifdef LDAP_CONTROL_X_PERMISSIVE_MODIFY
static int parsePermissiveModify (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	if ( op->o_permissive_modify != SLAP_NO_CONTROL ) {
		*text = "permissiveModify control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		*text = "permissiveModify control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_permissive_modify = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	return LDAP_SUCCESS;
}
#endif

#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
static int parseDomainScope (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	if ( op->o_domain_scope != SLAP_NO_CONTROL ) {
		*text = "domainScope control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		*text = "domainScope control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_domain_scope = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	return LDAP_SUCCESS;
}
#endif

#ifdef LDAP_CLIENT_UPDATE
static int parseClientUpdate (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	ber_tag_t tag;
	BerElement *ber;
	ber_int_t type;
	ber_int_t interval;
	ber_len_t len;
	struct berval scheme = { 0, NULL };
	struct berval cookie = { 0, NULL };

	if ( op->o_clientupdate != SLAP_NO_CONTROL ) {
		*text = "LCUP client update control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

#ifdef LDAP_SYNC
	if ( op->o_sync != SLAP_NO_CONTROL ) {
		*text = "LDAP Client Update and Sync controls used together";
		return LDAP_PROTOCOL_ERROR;
	}
#endif

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		*text = "LCUP client update control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	/* Parse the control value
	 *	ClientUpdateControlValue ::= SEQUENCE {
	 *		updateType	ENUMERATED {
	 *					synchronizeOnly	{0},
	 *					synchronizeAndPersist {1},
	 *					persistOnly {2} },
	 *		sendCookieInterval INTEGER OPTIONAL,
	 *		cookie		LCUPCookie OPTIONAL
	 *	}
	 */

	ber = ber_init( &ctrl->ldctl_value );
	if( ber == NULL ) {
		*text = "internal error";
		return LDAP_OTHER;
	}

	if ( (tag = ber_scanf( ber, "{i" /*}*/, &type )) == LBER_ERROR ) {
		*text = "LCUP client update control : decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	switch( type ) {
	case LDAP_CUP_SYNC_ONLY:
		type = SLAP_LCUP_SYNC;
		break;
	case LDAP_CUP_SYNC_AND_PERSIST:
		type = SLAP_LCUP_SYNC_AND_PERSIST;
		break;
	case LDAP_CUP_PERSIST_ONLY:
		type = SLAP_LCUP_PERSIST;
		break;
	default:
		*text = "LCUP client update control : unknown update type";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( (tag = ber_peek_tag( ber, &len )) == LBER_DEFAULT ) {
		*text = "LCUP client update control : decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( tag == LDAP_CUP_TAG_INTERVAL ) {
		if ( (tag = ber_scanf( ber, "i", &interval )) == LBER_ERROR ) {
			*text = "LCUP client update control : decoding error";
			return LDAP_PROTOCOL_ERROR;
		}
		
		if ( interval <= 0 ) {
			/* server chooses interval */
			interval = LDAP_CUP_DEFAULT_SEND_COOKIE_INTERVAL;
		}

	} else {
		/* server chooses interval */
		interval = LDAP_CUP_DEFAULT_SEND_COOKIE_INTERVAL;
	}

	if ( (tag = ber_peek_tag( ber, &len )) == LBER_DEFAULT ) {
		*text = "LCUP client update control : decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( tag == LDAP_CUP_TAG_COOKIE ) {
		if ( (tag = ber_scanf( ber, /*{*/ "{mm}}",
			&scheme, &cookie )) == LBER_ERROR )
		{
			*text = "LCUP client update control : decoding error";
			return LDAP_PROTOCOL_ERROR;
		}
	}

	/* TODO : Cookie Scheme Validation */
#if 0
	if ( lcup_cookie_scheme_validate(scheme) != LDAP_SUCCESS ) {
		*text = "Unsupported LCUP cookie scheme";
		return LCUP_UNSUPPORTED_SCHEME;
	}

	if ( lcup_cookie_validate(scheme, cookie) != LDAP_SUCCESS ) {
		*text = "Invalid LCUP cookie";
		return LCUP_INVALID_COOKIE;
	}
#endif

	ber_dupbv( &op->o_clientupdate_state, &cookie );

	(void) ber_free( ber, 1 );

	op->o_clientupdate_type = (char) type;
	op->o_clientupdate_interval = interval;

	op->o_clientupdate = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	return LDAP_SUCCESS;
}
#endif

#ifdef LDAP_SYNC
static int parseLdupSync (
	Connection *conn,
	Operation *op,
	LDAPControl *ctrl,
	const char **text )
{
	ber_tag_t tag;
	BerElement *ber;
	ber_int_t mode;
	ber_len_t len;
	struct berval cookie = { 0, NULL };

	if ( op->o_sync != SLAP_NO_CONTROL ) {
		*text = "LDAP Sync control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

#ifdef LDAP_CLIENT_UPDATE
	if ( op->o_clientupdate != SLAP_NO_CONTROL ) {
		*text = "LDAP Sync and LDAP Client Update controls used together";
		return LDAP_PROTOCOL_ERROR;
	}
#endif

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		*text = "LDAP Sync control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	/* Parse the control value
	 *      syncRequestValue ::= SEQUENCE {
	 *              mode   ENUMERATED {
	 *                      -- 0 unused
	 *                      refreshOnly		(1),
	 *                      -- 2 reserved
	 *                      refreshAndPersist	(3)
	 *              },
	 *              cookie  syncCookie OPTIONAL
	 *      }
	 */

	ber = ber_init( &ctrl->ldctl_value );
	if( ber == NULL ) {
		*text = "internal error";
		return LDAP_OTHER;
	}

	if ( (tag = ber_scanf( ber, "{i" /*}*/, &mode )) == LBER_ERROR ) {
		*text = "LDAP Sync control : mode decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	switch( mode ) {
	case LDAP_SYNC_REFRESH_ONLY:
		mode = SLAP_SYNC_REFRESH;
		break;
	case LDAP_SYNC_REFRESH_AND_PERSIST:
		mode = SLAP_SYNC_REFRESH_AND_PERSIST;
		break;
	default:
		*text = "LDAP Sync control : unknown update mode";
		return LDAP_PROTOCOL_ERROR;
	}

	tag = ber_peek_tag( ber, &len );

	if ( tag == LDAP_SYNC_TAG_COOKIE ) {
		if (( ber_scanf( ber, /*{*/ "m}",
					&cookie )) == LBER_ERROR ) {
			*text = "LDAP Sync control : cookie decoding error";
			return LDAP_PROTOCOL_ERROR;
		}
	} else {
		if (( ber_scanf( ber, /*{*/ "}")) == LBER_ERROR ) {
			*text = "LDAP Sync control : decoding error";
			return LDAP_PROTOCOL_ERROR;
		}
		cookie.bv_len = 0;
		cookie.bv_val = NULL;
	}

	/* TODO : Cookie Scheme Validation */
#if 0
	if ( lcup_cookie_scheme_validate(scheme) != LDAP_SUCCESS ) {
		*text = "Unsupported LCUP cookie scheme";
		return LCUP_UNSUPPORTED_SCHEME;
	}

	if ( lcup_cookie_validate(scheme, cookie) != LDAP_SUCCESS ) {
		*text = "Invalid LCUP cookie";
		return LCUP_INVALID_COOKIE;
	}
#endif

	ber_dupbv( &op->o_sync_state, &cookie );

	(void) ber_free( ber, 1 );

	op->o_sync_mode = (char) mode;

	op->o_sync = ctrl->ldctl_iscritical
		? SLAP_CRITICAL_CONTROL
		: SLAP_NONCRITICAL_CONTROL;

	return LDAP_SUCCESS;
}
#endif

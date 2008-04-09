/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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

#include "slap.h"

#include "../../libraries/liblber/lber-int.h"

static SLAP_CTRL_PARSE_FN parseAssert;
static SLAP_CTRL_PARSE_FN parsePreRead;
static SLAP_CTRL_PARSE_FN parsePostRead;
static SLAP_CTRL_PARSE_FN parseProxyAuthz;
#ifdef LDAP_DEVEL
static SLAP_CTRL_PARSE_FN parseDontUseCopy;
static SLAP_CTRL_PARSE_FN parseManageDIT;
#endif
static SLAP_CTRL_PARSE_FN parseManageDSAit;
static SLAP_CTRL_PARSE_FN parseNoOp;
static SLAP_CTRL_PARSE_FN parsePagedResults;
#ifdef LDAP_DEVEL
static SLAP_CTRL_PARSE_FN parseSortedResults;
#endif
static SLAP_CTRL_PARSE_FN parseValuesReturnFilter;
static SLAP_CTRL_PARSE_FN parsePermissiveModify;
static SLAP_CTRL_PARSE_FN parseDomainScope;
#ifdef SLAP_CONTROL_X_TREE_DELETE
static SLAP_CTRL_PARSE_FN parseTreeDelete;
#endif
static SLAP_CTRL_PARSE_FN parseSearchOptions;
static SLAP_CTRL_PARSE_FN parseSubentries;

#undef sc_mask /* avoid conflict with Irix 6.5 <sys/signal.h> */

const struct berval slap_pre_read_bv = BER_BVC(LDAP_CONTROL_PRE_READ);
const struct berval slap_post_read_bv = BER_BVC(LDAP_CONTROL_POST_READ);

struct slap_control_ids slap_cids;

struct slap_control {
	/* Control OID */
	char *sc_oid;

	/* The controlID for this control */
	int sc_cid;

	/* Operations supported by control */
	slap_mask_t sc_mask;

	/* Extended operations supported by control */
	char **sc_extendedops;

	/* Control parsing callback */
	SLAP_CTRL_PARSE_FN *sc_parse;

	LDAP_SLIST_ENTRY(slap_control) sc_next;
};

static LDAP_SLIST_HEAD(ControlsList, slap_control) controls_list
	= LDAP_SLIST_HEAD_INITIALIZER(&controls_list);

/*
 * all known request control OIDs should be added to this list
 */
/*
 * NOTE: initialize num_known_controls to 1 so that cid = 0 always
 * addresses an undefined control; this allows to safely test for 
 * well known controls even if they are not registered, e.g. if 
 * they get moved to modules.  An example is sc_LDAPsync, which 
 * is implemented in the syncprov overlay and thus, if configured 
 * as dynamic module, may not be registered.  One side effect is that 
 * slap_known_controls[0] == NULL, so it should always be used 
 * starting from 1.
 * FIXME: should we define the "undefined control" oid?
 */
char *slap_known_controls[SLAP_MAX_CIDS+1];
static int num_known_controls = 1;

static char *proxy_authz_extops[] = {
	LDAP_EXOP_MODIFY_PASSWD,
	LDAP_EXOP_X_WHO_AM_I,
	NULL
};

static struct slap_control control_defs[] = {
	{  LDAP_CONTROL_ASSERT,
 		(int)offsetof(struct slap_control_ids, sc_assert),
		SLAP_CTRL_DELETE|SLAP_CTRL_MODIFY|SLAP_CTRL_RENAME|
			SLAP_CTRL_COMPARE|SLAP_CTRL_SEARCH, NULL,
		parseAssert, LDAP_SLIST_ENTRY_INITIALIZER(next) },
	{ LDAP_CONTROL_PRE_READ,
 		(int)offsetof(struct slap_control_ids, sc_preRead),
		SLAP_CTRL_DELETE|SLAP_CTRL_MODIFY|SLAP_CTRL_RENAME, NULL,
		parsePreRead, LDAP_SLIST_ENTRY_INITIALIZER(next) },
	{ LDAP_CONTROL_POST_READ,
 		(int)offsetof(struct slap_control_ids, sc_postRead),
		SLAP_CTRL_ADD|SLAP_CTRL_MODIFY|SLAP_CTRL_RENAME, NULL,
		parsePostRead, LDAP_SLIST_ENTRY_INITIALIZER(next) },
 	{ LDAP_CONTROL_VALUESRETURNFILTER,
 		(int)offsetof(struct slap_control_ids, sc_valuesReturnFilter),
 		SLAP_CTRL_GLOBAL|SLAP_CTRL_SEARCH, NULL,
		parseValuesReturnFilter, LDAP_SLIST_ENTRY_INITIALIZER(next) },
#ifdef LDAP_CONTROL_X_VALUESRETURNFILTER
 	{ LDAP_CONTROL_X_VALUESRETURNFILTER,
 		(int)offsetof(struct slap_control_ids, sc_valuesReturnFilter),
 		SLAP_CTRL_GLOBAL|SLAP_CTRL_SEARCH, NULL,
		parseValuesReturnFilter, LDAP_SLIST_ENTRY_INITIALIZER(next) },
#endif
	{ LDAP_CONTROL_PAGEDRESULTS,
 		(int)offsetof(struct slap_control_ids, sc_pagedResults),
		SLAP_CTRL_SEARCH, NULL,
		parsePagedResults, LDAP_SLIST_ENTRY_INITIALIZER(next) },
#ifdef LDAP_DEVEL
	{ LDAP_CONTROL_SORTREQUEST,
 		(int)offsetof(struct slap_control_ids, sc_sortedResults),
		SLAP_CTRL_GLOBAL|SLAP_CTRL_SEARCH|SLAP_CTRL_HIDE, NULL,
		parseSortedResults, LDAP_SLIST_ENTRY_INITIALIZER(next) },
#endif
	{ LDAP_CONTROL_X_DOMAIN_SCOPE,
 		(int)offsetof(struct slap_control_ids, sc_domainScope),
		SLAP_CTRL_GLOBAL|SLAP_CTRL_SEARCH|SLAP_CTRL_HIDE, NULL,
		parseDomainScope, LDAP_SLIST_ENTRY_INITIALIZER(next) },
	{ LDAP_CONTROL_X_PERMISSIVE_MODIFY,
 		(int)offsetof(struct slap_control_ids, sc_permissiveModify),
		SLAP_CTRL_MODIFY|SLAP_CTRL_HIDE, NULL,
		parsePermissiveModify, LDAP_SLIST_ENTRY_INITIALIZER(next) },
#ifdef SLAP_CONTROL_X_TREE_DELETE
	{ LDAP_CONTROL_X_TREE_DELETE,
 		(int)offsetof(struct slap_control_ids, sc_treeDelete),
		SLAP_CTRL_DELETE|SLAP_CTRL_HIDE, NULL,
		parseTreeDelete, LDAP_SLIST_ENTRY_INITIALIZER(next) },
#endif
	{ LDAP_CONTROL_X_SEARCH_OPTIONS,
 		(int)offsetof(struct slap_control_ids, sc_searchOptions),
		SLAP_CTRL_GLOBAL|SLAP_CTRL_SEARCH|SLAP_CTRL_HIDE, NULL,
		parseSearchOptions, LDAP_SLIST_ENTRY_INITIALIZER(next) },
	{ LDAP_CONTROL_SUBENTRIES,
 		(int)offsetof(struct slap_control_ids, sc_subentries),
		SLAP_CTRL_SEARCH, NULL,
		parseSubentries, LDAP_SLIST_ENTRY_INITIALIZER(next) },
	{ LDAP_CONTROL_NOOP,
 		(int)offsetof(struct slap_control_ids, sc_noOp),
		SLAP_CTRL_ACCESS|SLAP_CTRL_HIDE, NULL,
		parseNoOp, LDAP_SLIST_ENTRY_INITIALIZER(next) },
#ifdef LDAP_DEVEL
	{ LDAP_CONTROL_DONTUSECOPY,
 		(int)offsetof(struct slap_control_ids, sc_dontUseCopy),
		SLAP_CTRL_INTROGATE|SLAP_CTRL_HIDE, NULL,
		parseDontUseCopy, LDAP_SLIST_ENTRY_INITIALIZER(next) },
	{ LDAP_CONTROL_MANAGEDIT,
 		(int)offsetof(struct slap_control_ids, sc_manageDIT),
		SLAP_CTRL_GLOBAL|SLAP_CTRL_UPDATE|SLAP_CTRL_HIDE, NULL,
		parseManageDIT, LDAP_SLIST_ENTRY_INITIALIZER(next) },
#endif
	{ LDAP_CONTROL_MANAGEDSAIT,
 		(int)offsetof(struct slap_control_ids, sc_manageDSAit),
		SLAP_CTRL_ACCESS, NULL,
		parseManageDSAit, LDAP_SLIST_ENTRY_INITIALIZER(next) },
	{ LDAP_CONTROL_PROXY_AUTHZ,
 		(int)offsetof(struct slap_control_ids, sc_proxyAuthz),
		SLAP_CTRL_GLOBAL|SLAP_CTRL_ACCESS, proxy_authz_extops,
		parseProxyAuthz, LDAP_SLIST_ENTRY_INITIALIZER(next) },
	{ NULL, 0, 0, NULL, 0, LDAP_SLIST_ENTRY_INITIALIZER(next) }
};

/*
 * Register a supported control.
 *
 * This can be called by an OpenLDAP plugin or, indirectly, by a
 * SLAPI plugin calling slapi_register_supported_control().
 */
int
register_supported_control(const char *controloid,
	slap_mask_t controlmask,
	char **controlexops,
	SLAP_CTRL_PARSE_FN *controlparsefn,
	int *controlcid)
{
	struct slap_control *sc;
	int i;

	if ( num_known_controls >= SLAP_MAX_CIDS ) {
		Debug( LDAP_DEBUG_ANY, "Too many controls registered."
			" Recompile slapd with SLAP_MAX_CIDS defined > %d\n",
		SLAP_MAX_CIDS, 0, 0 );
		return LDAP_OTHER;
	}

	if ( controloid == NULL ) return LDAP_PARAM_ERROR;

	/* sanity check - should never happen */
	for ( i = 0; slap_known_controls[ i ]; i++ ) {
		if ( strcmp( controloid, slap_known_controls[ i ] ) == 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"Control %s already registered.\n",
				controloid, 0, 0 );
			return LDAP_PARAM_ERROR;
		}
	}

	sc = (struct slap_control *)SLAP_MALLOC( sizeof( *sc ) );
	if ( sc == NULL ) return LDAP_NO_MEMORY;

	sc->sc_oid = ch_strdup( controloid );
	sc->sc_mask = controlmask;
	if ( controlexops != NULL ) {
		sc->sc_extendedops = ldap_charray_dup( controlexops );
		if ( sc->sc_extendedops == NULL ) {
			ch_free( sc );
			return LDAP_NO_MEMORY;
		}
	} else {
		sc->sc_extendedops = NULL;
	}
	sc->sc_parse = controlparsefn;

	if ( controlcid ) *controlcid = num_known_controls;
	sc->sc_cid = num_known_controls;

	/* Update slap_known_controls, too. */
	slap_known_controls[num_known_controls-1] = sc->sc_oid;
	slap_known_controls[num_known_controls++] = NULL;

	LDAP_SLIST_NEXT( sc, sc_next ) = NULL;
	LDAP_SLIST_INSERT_HEAD( &controls_list, sc, sc_next );
	return LDAP_SUCCESS;
}

/*
 * One-time initialization of internal controls.
 */
int
slap_controls_init( void )
{
	int i, rc;

	rc = LDAP_SUCCESS;

	for ( i = 0; control_defs[i].sc_oid != NULL; i++ ) {
		int *cid = (int *)(((char *)&slap_cids) + control_defs[i].sc_cid );
		rc = register_supported_control( control_defs[i].sc_oid,
			control_defs[i].sc_mask, control_defs[i].sc_extendedops,
			control_defs[i].sc_parse, cid );
		if ( rc != LDAP_SUCCESS ) break;
	}

	return rc;
}

/*
 * Free memory associated with list of supported controls.
 */
void
controls_destroy( void )
{
	struct slap_control *sc;

	while ( !LDAP_SLIST_EMPTY(&controls_list) ) {
		sc = LDAP_SLIST_FIRST(&controls_list);
		LDAP_SLIST_REMOVE_HEAD(&controls_list, sc_next);

		ch_free( sc->sc_oid );
		if ( sc->sc_extendedops != NULL ) {
			ldap_charray_free( sc->sc_extendedops );
		}
		ch_free( sc );
	}
}

/*
 * Format the supportedControl attribute of the root DSE,
 * detailing which controls are supported by the directory
 * server.
 */
int
controls_root_dse_info( Entry *e )
{
	AttributeDescription *ad_supportedControl
		= slap_schema.si_ad_supportedControl;
	struct berval vals[2];
	struct slap_control *sc;

	vals[1].bv_val = NULL;
	vals[1].bv_len = 0;

	LDAP_SLIST_FOREACH( sc, &controls_list, sc_next ) {
		if( sc->sc_mask & SLAP_CTRL_HIDE ) continue;

		vals[0].bv_val = sc->sc_oid;
		vals[0].bv_len = strlen( sc->sc_oid );

		if ( attr_merge( e, ad_supportedControl, vals, NULL ) ) {
			return -1;
		}
	}

	return 0;
}

/*
 * Return a list of OIDs and operation masks for supported
 * controls. Used by SLAPI.
 */
int
get_supported_controls(char ***ctrloidsp,
	slap_mask_t **ctrlmasks)
{
	int n;
	char **oids;
	slap_mask_t *masks;
	struct slap_control *sc;

	n = 0;

	LDAP_SLIST_FOREACH( sc, &controls_list, sc_next ) {
		n++;
	}

	if ( n == 0 ) {
		*ctrloidsp = NULL;
		*ctrlmasks = NULL;
		return LDAP_SUCCESS;
	}

	oids = (char **)SLAP_MALLOC( (n + 1) * sizeof(char *) );
	if ( oids == NULL ) {
		return LDAP_NO_MEMORY;
	}
	masks = (slap_mask_t *)SLAP_MALLOC( (n + 1) * sizeof(slap_mask_t) );
	if  ( masks == NULL ) {
		ch_free( oids );
		return LDAP_NO_MEMORY;
	}

	n = 0;

	LDAP_SLIST_FOREACH( sc, &controls_list, sc_next ) {
		oids[n] = ch_strdup( sc->sc_oid );
		masks[n] = sc->sc_mask;
		n++;
	}
	oids[n] = NULL;
	masks[n] = 0;

	*ctrloidsp = oids;
	*ctrlmasks = masks;

	return LDAP_SUCCESS;
}

/*
 * Find a control given its OID.
 */
static struct slap_control *
find_ctrl( const char *oid )
{
	struct slap_control *sc;

	LDAP_SLIST_FOREACH( sc, &controls_list, sc_next ) {
		if ( strcmp( oid, sc->sc_oid ) == 0 ) {
			return sc;
		}
	}

	return NULL;
}

int
slap_find_control_id(
	const char *oid,
	int *cid )
{
	struct slap_control *ctrl = find_ctrl( oid );
	if ( ctrl ) {
		if ( cid ) *cid = ctrl->sc_cid;
		return LDAP_SUCCESS;
	}
	return LDAP_CONTROL_NOT_FOUND;
}

int
slap_global_control( Operation *op, const char *oid, int *cid )
{
	struct slap_control *ctrl = find_ctrl( oid );

	if ( ctrl == NULL ) {
		/* should not be reachable */
		Debug( LDAP_DEBUG_ANY,
			"slap_global_control: unrecognized control: %s\n",      
			oid, 0, 0 );
		return LDAP_CONTROL_NOT_FOUND;
	}

	if ( cid ) *cid = ctrl->sc_cid;

	if ( ( ctrl->sc_mask & SLAP_CTRL_GLOBAL ) ||
		( ( op->o_tag & LDAP_REQ_SEARCH ) &&
		( ctrl->sc_mask & SLAP_CTRL_GLOBAL_SEARCH ) ) )
	{
		return LDAP_COMPARE_TRUE;
	}

	Debug( LDAP_DEBUG_TRACE,
		"slap_global_control: unavailable control: %s\n",      
		oid, 0, 0 );

	return LDAP_COMPARE_FALSE;
}

void slap_free_ctrls(
	Operation *op,
	LDAPControl **ctrls )
{
	int i;

	for (i=0; ctrls[i]; i++) {
		op->o_tmpfree(ctrls[i], op->o_tmpmemctx );
	}
	op->o_tmpfree( ctrls, op->o_tmpmemctx );
}

int slap_parse_ctrl(
	Operation *op,
	SlapReply *rs,
	LDAPControl *control,
	const char **text )
{
	struct slap_control *sc;

	sc = find_ctrl( control->ldctl_oid );
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
			assert( op->ore_reqoid.bv_val != NULL );
			if( sc->sc_extendedops != NULL ) {
				int i;
				for( i=0; sc->sc_extendedops[i] != NULL; i++ ) {
					if( strcmp( op->ore_reqoid.bv_val,
						sc->sc_extendedops[i] ) == 0 )
					{
						tagmask=0L;
						break;
					}
				}
			}
			break;
		default:
			*text = "controls internal error";
			return LDAP_OTHER;
		}

		if (( sc->sc_mask & tagmask ) == tagmask ) {
			/* available extension */
			int	rc;

			if( !sc->sc_parse ) {
				*text = "not yet implemented";
				return LDAP_OTHER;
			}

			rc = sc->sc_parse( op, rs, control );
			if ( rc ) {
				assert( rc != LDAP_UNAVAILABLE_CRITICAL_EXTENSION );
				return rc;
			}

		} else if( control->ldctl_iscritical ) {
			/* unavailable CRITICAL control */
			*text = "critical extension is unavailable";
			return LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
		}
	} else if( control->ldctl_iscritical ) {
		/* unrecognized CRITICAL control */
		*text = "critical extension is not recognized";
		return LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
	}

	return LDAP_SUCCESS;
}

int get_ctrls(
	Operation *op,
	SlapReply *rs,
	int sendres )
{
	int nctrls = 0;
	ber_tag_t tag;
	ber_len_t len;
	char *opaque;
	BerElement *ber = op->o_ber;
	struct berval bv;

	len = ber_pvt_ber_remaining(ber);

	if( len == 0) {
		/* no controls */
		rs->sr_err = LDAP_SUCCESS;
		return rs->sr_err;
	}

	if(( tag = ber_peek_tag( ber, &len )) != LDAP_TAG_CONTROLS ) {
		if( tag == LBER_ERROR ) {
			rs->sr_err = SLAPD_DISCONNECT;
			rs->sr_text = "unexpected data in PDU";
		}

		goto return_results;
	}

	Debug( LDAP_DEBUG_TRACE,
		"=> get_ctrls\n", 0, 0, 0 );

	if( op->o_protocol < LDAP_VERSION3 ) {
		rs->sr_err = SLAPD_DISCONNECT;
		rs->sr_text = "controls require LDAPv3";
		goto return_results;
	}

	/* one for first control, one for termination */
	op->o_ctrls = op->o_tmpalloc( 2 * sizeof(LDAPControl *), op->o_tmpmemctx );

#if 0
	if( op->ctrls == NULL ) {
		rs->sr_err = LDAP_NO_MEMORY;
		rs->sr_text = "no memory";
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

		c = op->o_tmpalloc( sizeof(LDAPControl), op->o_tmpmemctx );
		memset(c, 0, sizeof(LDAPControl));

		/* allocate pointer space for current controls (nctrls)
		 * + this control + extra NULL
		 */
		tctrls = op->o_tmprealloc( op->o_ctrls,
			(nctrls+2) * sizeof(LDAPControl *), op->o_tmpmemctx );

#if 0
		if( tctrls == NULL ) {
			ch_free( c );
			ldap_controls_free(op->o_ctrls);
			op->o_ctrls = NULL;

			rs->sr_err = LDAP_NO_MEMORY;
			rs->sr_text = "no memory";
			goto return_results;
		}
#endif
		op->o_ctrls = tctrls;

		op->o_ctrls[nctrls++] = c;
		op->o_ctrls[nctrls] = NULL;

		tag = ber_scanf( ber, "{m" /*}*/, &bv );
		c->ldctl_oid = bv.bv_val;

		if( tag == LBER_ERROR ) {
			Debug( LDAP_DEBUG_TRACE, "=> get_ctrls: get oid failed.\n",
				0, 0, 0 );

			slap_free_ctrls( op, op->o_ctrls );
			op->o_ctrls = NULL;
			rs->sr_err = SLAPD_DISCONNECT;
			rs->sr_text = "decoding controls error";
			goto return_results;

		} else if( c->ldctl_oid == NULL ) {
			Debug( LDAP_DEBUG_TRACE,
				"get_ctrls: conn %lu got emtpy OID.\n",
				op->o_connid, 0, 0 );

			slap_free_ctrls( op, op->o_ctrls );
			op->o_ctrls = NULL;
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			rs->sr_text = "OID field is empty";
			goto return_results;
		}

		tag = ber_peek_tag( ber, &len );

		if( tag == LBER_BOOLEAN ) {
			ber_int_t crit;
			tag = ber_scanf( ber, "b", &crit );

			if( tag == LBER_ERROR ) {
				Debug( LDAP_DEBUG_TRACE, "=> get_ctrls: get crit failed.\n",
					0, 0, 0 );
				slap_free_ctrls( op, op->o_ctrls );
				op->o_ctrls = NULL;
				rs->sr_err = SLAPD_DISCONNECT;
				rs->sr_text = "decoding controls error";
				goto return_results;
			}

			c->ldctl_iscritical = (crit != 0);
			tag = ber_peek_tag( ber, &len );
		}

		if( tag == LBER_OCTETSTRING ) {
			tag = ber_scanf( ber, "m", &c->ldctl_value );

			if( tag == LBER_ERROR ) {
				Debug( LDAP_DEBUG_TRACE, "=> get_ctrls: conn %lu: "
					"%s (%scritical): get value failed.\n",
					op->o_connid, c->ldctl_oid,
					c->ldctl_iscritical ? "" : "non" );
				slap_free_ctrls( op, op->o_ctrls );
				op->o_ctrls = NULL;
				rs->sr_err = SLAPD_DISCONNECT;
				rs->sr_text = "decoding controls error";
				goto return_results;
			}
		}

		Debug( LDAP_DEBUG_TRACE,
			"=> get_ctrls: oid=\"%s\" (%scritical)\n",
			c->ldctl_oid, c->ldctl_iscritical ? "" : "non", 0 );

		rs->sr_err = slap_parse_ctrl( op, rs, c, &rs->sr_text );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			goto return_results;
		}
	}

return_results:
	Debug( LDAP_DEBUG_TRACE,
		"<= get_ctrls: n=%d rc=%d err=\"%s\"\n",
		nctrls, rs->sr_err, rs->sr_text ? rs->sr_text : "");

	if( sendres && rs->sr_err != LDAP_SUCCESS ) {
		if( rs->sr_err == SLAPD_DISCONNECT ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			send_ldap_disconnect( op, rs );
			rs->sr_err = SLAPD_DISCONNECT;
		} else {
			send_ldap_result( op, rs );
		}
	}

	return rs->sr_err;
}

int
slap_remove_control(
	Operation	*op,
	SlapReply	*rs,
	int		ctrl,
	BI_chk_controls	fnc )
{
	int		i, j;

	switch ( op->o_ctrlflag[ ctrl ] ) {
	case SLAP_CONTROL_NONCRITICAL:
		for ( i = 0, j = -1; op->o_ctrls[ i ] != NULL; i++ ) {
			if ( strcmp( op->o_ctrls[ i ]->ldctl_oid,
				slap_known_controls[ ctrl - 1 ] ) == 0 )
			{
				j = i;
			}
		}

		if ( j == -1 ) {
			rs->sr_err = LDAP_OTHER;
			break;
		}

		if ( fnc ) {
			(void)fnc( op, rs );
		}

		op->o_tmpfree( op->o_ctrls[ j ], op->o_tmpmemctx );

		if ( i > 1 ) {
			AC_MEMCPY( &op->o_ctrls[ j ], &op->o_ctrls[ j + 1 ],
				( i - j ) * sizeof( LDAPControl * ) );

		} else {
			op->o_tmpfree( op->o_ctrls, op->o_tmpmemctx );
			op->o_ctrls = NULL;
		}

		op->o_ctrlflag[ ctrl ] = SLAP_CONTROL_IGNORED;

		Debug( LDAP_DEBUG_ANY, "%s: "
			"non-critical control \"%s\" not supported; stripped.\n",
			op->o_log_prefix, slap_known_controls[ ctrl ], 0 );
		/* fall thru */

	case SLAP_CONTROL_IGNORED:
	case SLAP_CONTROL_NONE:
		rs->sr_err = SLAP_CB_CONTINUE;
		break;

	case SLAP_CONTROL_CRITICAL:
		rs->sr_err = LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
		if ( fnc ) {
			(void)fnc( op, rs );
		}
		Debug( LDAP_DEBUG_ANY, "%s: "
			"critical control \"%s\" not supported.\n",
			op->o_log_prefix, slap_known_controls[ ctrl ], 0 );
		break;

	default:
		/* handle all cases! */
		assert( 0 );
	}

	return rs->sr_err;
}

#ifdef LDAP_DEVEL
static int parseDontUseCopy (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	if ( op->o_dontUseCopy != SLAP_CONTROL_NONE ) {
		rs->sr_text = "dontUseCopy control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		rs->sr_text = "dontUseCopy control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_iscritical != SLAP_CONTROL_CRITICAL ) {
		rs->sr_text = "dontUseCopy criticality of FALSE not allowed";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_dontUseCopy = SLAP_CONTROL_CRITICAL;
	return LDAP_SUCCESS;
}

static int parseManageDIT (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	if ( op->o_managedit != SLAP_CONTROL_NONE ) {
		rs->sr_text = "manageDIT control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		rs->sr_text = "manageDIT control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_managedit = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	return LDAP_SUCCESS;
}
#endif

static int parseManageDSAit (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	if ( op->o_managedsait != SLAP_CONTROL_NONE ) {
		rs->sr_text = "manageDSAit control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		rs->sr_text = "manageDSAit control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_managedsait = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	return LDAP_SUCCESS;
}

static int parseProxyAuthz (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	int		rc;
	struct berval	dn = BER_BVNULL;

	if ( op->o_proxy_authz != SLAP_CONTROL_NONE ) {
		rs->sr_text = "proxy authorization control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( BER_BVISEMPTY( &op->o_ndn ) ) {
		rs->sr_text = "anonymous proxyAuthz not allowed";
		return LDAP_PROXY_AUTHZ_FAILURE;
	}

	op->o_proxy_authz = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	Debug( LDAP_DEBUG_ARGS,
		"parseProxyAuthz: conn %lu authzid=\"%s\"\n", 
		op->o_connid,
		ctrl->ldctl_value.bv_len ?  ctrl->ldctl_value.bv_val : "anonymous",
		0 );

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"parseProxyAuthz: conn=%lu anonymous\n", 
			op->o_connid, 0, 0 );

		/* anonymous */
		if ( !BER_BVISNULL( &op->o_ndn ) ) {
			op->o_ndn.bv_val[ 0 ] = '\0';
		}
		op->o_ndn.bv_len = 0;

		if ( !BER_BVISNULL( &op->o_dn ) ) {
			op->o_dn.bv_val[ 0 ] = '\0';
		}
		op->o_dn.bv_len = 0;

		return LDAP_SUCCESS;
	}

	rc = slap_sasl_getdn( op->o_conn, op, &ctrl->ldctl_value,
			NULL, &dn, SLAP_GETDN_AUTHZID );

	/* FIXME: empty DN in proxyAuthz control should be legal... */
	if( rc != LDAP_SUCCESS /* || !dn.bv_len */ ) {
		if ( dn.bv_val ) {
			ch_free( dn.bv_val );
		}
		rs->sr_text = "authzId mapping failed";
		return LDAP_PROXY_AUTHZ_FAILURE;
	}

	Debug( LDAP_DEBUG_TRACE,
		"parseProxyAuthz: conn=%lu \"%s\"\n", 
		op->o_connid,
		dn.bv_len ? dn.bv_val : "(NULL)", 0 );

	rc = slap_sasl_authorized( op, &op->o_ndn, &dn );

	if ( rc ) {
		ch_free( dn.bv_val );
		rs->sr_text = "not authorized to assume identity";
		return LDAP_PROXY_AUTHZ_FAILURE;
	}

	ch_free( op->o_ndn.bv_val );
	ch_free( op->o_dn.bv_val );

	/*
	 * NOTE: since slap_sasl_getdn() returns a normalized dn,
	 * from now on op->o_dn is normalized
	 */
	op->o_ndn = dn;
	ber_dupbv( &op->o_dn, &dn );

	Statslog( LDAP_DEBUG_STATS, "%s PROXYAUTHZ dn=\"%s\"\n",
	    op->o_log_prefix, dn.bv_val, 0, 0, 0 );

	return LDAP_SUCCESS;
}

static int parseNoOp (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	if ( op->o_noop != SLAP_CONTROL_NONE ) {
		rs->sr_text = "noop control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		rs->sr_text = "noop control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_noop = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	return LDAP_SUCCESS;
}

static int parsePagedResults (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	int		rc = LDAP_SUCCESS;
	ber_tag_t	tag;
	ber_int_t	size;
	BerElement	*ber;
	struct berval	cookie = BER_BVNULL;
	PagedResultsState	*ps;

	if ( op->o_pagedresults != SLAP_CONTROL_NONE ) {
		rs->sr_text = "paged results control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( BER_BVISEMPTY( &ctrl->ldctl_value ) ) {
		rs->sr_text = "paged results control value is empty (or absent)";
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
	if ( ber == NULL ) {
		rs->sr_text = "internal error";
		return LDAP_OTHER;
	}

	tag = ber_scanf( ber, "{im}", &size, &cookie );

	if ( tag == LBER_ERROR ) {
		rs->sr_text = "paged results control could not be decoded";
		rc = LDAP_PROTOCOL_ERROR;
		goto done;
	}

	if ( size < 0 ) {
		rs->sr_text = "paged results control size invalid";
		rc = LDAP_PROTOCOL_ERROR;
		goto done;
	}

	ps = op->o_tmpalloc( sizeof(PagedResultsState), op->o_tmpmemctx );
	*ps = op->o_conn->c_pagedresults_state;
	ps->ps_size = size;
	op->o_pagedresults_state = ps;
	if ( !cookie.bv_len ) {
		ps->ps_count = 0;
		ps->ps_cookie = 0;
	}

	/* NOTE: according to RFC 2696 3.:

    If the page size is greater than or equal to the sizeLimit value, the
    server should ignore the control as the request can be satisfied in a
    single page.
	 
	 * NOTE: this assumes that the op->ors_slimit be set
	 * before the controls are parsed.     
	 */
		
	if ( op->ors_slimit > 0 && size >= op->ors_slimit ) {
		op->o_pagedresults = SLAP_CONTROL_IGNORED;

	} else if ( ctrl->ldctl_iscritical ) {
		op->o_pagedresults = SLAP_CONTROL_CRITICAL;

	} else {
		op->o_pagedresults = SLAP_CONTROL_NONCRITICAL;
	}

done:;
	(void)ber_free( ber, 1 );
	return rc;
}

#ifdef LDAP_DEVEL
static int parseSortedResults (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	int		rc = LDAP_SUCCESS;

	if ( op->o_sortedresults != SLAP_CONTROL_NONE ) {
		rs->sr_text = "sorted results control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( BER_BVISEMPTY( &ctrl->ldctl_value ) ) {
		rs->sr_text = "sorted results control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	/* blow off parsing the value */

	op->o_sortedresults = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	return rc;
}
#endif

static int parseAssert (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	BerElement	*ber;
	struct berval	fstr = BER_BVNULL;

	if ( op->o_assert != SLAP_CONTROL_NONE ) {
		rs->sr_text = "assert control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		rs->sr_text = "assert control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	ber = ber_init( &(ctrl->ldctl_value) );
	if (ber == NULL) {
		rs->sr_text = "assert control: internal error";
		return LDAP_OTHER;
	}
	
	rs->sr_err = get_filter( op, ber, (Filter **)&(op->o_assertion),
		&rs->sr_text);
	if( rs->sr_err != LDAP_SUCCESS ) {
		if( rs->sr_err == SLAPD_DISCONNECT ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			send_ldap_disconnect( op, rs );
			rs->sr_err = SLAPD_DISCONNECT;
		} else {
			send_ldap_result( op, rs );
		}
		if( op->o_assertion != NULL ) {
			filter_free_x( op, op->o_assertion );
		}
		return rs->sr_err;
	}

#ifdef LDAP_DEBUG
	filter2bv_x( op, op->o_assertion, &fstr );

	Debug( LDAP_DEBUG_ARGS, "parseAssert: conn %ld assert: %s\n",
		op->o_connid, fstr.bv_len ? fstr.bv_val : "empty" , 0 );
	op->o_tmpfree( fstr.bv_val, op->o_tmpmemctx );
#endif

	op->o_assert = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	rs->sr_err = LDAP_SUCCESS;
	return LDAP_SUCCESS;
}

static int parsePreRead (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	ber_len_t siz, off, i;
	AttributeName *an = NULL;
	BerElement	*ber;

	if ( op->o_preread != SLAP_CONTROL_NONE ) {
		rs->sr_text = "preread control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		rs->sr_text = "preread control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	ber = ber_init( &(ctrl->ldctl_value) );
	if (ber == NULL) {
		rs->sr_text = "preread control: internal error";
		return LDAP_OTHER;
	}

	siz = sizeof( AttributeName );
	off = offsetof( AttributeName, an_name );
	if ( ber_scanf( ber, "{M}", &an, &siz, off ) == LBER_ERROR ) {
		rs->sr_text = "preread control: decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	for( i=0; i<siz; i++ ) {
		int		rc = LDAP_SUCCESS;
		const char	*dummy = NULL;

		an[i].an_desc = NULL;
		an[i].an_oc = NULL;
		an[i].an_oc_exclude = 0;
		rc = slap_bv2ad( &an[i].an_name, &an[i].an_desc, &dummy );
		if ( rc != LDAP_SUCCESS && ctrl->ldctl_iscritical ) {
			rs->sr_text = dummy
				? dummy
				: "postread control: unknown attributeType";
			return rc;
		}
	}

	op->o_preread = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	op->o_preread_attrs = an;

	rs->sr_err = LDAP_SUCCESS;
	return LDAP_SUCCESS;
}

static int parsePostRead (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	ber_len_t siz, off, i;
	AttributeName *an = NULL;
	BerElement	*ber;

	if ( op->o_postread != SLAP_CONTROL_NONE ) {
		rs->sr_text = "postread control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		rs->sr_text = "postread control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	ber = ber_init( &(ctrl->ldctl_value) );
	if (ber == NULL) {
		rs->sr_text = "postread control: internal error";
		return LDAP_OTHER;
	}

	siz = sizeof( AttributeName );
	off = offsetof( AttributeName, an_name );
	if ( ber_scanf( ber, "{M}", &an, &siz, off ) == LBER_ERROR ) {
		rs->sr_text = "postread control: decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	for( i=0; i<siz; i++ ) {
		int		rc = LDAP_SUCCESS;
		const char	*dummy = NULL;

		an[i].an_desc = NULL;
		an[i].an_oc = NULL;
		an[i].an_oc_exclude = 0;
		rc = slap_bv2ad( &an[i].an_name, &an[i].an_desc, &dummy );
		if ( rc != LDAP_SUCCESS && ctrl->ldctl_iscritical ) {
			rs->sr_text = dummy
				? dummy
				: "postread control: unknown attributeType";
			return rc;
		}
	}

	op->o_postread = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	op->o_postread_attrs = an;

	rs->sr_err = LDAP_SUCCESS;
	return LDAP_SUCCESS;
}

static int parseValuesReturnFilter (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	BerElement	*ber;
	struct berval	fstr = BER_BVNULL;

	if ( op->o_valuesreturnfilter != SLAP_CONTROL_NONE ) {
		rs->sr_text = "valuesReturnFilter control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		rs->sr_text = "valuesReturnFilter control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	ber = ber_init( &(ctrl->ldctl_value) );
	if (ber == NULL) {
		rs->sr_text = "internal error";
		return LDAP_OTHER;
	}
	
	rs->sr_err = get_vrFilter( op, ber,
		(ValuesReturnFilter **)&(op->o_vrFilter), &rs->sr_text);

	(void) ber_free( ber, 1 );

	if( rs->sr_err != LDAP_SUCCESS ) {
		if( rs->sr_err == SLAPD_DISCONNECT ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			send_ldap_disconnect( op, rs );
			rs->sr_err = SLAPD_DISCONNECT;
		} else {
			send_ldap_result( op, rs );
		}
		if( op->o_vrFilter != NULL) vrFilter_free( op, op->o_vrFilter ); 
	}
#ifdef LDAP_DEBUG
	else {
		vrFilter2bv( op, op->o_vrFilter, &fstr );
	}

	Debug( LDAP_DEBUG_ARGS, "	vrFilter: %s\n",
		fstr.bv_len ? fstr.bv_val : "empty", 0, 0 );
	op->o_tmpfree( fstr.bv_val, op->o_tmpmemctx );
#endif

	op->o_valuesreturnfilter = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	rs->sr_err = LDAP_SUCCESS;
	return LDAP_SUCCESS;
}

static int parseSubentries (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	if ( op->o_subentries != SLAP_CONTROL_NONE ) {
		rs->sr_text = "subentries control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	/* FIXME: should use BER library */
	if( ( ctrl->ldctl_value.bv_len != 3 )
		|| ( ctrl->ldctl_value.bv_val[0] != 0x01 )
		|| ( ctrl->ldctl_value.bv_val[1] != 0x01 ))
	{
		rs->sr_text = "subentries control value encoding is bogus";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_subentries = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	if (ctrl->ldctl_value.bv_val[2]) {
		set_subentries_visibility( op );
	}

	return LDAP_SUCCESS;
}

static int parsePermissiveModify (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	if ( op->o_permissive_modify != SLAP_CONTROL_NONE ) {
		rs->sr_text = "permissiveModify control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		rs->sr_text = "permissiveModify control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_permissive_modify = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	return LDAP_SUCCESS;
}

static int parseDomainScope (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	if ( op->o_domain_scope != SLAP_CONTROL_NONE ) {
		rs->sr_text = "domainScope control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		rs->sr_text = "domainScope control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_domain_scope = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	return LDAP_SUCCESS;
}

#ifdef SLAP_CONTROL_X_TREE_DELETE
static int parseTreeDelete (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	if ( op->o_tree_delete != SLAP_CONTROL_NONE ) {
		rs->sr_text = "treeDelete control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_len ) {
		rs->sr_text = "treeDelete control value not empty";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_tree_delete = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	return LDAP_SUCCESS;
}
#endif

static int parseSearchOptions (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	BerElement *ber;
	ber_int_t search_flags;
	ber_tag_t tag;

	if ( ctrl->ldctl_value.bv_len == 0 ) {
		rs->sr_text = "searchOptions control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	ber = ber_init( &ctrl->ldctl_value );
	if( ber == NULL ) {
		rs->sr_text = "internal error";
		return LDAP_OTHER;
	}

	if ( (tag = ber_scanf( ber, "{i}", &search_flags )) == LBER_ERROR ) {
		rs->sr_text = "searchOptions control decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	(void) ber_free( ber, 1 );

	if ( search_flags & LDAP_SEARCH_FLAG_DOMAIN_SCOPE ) {
		if ( op->o_domain_scope != SLAP_CONTROL_NONE ) {
			rs->sr_text = "searchOptions control specified multiple times "
				"or with domainScope control";
			return LDAP_PROTOCOL_ERROR;
		}

		op->o_domain_scope = ctrl->ldctl_iscritical
			? SLAP_CONTROL_CRITICAL
			: SLAP_CONTROL_NONCRITICAL;
	}

	if ( search_flags & ~(LDAP_SEARCH_FLAG_DOMAIN_SCOPE) ) {
		/* Other search flags not recognised so far,
		 * including:
		 *		LDAP_SEARCH_FLAG_PHANTOM_ROOM
		 */
		rs->sr_text = "searchOptions contained unrecognized flag";
		return LDAP_UNWILLING_TO_PERFORM;
	}

	return LDAP_SUCCESS;
}


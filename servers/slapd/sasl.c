/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/string.h>

#include <lber.h>
#include <ldap_log.h>

#include "slap.h"

#ifdef HAVE_CYRUS_SASL
#include <limits.h>

#ifdef HAVE_SASL_SASL_H
#include <sasl/sasl.h>
#else
#include <sasl.h>
#endif

#include <lutil.h>
#if SASL_VERSION_MAJOR >= 2
#include <sasl/saslplug.h>
#define	SASL_CONST const
#else
#define	SASL_CONST
#endif

#include <ldap_pvt.h>

/* Flags for telling slap_sasl_getdn() what type of identity is being passed */
#define FLAG_GETDN_AUTHCID 2
#define FLAG_GETDN_AUTHZID 4

static sasl_security_properties_t sasl_secprops;

int slap_sasl_config( int cargc, char **cargv, char *line,
	const char *fname, int lineno )
{
		/* set SASL proxy authorization policy */
		if ( strcasecmp( cargv[0], "sasl-authz-policy" ) == 0 ) {
			if ( cargc != 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d: missing policy in \"sasl-authz-policy <policy>\" line\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing policy in \"sasl-authz-policy <policy>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( slap_sasl_setpolicy( cargv[1] ) ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d: unable "
					   "to parse value \"%s\" "
					   "in \"sasl-authz-policy "
					   "<policy>\" line.\n",
					   fname, lineno, cargv[1] );
#else
				Debug( LDAP_DEBUG_ANY,
				    	"%s: line %d: unable "
					"to parse value \"%s\" "
					"in \"sasl-authz-policy "
					"<policy>\" line\n",
    					fname, lineno, cargv[1] );
#endif
				return( 1 );
			}
			

		/* set SASL host */
		} else if ( strcasecmp( cargv[0], "sasl-host" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d: missing host in \"sasl-host <host>\" line\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing host in \"sasl-host <host>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if ( global_host != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d: already set sasl-host!\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: already set sasl-host!\n",
					fname, lineno, 0 );
#endif

				return 1;

			} else {
				global_host = ch_strdup( cargv[1] );
			}

		/* set SASL realm */
		} else if ( strcasecmp( cargv[0], "sasl-realm" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d: missing realm in \"sasl-realm <realm>\" line.\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing realm in \"sasl-realm <realm>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if ( global_realm != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d: already set sasl-realm!\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: already set sasl-realm!\n",
					fname, lineno, 0 );
#endif

				return 1;

			} else {
				global_realm = ch_strdup( cargv[1] );
			}

		} else if ( !strcasecmp( cargv[0], "sasl-regexp" ) 
			|| !strcasecmp( cargv[0], "saslregexp" ) )
		{
			int rc;
			if ( cargc != 3 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d: need 2 args in "
					   "\"saslregexp <match> <replace>\"\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, 
				"%s: line %d: need 2 args in \"saslregexp <match> <replace>\"\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			rc = slap_sasl_regexp_config( cargv[1], cargv[2] );
			if ( rc ) {
				return rc;
			}

		/* SASL security properties */
		} else if ( strcasecmp( cargv[0], "sasl-secprops" ) == 0 ) {
			char *txt;

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d: missing flags in "
					   "\"sasl-secprops <properties>\" line\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing flags in \"sasl-secprops <properties>\" line\n",
				    fname, lineno, 0 );
#endif

				return 1;
			}

			txt = slap_sasl_secprops( cargv[1] );
			if ( txt != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					   "%s: line %d sasl-secprops: %s\n",
					   fname, lineno, txt );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: sasl-secprops: %s\n",
				    fname, lineno, txt );
#endif

				return 1;
			}
	    }

	    return LDAP_SUCCESS;
}

static int
slap_sasl_log(
	void *context,
	int priority,
	const char *message) 
{
	Connection *conn = context;
	int level;
	const char * label;

	if ( message == NULL ) {
		return SASL_BADPARAM;
	}

	switch (priority) {
#if SASL_VERSION_MAJOR >= 2
	case SASL_LOG_NONE:
		level = LDAP_DEBUG_NONE;
		label = "None";
		break;
	case SASL_LOG_ERR:
		level = LDAP_DEBUG_ANY;
		label = "Error";
		break;
	case SASL_LOG_FAIL:
		level = LDAP_DEBUG_ANY;
		label = "Failure";
		break;
	case SASL_LOG_WARN:
		level = LDAP_DEBUG_TRACE;
		label = "Warning";
		break;
	case SASL_LOG_NOTE:
		level = LDAP_DEBUG_TRACE;
		label = "Notice";
		break;
	case SASL_LOG_DEBUG:
		level = LDAP_DEBUG_TRACE;
		label = "Debug";
		break;
	case SASL_LOG_TRACE:
		level = LDAP_DEBUG_TRACE;
		label = "Trace";
		break;
	case SASL_LOG_PASS:
		level = LDAP_DEBUG_TRACE;
		label = "Password Trace";
		break;
#else
	case SASL_LOG_ERR:
		level = LDAP_DEBUG_ANY;
		label = "Error";
		break;
	case SASL_LOG_WARNING:
		level = LDAP_DEBUG_TRACE;
		label = "Warning";
		break;
	case SASL_LOG_INFO:
		level = LDAP_DEBUG_TRACE;
		label = "Info";
		break;
#endif
	default:
		return SASL_BADPARAM;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"SASL [conn=%ld] %s: %s\n", conn ? conn->c_connid : -1, label, message);
#else
	Debug( level, "SASL [conn=%ld] %s: %s\n",
		conn ? conn->c_connid: -1,
		label, message );
#endif


	return SASL_OK;
}


/* Take any sort of identity string and return a DN with the "dn:" prefix. The
   string returned in *dn is in its own allocated memory, and must be free'd 
   by the calling process.
   -Mark Adamson, Carnegie Mellon

   The "dn:" prefix is no longer used anywhere inside slapd. It is only used
   on strings passed in directly from SASL.
   -Howard Chu, Symas Corp.
*/

#define	SET_DN	1
#define	SET_U	2

static struct berval ext_bv = { sizeof("EXTERNAL")-1, "EXTERNAL" };

int slap_sasl_getdn( Connection *conn, char *id, int len,
	char *user_realm, struct berval *dn, int flags )
{
	char *c1;
	int rc, is_dn = 0, do_norm = 1;
	sasl_conn_t *ctx;
	struct berval dn2;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_getdn: conn %d id=%s\n",
		conn ? conn->c_connid : -1, id ? (*id ? id : "<empty>") : "NULL", 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "slap_sasl_getdn: id=%s\n", 
      id?(*id?id:"<empty>"):"NULL",0,0 );
#endif

	dn->bv_val = NULL;
	dn->bv_len = 0;

	if ( id ) {
		if ( len == 0 ) len = strlen( id );

		/* Blatantly anonymous ID */
		if ( len == sizeof("anonymous") - 1 &&
			!strcasecmp( id, "anonymous" ) ) {
			return( LDAP_SUCCESS );
		}
	} else {
		len = 0;
	}

	ctx = conn->c_sasl_context;

	/* An authcID needs to be converted to authzID form. Set the
	 * values directly into *dn; they will be normalized later. (and
	 * normalizing always makes a new copy.) An ID from a TLS certificate
	 * is already normalized, so copy it and skip normalization.
	 */
	if( flags & FLAG_GETDN_AUTHCID ) {
#ifdef HAVE_TLS
		if( conn->c_is_tls && conn->c_sasl_bind_mech.bv_len == ext_bv.bv_len
			&& ( strcasecmp( ext_bv.bv_val, conn->c_sasl_bind_mech.bv_val ) == 0 ) ) {
			/* X.509 DN is already normalized */
			do_norm = 0;
			is_dn = SET_DN;
			ber_str2bv( id, len, 1, dn );

		} else
#endif
		{
			/* convert to u:<username> form */
			is_dn = SET_U;
			dn->bv_val = id;
			dn->bv_len = len;
		}
	}
	if( !is_dn ) {
		if( !strncasecmp( id, "u:", sizeof("u:")-1 )) {
			is_dn = SET_U;
			dn->bv_val = id+2;
			dn->bv_len = len-2;
		} else if ( !strncasecmp( id, "dn:", sizeof("dn:")-1) ) {
			is_dn = SET_DN;
			dn->bv_val = id+3;
			dn->bv_len = len-3;
		}
	}

	/* No other possibilities from here */
	if( !is_dn ) {
		dn->bv_val = NULL;
		dn->bv_len = 0;
		return( LDAP_INAPPROPRIATE_AUTH );
	}

	/* Username strings */
	if( is_dn == SET_U ) {
		char *p, *realm;
		len = dn->bv_len + sizeof("uid=")-1 + sizeof(",cn=auth")-1;

		/* username may have embedded realm name */
		if( ( realm = strchr( dn->bv_val, '@') ) ) {
			*realm++ = '\0';
			len += sizeof(",cn=")-2;
		} else if( user_realm && *user_realm ) {
 			len += strlen( user_realm ) + sizeof(",cn=")-1;
		}

		if( conn->c_sasl_bind_mech.bv_len ) {
			len += conn->c_sasl_bind_mech.bv_len + sizeof(",cn=")-1;
		}

		/* Build the new dn */
		c1 = dn->bv_val;
		dn->bv_val = ch_malloc( len+1 );
		p = lutil_strcopy( dn->bv_val, "uid=" );
		p = lutil_strncopy( p, c1, dn->bv_len );

		if( realm ) {
			int rlen = dn->bv_len - ( realm - c1 );
			p = lutil_strcopy( p, ",cn=" );
			p = lutil_strncopy( p, realm, rlen );
			realm[-1] = '@';
		} else if( user_realm && *user_realm ) {
			p = lutil_strcopy( p, ",cn=" );
			p = lutil_strcopy( p, user_realm );
		}

		if( conn->c_sasl_bind_mech.bv_len ) {
			p = lutil_strcopy( p, ",cn=" );
			p = lutil_strcopy( p, conn->c_sasl_bind_mech.bv_val );
		}
		p = lutil_strcopy( p, ",cn=auth" );
		dn->bv_len = p - dn->bv_val;

#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, ENTRY, 
			"slap_sasl_getdn: u:id converted to %s.\n", dn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "getdn: u:id converted to %s\n", dn->bv_val,0,0 );
#endif
	}

	/* All strings are in DN form now. Normalize if needed. */
	if ( do_norm ) {
		rc = dnNormalize2( NULL, dn, &dn2 );

		/* User DNs were constructed above and must be freed now */
		if ( is_dn == SET_U )
			ch_free( dn->bv_val );

		if ( rc != LDAP_SUCCESS ) {
			dn->bv_val = NULL;
			dn->bv_len = 0;
			return rc;
		}
		*dn = dn2;
	}

	/* Run thru regexp */
	slap_sasl2dn( conn, dn, &dn2 );
	if( dn2.bv_val ) {
		ch_free( dn->bv_val );
		*dn = dn2;
#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, ENTRY, 
			"slap_sasl_getdn: dn:id converted to %s.\n", dn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "getdn: dn:id converted to %s\n",
			dn->bv_val, 0, 0 );
#endif
	}

	return( LDAP_SUCCESS );
}

#if SASL_VERSION_MAJOR >= 2
static const char *slap_propnames[] = {
	"*slapConn", "*authcDN", "*authzDN", NULL };

static Filter *generic_filter;

#define	PROP_CONN	0
#define	PROP_AUTHC	1
#define	PROP_AUTHZ	2

typedef struct lookup_info {
	int last;
	int flags;
	const struct propval *list;
	sasl_server_params_t *sparams;
} lookup_info;

static int
sasl_ap_lookup(
	BackendDB *be,
	Connection *conn,
	Operation *op,
	Entry *e,
	AttributeName *an,
	int attrsonly,
	LDAPControl **ctrls )
{
	BerVarray bv;
	AttributeDescription *ad;
	Attribute *a;
	const char *text;
	int rc, i;
	slap_callback *tmp = op->o_callback;
	lookup_info *sl = tmp->sc_private;

	for( i = 0; i < sl->last; i++ ) {
		const char *name = sl->list[i].name;

		if ( name[0] == '*' ) {
			if ( sl->flags & SASL_AUXPROP_AUTHZID ) continue;
			name++;
		} else if ( !(sl->flags & SASL_AUXPROP_AUTHZID ) )
			continue;

		if ( sl->list[i].values ) {
			if ( !(sl->flags & SASL_AUXPROP_OVERRIDE) ) continue;
		}
		ad = NULL;
		rc = slap_str2ad( name, &ad, &text );
		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG( TRANSPORT, DETAIL1, 
				"slap_auxprop: str2ad(%s): %s\n", name, text, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"slap_auxprop: str2ad(%s): %s\n", name, text, 0 );
#endif
			continue;
		}
		a = attr_find( e->e_attrs, ad );
		if ( !a ) continue;
		if ( ! access_allowed( be, conn, op, e, ad, NULL, ACL_AUTH, NULL ) )
			continue;
		if ( sl->list[i].values && ( sl->flags & SASL_AUXPROP_OVERRIDE ) )
			sl->sparams->utils->prop_erase( sl->sparams->propctx, sl->list[i].name );
		for ( bv = a->a_vals; bv->bv_val; bv++ ) {
			sl->sparams->utils->prop_set( sl->sparams->propctx, sl->list[i].name,
				bv->bv_val, bv->bv_len );
		}
	}
	return LDAP_SUCCESS;
}

static void
slap_auxprop_lookup(
	void *glob_context,
	sasl_server_params_t *sparams,
	unsigned flags,
	const char *user,
	unsigned ulen)
{
	int rc, i, doit=0;
	struct berval dn;
	Connection *conn = NULL;
	lookup_info sl;

	sl.list = sparams->utils->prop_get( sparams->propctx );
	sl.sparams = sparams;
	sl.flags = flags;

	/* Find our DN and conn first */
	for( i = 0, sl.last = 0; sl.list[i].name; i++ ) {
		if ( sl.list[i].name[0] == '*' ) {
			if ( !strcmp( sl.list[i].name, slap_propnames[PROP_CONN] ) ) {
				if ( sl.list[i].values && sl.list[i].values[0] )
					AC_MEMCPY( &conn, sl.list[i].values[0], sizeof( conn ) );
				if ( !sl.last ) sl.last = i;
			}
			if ( (flags & SASL_AUXPROP_AUTHZID) &&
				!strcmp( sl.list[i].name, slap_propnames[PROP_AUTHZ] ) ) {

				if ( sl.list[i].values && sl.list[i].values[0] )
					AC_MEMCPY( &dn, sl.list[i].values[0], sizeof( dn ) );
				if ( !sl.last ) sl.last = i;
				break;
			}
			if ( !strcmp( sl.list[i].name, slap_propnames[PROP_AUTHC] ) ) {
				if ( !sl.last ) sl.last = i;
				if ( sl.list[i].values && sl.list[i].values[0] ) {
					AC_MEMCPY( &dn, sl.list[i].values[0], sizeof( dn ) );
					if ( !(flags & SASL_AUXPROP_AUTHZID) )
						break;
				}
			}
		}
	}

	/* Now see what else needs to be fetched */
	for( i = 0; i < sl.last; i++ ) {
		const char *name = sl.list[i].name;

		if ( name[0] == '*' ) {
			if ( flags & SASL_AUXPROP_AUTHZID ) continue;
			name++;
		} else if ( !(flags & SASL_AUXPROP_AUTHZID ) )
			continue;

		if ( sl.list[i].values ) {
			if ( !(flags & SASL_AUXPROP_OVERRIDE) ) continue;
		}
		doit = 1;
	}

	if (doit) {
		Backend *be;
		Operation op = {0};
		slap_callback cb = { slap_cb_null_response,
			slap_cb_null_sresult, sasl_ap_lookup, NULL };

		cb.sc_private = &sl;

		be = select_backend( &dn, 0, 1 );

		if ( be && be->be_search ) {
			op.o_tag = LDAP_REQ_SEARCH;
			op.o_protocol = LDAP_VERSION3;
			op.o_ndn = conn->c_ndn;
			op.o_callback = &cb;
			op.o_time = slap_get_time();
			op.o_do_not_cache = 1;
			op.o_threadctx = conn->c_sasl_bindop->o_threadctx;

			(*be->be_search)( be, conn, &op, NULL, &dn,
				LDAP_SCOPE_BASE, LDAP_DEREF_NEVER, 1, 0,
				generic_filter, NULL, NULL, 0 );
		}
	}
}

static sasl_auxprop_plug_t slap_auxprop_plugin = {
	0,	/* Features */
	0,	/* spare */
	NULL,	/* glob_context */
	NULL,	/* auxprop_free */
	slap_auxprop_lookup,
	"slapd",	/* name */
	NULL	/* spare */
};

static int
slap_auxprop_init(
	const sasl_utils_t *utils,
	int max_version,
	int *out_version,
	sasl_auxprop_plug_t **plug,
	const char *plugname)
{
	if ( !out_version | !plug ) return SASL_BADPARAM;

	if ( max_version < SASL_AUXPROP_PLUG_VERSION ) return SASL_BADVERS;

	*out_version = SASL_AUXPROP_PLUG_VERSION;
	*plug = &slap_auxprop_plugin;
	return SASL_OK;
}

typedef struct checkpass_info {
	int rc;
	struct berval cred;
} checkpass_info;

static int
sasl_cb_checkpass(
	BackendDB *be,
	Connection *conn,
	Operation *op,
	Entry *e,
	AttributeName *an,
	int attrsonly,
	LDAPControl **ctrls )
{
	slap_callback *tmp = op->o_callback;
	checkpass_info *ci = tmp->sc_private;
	Attribute *a;
	struct berval *bv;
	
	ci->rc = SASL_NOVERIFY;

	a = attr_find( e->e_attrs, slap_schema.si_ad_userPassword );
	if ( !a ) return 0;
	if ( ! access_allowed( be, conn, op, e, slap_schema.si_ad_userPassword,
		NULL, ACL_AUTH, NULL ) ) return 0;

	for ( bv = a->a_vals; bv->bv_val != NULL; bv++ ) {
		if ( !lutil_passwd( bv, &ci->cred, NULL ) ) {
			ci->rc = SASL_OK;
			break;
		}
	}
	return 0;
}

static int
slap_sasl_checkpass(
	sasl_conn_t *sconn,
	void *context,
	const char *username,
	const char *pass,
	unsigned passlen,
	struct propctx *propctx)
{
	Connection *conn = (Connection *)context;
	struct berval dn;
	int rc;
	Backend *be;
	checkpass_info ci;

	ci.rc = SASL_NOUSER;

	/* SASL will fallback to its own mechanisms if we don't
	 * find an answer here.
	 */

	rc = slap_sasl_getdn( conn, (char *)username, 0, NULL, &dn,
		FLAG_GETDN_AUTHCID );
	if ( rc != LDAP_SUCCESS ) {
		sasl_seterror( sconn, 0, ldap_err2string( rc ) );
		return SASL_NOUSER;
	}

	if ( dn.bv_len == 0 ) {
		sasl_seterror( sconn, 0,
			"No password is associated with the Root DSE" );
		if ( dn.bv_val != NULL ) {
			ch_free( dn.bv_val );
		}
		return SASL_NOUSER;
	}

	be = select_backend( &dn, 0, 1 );
	if ( be && be->be_search ) {
		Operation op = {0};
		slap_callback cb = { slap_cb_null_response,
			slap_cb_null_sresult, sasl_cb_checkpass, NULL };

		ci.cred.bv_val = (char *)pass;
		ci.cred.bv_len = passlen;

		cb.sc_private = &ci;
		op.o_tag = LDAP_REQ_SEARCH;
		op.o_protocol = LDAP_VERSION3;
		op.o_ndn = conn->c_ndn;
		op.o_callback = &cb;
		op.o_time = slap_get_time();
		op.o_do_not_cache = 1;
		op.o_threadctx = conn->c_sasl_bindop->o_threadctx;

		(*be->be_search)( be, conn, &op, NULL, &dn,
			LDAP_SCOPE_BASE, LDAP_DEREF_NEVER, 1, 0,
			generic_filter, NULL, NULL, 0 );
	}
	if ( ci.rc != SASL_OK ) {
		sasl_seterror( sconn, 0,
			ldap_err2string( LDAP_INVALID_CREDENTIALS ) );
	}

	ch_free( dn.bv_val );

	return ci.rc;
}

/* Convert a SASL authcid or authzid into a DN. Store the DN in an
 * auxiliary property, so that we can refer to it in sasl_authorize
 * without interfering with anything else. Also, the SASL username
 * buffer is constrained to 256 characters, and our DNs could be
 * much longer (totally arbitrary length)...
 */
static int
slap_sasl_canonicalize(
	sasl_conn_t *sconn,
	void *context,
	const char *in,
	unsigned inlen,
	unsigned flags,
	const char *user_realm,
	char *out,
	unsigned out_max,
	unsigned *out_len)
{
	Connection *conn = (Connection *)context;
	struct propctx *props = sasl_auxprop_getctx( sconn );
	struct propval auxvals[3];
	struct berval dn;
	int rc, which;
	const char *names[2];

	*out_len = 0;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_canonicalize: conn %d %s=\"%s\"\n",
		conn ? conn->c_connid : -1,
		(flags & SASL_CU_AUTHID) ? "authcid" : "authzid", in ? in : "<empty>");
#else
	Debug( LDAP_DEBUG_ARGS, "SASL Canonicalize [conn=%ld]: "
		"%s=\"%s\"\n",
			conn ? conn->c_connid : -1,
			(flags & SASL_CU_AUTHID) ? "authcid" : "authzid",
			in ? in : "<empty>" );
#endif

	/* If name is too big, just truncate. We don't care, we're
	 * using DNs, not the usernames.
	 */
	if ( inlen > out_max )
		inlen = out_max-1;

	/* See if we need to add request, can only do it once */
	prop_getnames( props, slap_propnames, auxvals );
	if ( !auxvals[0].name )
		prop_request( props, slap_propnames );

	if ( flags & SASL_CU_AUTHID )
		which = PROP_AUTHC;
	else
		which = PROP_AUTHZ;

	/* Need to store the Connection for auxprop_lookup */
	if ( !auxvals[PROP_CONN].values ) {
		names[0] = slap_propnames[PROP_CONN];
		names[1] = NULL;
		prop_set( props, names[0], (char *)&conn, sizeof( conn ) );
	}
		
	/* Already been here? */
	if ( auxvals[which].values )
		goto done;

	if ( flags == SASL_CU_AUTHZID ) {
	/* If we got unqualified authzid's, they probably came from SASL
	 * itself just passing the authcid to us. Look inside the oparams
	 * structure to see if that's true. (HACK: the out_len pointer is
	 * the address of a member of a sasl_out_params_t structure...)
	 */
		sasl_out_params_t dummy;
		int offset = (void *)&dummy.ulen - (void *)&dummy.authid;
		char **authid = (void *)out_len - offset;
		if ( *authid && !strcmp( in, *authid ) )
			goto done;
	}

	rc = slap_sasl_getdn( conn, (char *)in, inlen, (char *)user_realm, &dn,
		(flags & SASL_CU_AUTHID) ? FLAG_GETDN_AUTHCID : FLAG_GETDN_AUTHZID );
	if ( rc != LDAP_SUCCESS ) {
		sasl_seterror( sconn, 0, ldap_err2string( rc ) );
		return SASL_NOAUTHZ;
	}		

	names[0] = slap_propnames[which];
	names[1] = NULL;

	prop_set( props, names[0], (char *)&dn, sizeof( dn ) );
		
#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_canonicalize: conn %d %s=\"%s\"\n",
		conn ? conn->c_connid : -1, names[0]+1, dn.bv_val );
#else
	Debug( LDAP_DEBUG_ARGS, "SASL Canonicalize [conn=%ld]: "
		"%s=\"%s\"\n",
			conn ? conn->c_connid : -1,
			names[0]+1, dn.bv_val );
#endif
done:	AC_MEMCPY( out, in, inlen );
	out[inlen] = '\0';

	*out_len = inlen;

	return SASL_OK;
}

static int
slap_sasl_authorize(
	sasl_conn_t *sconn,
	void *context,
	char *requested_user,
	unsigned rlen,
	char *auth_identity,
	unsigned alen,
	const char *def_realm,
	unsigned urlen,
	struct propctx *props)
{
	Connection *conn = (Connection *)context;
	struct propval auxvals[3];
	struct berval authcDN, authzDN;
	int rc;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_authorize: conn %d authcid=\"%s\" authzid=\"%s\"\n",
		conn ? conn->c_connid : -1, auth_identity, requested_user);
#else
	Debug( LDAP_DEBUG_ARGS, "SASL Authorize [conn=%ld]: "
		"authcid=\"%s\" authzid=\"%s\"\n",
		conn ? conn->c_connid : -1, auth_identity, requested_user );
#endif
	if ( conn->c_sasl_dn.bv_val ) {
		ch_free( conn->c_sasl_dn.bv_val );
		conn->c_sasl_dn.bv_val = NULL;
		conn->c_sasl_dn.bv_len = 0;
	}

	/* Skip PROP_CONN */
	prop_getnames( props, slap_propnames+1, auxvals );
	
	AC_MEMCPY( &authcDN, auxvals[0].values[0], sizeof(authcDN) );

	/* Nothing to do if no authzID was given */
	if ( !auxvals[1].name || !auxvals[1].values ) {
		conn->c_sasl_dn = authcDN;
		return SASL_OK;
	}
	
	AC_MEMCPY( &authzDN, auxvals[1].values[0], sizeof(authzDN) );

	rc = slap_sasl_authorized( conn, &authcDN, &authzDN );
	ch_free( authcDN.bv_val );
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, INFO, 
			"slap_sasl_authorize: conn %ld  authorization disallowed (%d)\n",
			(long)(conn ? conn->c_connid : -1), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
			" authorization disallowed (%d)\n",
			(long) (conn ? conn->c_connid : -1), rc, 0 );
#endif

		sasl_seterror( sconn, 0, "not authorized" );
		ch_free( authzDN.bv_val );
		return SASL_NOAUTHZ;
	}

	conn->c_sasl_dn = authzDN;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_authorize: conn %d authorization allowed\n",
		(long)(conn ? conn->c_connid : -1), 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
		" authorization allowed\n",
		(long) (conn ? conn->c_connid : -1), 0, 0 );
#endif
	return SASL_OK;
} 
#else
static int
slap_sasl_authorize(
	void *context,
	char *authcid,
	char *authzid,
	const char **user,
	const char **errstr)
{
	struct berval authcDN, authzDN;
	int rc;
	Connection *conn = context;
	char *realm;

	*user = NULL;
	if ( conn->c_sasl_dn.bv_val ) {
		ch_free( conn->c_sasl_dn.bv_val );
		conn->c_sasl_dn.bv_val = NULL;
		conn->c_sasl_dn.bv_len = 0;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_authorize: conn %d	 authcid=\"%s\" authzid=\"%s\"\n",
		conn ? conn->c_connid : -1, authcid ? authcid : "<empty>",
		authzid ? authzid : "<empty>" );
#else
	Debug( LDAP_DEBUG_ARGS, "SASL Authorize [conn=%ld]: "
		"authcid=\"%s\" authzid=\"%s\"\n",
		(long) (conn ? conn->c_connid : -1),
		authcid ? authcid : "<empty>",
		authzid ? authzid : "<empty>" );
#endif

	/* Figure out how much data we have for the dn */
	rc = sasl_getprop( conn->c_sasl_context, SASL_REALM, (void **)&realm );
	if( rc != SASL_OK && rc != SASL_NOTDONE ) {
#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, ERR,
			"slap_sasl_authorize: getprop(REALM) failed.\n", 0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE,
			"authorize: getprop(REALM) failed!\n", 0,0,0);
#endif
		*errstr = "Could not extract realm";
		return SASL_NOAUTHZ;
	}

	/* Convert the identities to DN's. If no authzid was given, client will
	   be bound as the DN matching their username */
	rc = slap_sasl_getdn( conn, (char *)authcid, 0, realm, &authcDN, FLAG_GETDN_AUTHCID );
	if( rc != LDAP_SUCCESS ) {
		*errstr = ldap_err2string( rc );
		return SASL_NOAUTHZ;
	}
	if( ( authzid == NULL ) || !strcmp( authcid,authzid ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, ENTRY, 
			"slap_sasl_authorize: conn %d  Using authcDN=%s\n",
			conn ? conn->c_connid : -1, authcDN.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
		 "Using authcDN=%s\n", (long) (conn ? conn->c_connid : -1), authcDN.bv_val,0 );
#endif

		conn->c_sasl_dn = authcDN;
		*errstr = NULL;
		return SASL_OK;
	}
	rc = slap_sasl_getdn( conn, (char *)authzid, 0, realm, &authzDN, FLAG_GETDN_AUTHZID );
	if( rc != LDAP_SUCCESS ) {
		ch_free( authcDN.bv_val );
		*errstr = ldap_err2string( rc );
		return SASL_NOAUTHZ;
	}

	rc = slap_sasl_authorized(conn, &authcDN, &authzDN );
	ch_free( authcDN.bv_val );
	if( rc ) {
#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, INFO, 
			"slap_sasl_authorize: conn %ld  authorization disallowed (%d)\n",
			(long)(conn ? conn->c_connid : -1), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
			" authorization disallowed (%d)\n",
			(long) (conn ? conn->c_connid : -1), rc, 0 );
#endif

		*errstr = "not authorized";
		ch_free( authzDN.bv_val );
		return SASL_NOAUTHZ;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, RESULTS, 
		"slap_sasl_authorize: conn %d authorization allowed\n",
	   (long)(conn ? conn->c_connid : -1 ), 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
		" authorization allowed\n",
		(long) (conn ? conn->c_connid : -1), 0, 0 );
#endif

	conn->c_sasl_dn = authzDN;
	*errstr = NULL;
	return SASL_OK;
}
#endif /* SASL_VERSION_MAJOR >= 2 */

static int
slap_sasl_err2ldap( int saslerr )
{
	int rc;

	switch (saslerr) {
		case SASL_CONTINUE:
			rc = LDAP_SASL_BIND_IN_PROGRESS;
			break;
		case SASL_FAIL:
			rc = LDAP_OTHER;
			break;
		case SASL_NOMEM:
			rc = LDAP_OTHER;
			break;
		case SASL_NOMECH:
			rc = LDAP_AUTH_METHOD_NOT_SUPPORTED;
			break;
		case SASL_BADAUTH:
			rc = LDAP_INVALID_CREDENTIALS;
			break;
		case SASL_NOAUTHZ:
			rc = LDAP_INSUFFICIENT_ACCESS;
			break;
		case SASL_TOOWEAK:
		case SASL_ENCRYPT:
			rc = LDAP_INAPPROPRIATE_AUTH;
			break;
		default:
			rc = LDAP_OTHER;
			break;
	}

	return rc;
}
#endif


int slap_sasl_init( void )
{
#ifdef HAVE_CYRUS_SASL
	int rc;
	static sasl_callback_t server_callbacks[] = {
		{ SASL_CB_LOG, &slap_sasl_log, NULL },
		{ SASL_CB_LIST_END, NULL, NULL }
	};

	sasl_set_alloc(
		ber_memalloc,
		ber_memcalloc,
		ber_memrealloc,
		ber_memfree ); 

	sasl_set_mutex(
		ldap_pvt_sasl_mutex_new,
		ldap_pvt_sasl_mutex_lock,
		ldap_pvt_sasl_mutex_unlock,
		ldap_pvt_sasl_mutex_dispose );

#if SASL_VERSION_MAJOR >= 2
	sasl_auxprop_add_plugin( "slapd", slap_auxprop_init );
#endif
	/* should provide callbacks for logging */
	/* server name should be configurable */
	rc = sasl_server_init( server_callbacks, "slapd" );

	if( rc != SASL_OK ) {
#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, INFO, "slap_sasl_init: init failed.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "sasl_server_init failed\n",
			0, 0, 0 );
#endif

		return -1;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, INFO, "slap_sasl_init: initialized!\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "slap_sasl_init: initialized!\n",
		0, 0, 0 );
#endif


	/* default security properties */
	memset( &sasl_secprops, '\0', sizeof(sasl_secprops) );
	sasl_secprops.max_ssf = INT_MAX;
	sasl_secprops.maxbufsize = 65536;
	sasl_secprops.security_flags = SASL_SEC_NOPLAINTEXT|SASL_SEC_NOANONYMOUS;
#endif

	return 0;
}

int slap_sasl_destroy( void )
{
#ifdef HAVE_CYRUS_SASL
	sasl_done();
#endif
#if SASL_VERSION_MAJOR >= 2
	filter_free( generic_filter );
#endif
	free( global_host );
	global_host = NULL;

	return 0;
}

int slap_sasl_open( Connection *conn )
{
	int cb, sc = LDAP_SUCCESS;
#if SASL_VERSION_MAJOR >= 2
	char *ipremoteport = NULL, *iplocalport = NULL;
#endif

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = NULL;
	sasl_callback_t *session_callbacks;

	assert( conn->c_sasl_context == NULL );
	assert( conn->c_sasl_extra == NULL );

	conn->c_sasl_layers = 0;

	session_callbacks =
#if SASL_VERSION_MAJOR >= 2
		ch_calloc( 5, sizeof(sasl_callback_t));
#else
		ch_calloc( 3, sizeof(sasl_callback_t));
#endif
	conn->c_sasl_extra = session_callbacks;

	session_callbacks[cb=0].id = SASL_CB_LOG;
	session_callbacks[cb].proc = &slap_sasl_log;
	session_callbacks[cb++].context = conn;

	session_callbacks[cb].id = SASL_CB_PROXY_POLICY;
	session_callbacks[cb].proc = &slap_sasl_authorize;
	session_callbacks[cb++].context = conn;

#if SASL_VERSION_MAJOR >= 2
	session_callbacks[cb].id = SASL_CB_CANON_USER;
	session_callbacks[cb].proc = &slap_sasl_canonicalize;
	session_callbacks[cb++].context = conn;

	/* XXXX: this should be conditional */
	session_callbacks[cb].id = SASL_CB_SERVER_USERDB_CHECKPASS;
	session_callbacks[cb].proc = &slap_sasl_checkpass;
	session_callbacks[cb++].context = conn;
#endif

	session_callbacks[cb].id = SASL_CB_LIST_END;
	session_callbacks[cb].proc = NULL;
	session_callbacks[cb++].context = NULL;

	if( global_host == NULL ) {
		global_host = ldap_pvt_get_fqdn( NULL );
	}

	/* create new SASL context */
#if SASL_VERSION_MAJOR >= 2
	if ( generic_filter == NULL ) {
		generic_filter = str2filter( "(objectclass=*)" );
	}
	if ( conn->c_sock_name.bv_len != 0 &&
	     strncmp( conn->c_sock_name.bv_val, "IP=", 3 ) == 0) {
		char *p;

		iplocalport = ch_strdup( conn->c_sock_name.bv_val + 3 );
		/* Convert IPv6 addresses to address;port syntax. */
		p = strrchr( iplocalport, ' ' );
		/* Convert IPv4 addresses to address;port syntax. */
		if ( p == NULL ) p = strchr( iplocalport, ':' );
		if ( p != NULL ) {
			*p = ';';
		}
	}
	if ( conn->c_peer_name.bv_len != 0 &&
	     strncmp( conn->c_peer_name.bv_val, "IP=", 3 ) == 0) {
		char *p;

		ipremoteport = ch_strdup( conn->c_peer_name.bv_val + 3 );
		/* Convert IPv6 addresses to address;port syntax. */
		p = strrchr( ipremoteport, ' ' );
		/* Convert IPv4 addresses to address;port syntax. */
		if ( p == NULL ) p = strchr( ipremoteport, ':' );
		if ( p != NULL ) {
			*p = ';';
		}
	}
	sc = sasl_server_new( "ldap", global_host, global_realm,
		iplocalport, ipremoteport, session_callbacks, 0, &ctx );
	if ( iplocalport != NULL ) {
		ch_free( iplocalport );
	}
	if ( ipremoteport != NULL ) {
		ch_free( ipremoteport );
	}
#else
	sc = sasl_server_new( "ldap", global_host, global_realm,
		session_callbacks, SASL_SECURITY_LAYER, &ctx );
#endif

	if( sc != SASL_OK ) {
#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, ERR, 
			"slap_sasl_open: sasl_server_new failed: %d\n", sc, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "sasl_server_new failed: %d\n",
			sc, 0, 0 );
#endif

		return -1;
	}

	conn->c_sasl_context = ctx;

	if( sc == SASL_OK ) {
		sc = sasl_setprop( ctx,
			SASL_SEC_PROPS, &sasl_secprops );

		if( sc != SASL_OK ) {
#ifdef NEW_LOGGING
			LDAP_LOG( TRANSPORT, ERR, 
				"slap_sasl_open: sasl_setprop failed: %d \n", sc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "sasl_setprop failed: %d\n",
				sc, 0, 0 );
#endif

			slap_sasl_close( conn );
			return -1;
		}
	}

	sc = slap_sasl_err2ldap( sc );
#endif
	return sc;
}

int slap_sasl_external(
	Connection *conn,
	slap_ssf_t ssf,
	const char *auth_id )
{
#if SASL_VERSION_MAJOR >= 2
	int sc;
	sasl_conn_t *ctx = conn->c_sasl_context;

	if ( ctx == NULL ) {
		return LDAP_UNAVAILABLE;
	}

	sc = sasl_setprop( ctx, SASL_SSF_EXTERNAL, &ssf );

	if ( sc != SASL_OK ) {
		return LDAP_OTHER;
	}

	sc = sasl_setprop( ctx, SASL_AUTH_EXTERNAL, auth_id );

	if ( sc != SASL_OK ) {
		return LDAP_OTHER;
	}

#elif defined(HAVE_CYRUS_SASL)
	int sc;
	sasl_conn_t *ctx = conn->c_sasl_context;
	sasl_external_properties_t extprops;

	if ( ctx == NULL ) {
		return LDAP_UNAVAILABLE;
	}

	memset( &extprops, '\0', sizeof(extprops) );
	extprops.ssf = ssf;
	extprops.auth_id = (char *) auth_id;

	sc = sasl_setprop( ctx, SASL_SSF_EXTERNAL,
		(void *) &extprops );

	if ( sc != SASL_OK ) {
		return LDAP_OTHER;
	}
#endif

	return LDAP_SUCCESS;
}

int slap_sasl_reset( Connection *conn )
{
#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;

	if( ctx != NULL ) {
	}
#endif
	/* must return "anonymous" */
	return LDAP_SUCCESS;
}

char ** slap_sasl_mechs( Connection *conn )
{
	char **mechs = NULL;

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;

	if( ctx != NULL ) {
		int sc;
		SASL_CONST char *mechstr;

		sc = sasl_listmech( ctx,
			NULL, NULL, ",", NULL,
			&mechstr, NULL, NULL );

		if( sc != SASL_OK ) {
#ifdef NEW_LOGGING
			LDAP_LOG( TRANSPORT, ERR, 
				"slap_sasl_mechs: sasl_listmech failed: %d\n", sc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "slap_sasl_listmech failed: %d\n",
				sc, 0, 0 );
#endif

			return NULL;
		}

		mechs = ldap_str2charray( mechstr, "," );

#if SASL_VERSION_MAJOR < 2
		ch_free( mechstr );
#endif
	}
#endif

	return mechs;
}

int slap_sasl_close( Connection *conn )
{
#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;

	if( ctx != NULL ) {
		sasl_dispose( &ctx );
	}

	conn->c_sasl_context = NULL;

	free( conn->c_sasl_extra );
	conn->c_sasl_extra = NULL;
#endif

	return LDAP_SUCCESS;
}

int slap_sasl_bind(
    Connection		*conn,
    Operation		*op,  
    struct berval	*dn,  
    struct berval	*ndn,
    struct berval	*cred,
	struct berval			*edn,
	slap_ssf_t		*ssfp )
{
	int rc = 1;

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;
	struct berval response;
	unsigned reslen = 0;
	const char *errstr = NULL;
	int sc;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"sasl_bind: dn=\"%s\" mech=%s datalen=%ld\n",
		dn->bv_len ? dn->bv_val : "",
		conn->c_sasl_bind_in_progress ? "<continuing>" : 
		conn->c_sasl_bind_mech.bv_val,
		cred ? cred->bv_len : 0 );
#else
	Debug(LDAP_DEBUG_ARGS,
		"==> sasl_bind: dn=\"%s\" mech=%s datalen=%ld\n",
		dn->bv_len ? dn->bv_val : "",
		conn->c_sasl_bind_in_progress ? "<continuing>":conn->c_sasl_bind_mech.bv_val,
		cred ? cred->bv_len : 0 );
#endif


	if( ctx == NULL ) {
		send_ldap_result( conn, op, LDAP_UNAVAILABLE,
			NULL, "SASL unavailable on this session", NULL, NULL );
		return rc;
	}

#if SASL_VERSION_MAJOR >= 2
#define	START( ctx, mech, cred, clen, resp, rlen, err ) \
	sasl_server_start( ctx, mech, cred, clen, resp, rlen )
#define	STEP( ctx, cred, clen, resp, rlen, err ) \
	sasl_server_step( ctx, cred, clen, resp, rlen )
#else
#define	START( ctx, mech, cred, clen, resp, rlen, err ) \
	sasl_server_start( ctx, mech, cred, clen, resp, rlen, err )
#define	STEP( ctx, cred, clen, resp, rlen, err ) \
	sasl_server_step( ctx, cred, clen, resp, rlen, err )
#endif

	if ( !conn->c_sasl_bind_in_progress ) {
		sc = START( ctx,
			conn->c_sasl_bind_mech.bv_val,
			cred->bv_len ? cred->bv_val : "",
			cred->bv_len,
			(SASL_CONST char **)&response.bv_val, &reslen, &errstr );

	} else {
		sc = STEP( ctx,
			cred->bv_val, cred->bv_len,
			(SASL_CONST char **)&response.bv_val, &reslen, &errstr );
	}

	response.bv_len = reslen;

	if ( sc == SASL_OK ) {
		sasl_ssf_t *ssf = NULL;

		*edn = conn->c_sasl_dn;
		conn->c_sasl_dn.bv_val = NULL;
		conn->c_sasl_dn.bv_len = 0;

		rc = LDAP_SUCCESS;

		(void) sasl_getprop( ctx, SASL_SSF, (void *)&ssf );
		*ssfp = ssf ? *ssf : 0;

		if( *ssfp ) {
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );
			conn->c_sasl_layers++;
			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
		}

		send_ldap_sasl( conn, op, rc,
			NULL, NULL, NULL, NULL,
			response.bv_len ? &response : NULL );

	} else if ( sc == SASL_CONTINUE ) {
		send_ldap_sasl( conn, op, rc = LDAP_SASL_BIND_IN_PROGRESS,
			NULL, NULL, NULL, NULL, &response );

	} else {
#if SASL_VERSION_MAJOR >= 2
		errstr = sasl_errdetail( ctx );
#endif
		send_ldap_result( conn, op, rc = slap_sasl_err2ldap( sc ),
			NULL, errstr, NULL, NULL );
	}

#if SASL_VERSION_MAJOR < 2
	if( response.bv_len ) {
		ch_free( response.bv_val );
	}
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, RESULTS, "slap_sasl_bind: rc=%d\n", rc, 0, 0 );
#else
	Debug(LDAP_DEBUG_TRACE, "<== slap_sasl_bind: rc=%d\n", rc, 0, 0);
#endif


#else
	send_ldap_result( conn, op, rc = LDAP_UNAVAILABLE,
		NULL, "SASL not supported", NULL, NULL );
#endif

	return rc;
}

char* slap_sasl_secprops( const char *in )
{
#ifdef HAVE_CYRUS_SASL
	int rc = ldap_pvt_sasl_secprops( in, &sasl_secprops );

	return rc == LDAP_SUCCESS ? NULL : "Invalid security properties";
#else
	return "SASL not supported";
#endif
}

#ifdef HAVE_CYRUS_SASL
int
slap_sasl_setpass(
	Connection      *conn,
	Operation       *op,
	const char      *reqoid,
	struct berval   *reqdata,
	char            **rspoid,
	struct berval   **rspdata,
	LDAPControl     *** rspctrls,
	const char      **text )
{
	int rc;
	struct berval id = { 0, NULL };	/* needs to come from connection */
	struct berval new = { 0, NULL };
	struct berval old = { 0, NULL };

	assert( reqoid != NULL );
	assert( strcmp( LDAP_EXOP_MODIFY_PASSWD, reqoid ) == 0 );

	rc = sasl_getprop( conn->c_sasl_context, SASL_USERNAME,
		(SASL_CONST void **)&id.bv_val );

	if( rc != SASL_OK ) {
		*text = "unable to retrieve SASL username";
		rc = LDAP_OTHER;
		goto done;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACKEND, ENTRY,
		"slap_sasl_setpass: \"%s\"\n",
		id.bv_val ? id.bv_val : "", 0, 0);
#else
	Debug( LDAP_DEBUG_ARGS, "==> slap_sasl_setpass: \"%s\"\n",
		id.bv_val ? id.bv_val : "", 0, 0 );
#endif

	rc = slap_passwd_parse( reqdata,
		NULL, &old, &new, text );

	if( rc != LDAP_SUCCESS ) {
		goto done;
	}

	if( new.bv_len == 0 ) {
		slap_passwd_generate(&new);

		if( new.bv_len == 0 ) {
			*text = "password generation failed.";
			rc = LDAP_OTHER;
			goto done;
		}
		
		*rspdata = slap_passwd_return( &new );
	}

#if SASL_VERSION_MAJOR < 2
	rc = sasl_setpass( conn->c_sasl_context,
		id.bv_val, new.bv_val, new.bv_len, 0, text );
#else
	rc = sasl_setpass( conn->c_sasl_context, id.bv_val,
		new.bv_val, new.bv_len, old.bv_val, old.bv_len, 0 );
	if( rc != SASL_OK ) {
		*text = sasl_errdetail( conn->c_sasl_context );
	}
#endif
	switch(rc) {
		case SASL_OK:
			rc = LDAP_SUCCESS;
			break;

		case SASL_NOCHANGE:
		case SASL_NOMECH:
		case SASL_DISABLED:
		case SASL_PWLOCK:
		case SASL_FAIL:
		case SASL_BADPARAM:
		default:
			rc = LDAP_OTHER;
	}

done:
	return rc;
}
#endif

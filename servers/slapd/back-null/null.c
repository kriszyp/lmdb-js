/* null.c - the null backend */
/*
 * Copyright 2002-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "external.h"

struct null_info {
	int bind_allowed;
};

int
null_back_bind(
	Backend			*be,
	Connection		*conn,
	Operation		*op,
	struct berval	*dn,
	struct berval	*ndn,
	int				method,
	struct berval	*cred,
	struct berval	*edn
)
{
	struct null_info *ni = (struct null_info *) be->be_private;

	if( ni->bind_allowed )
		/* front end will send result on success (0) */
		return 0;
	send_ldap_result( conn, op, LDAP_INVALID_CREDENTIALS,
	                  NULL, NULL, NULL, NULL );
	return LDAP_INVALID_CREDENTIALS;
}

int
null_back_add(
	BackendDB	*be,
	Connection	*conn,
	Operation	*op,
	Entry		*e )
{
	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL, NULL, NULL );
	return 0;
}

int
null_back_compare(
	BackendDB		*be,
	Connection		*conn,
	Operation		*op,
	struct berval	*dn,
	struct berval	*ndn,
	AttributeAssertion *ava
)
{
	send_ldap_result( conn, op, LDAP_COMPARE_FALSE, NULL, NULL, NULL, NULL );
	return 0;
}

int
null_back_delete(
	BackendDB		*be,
	Connection		*conn,
	Operation		*op,
	struct berval	*dn,
	struct berval	*ndn
)
{
	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL, NULL, NULL );
	return 0;
}

int
null_back_modify(
	BackendDB		*be,
	Connection		*conn,
	Operation		*op,
	struct berval	*dn,
	struct berval	*ndn,
	Modifications	*modlist )
{
	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL, NULL, NULL );
	return 0;
}

int
null_back_modrdn(
	Backend			*be,
	Connection		*conn,
	Operation		*op,
	struct berval	*dn,
	struct berval	*ndn,
	struct berval	*newrdn,
	struct berval	*nnewrdn,
	int				deleteoldrdn,
	struct berval	*newSuperior,
	struct berval	*nnewSuperior )
{
	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL, NULL, NULL );
	return 0;
}

int
null_back_search(
	BackendDB		*be,
	Connection		*conn,
	Operation		*op,
	struct berval	*base,
	struct berval	*nbase,
	int				scope,
	int				deref,
	int				slimit,
	int				tlimit,
	Filter			*filter,
	struct berval	*filterstr,
	AttributeName	*attrs,
	int				attrsonly )
{
	send_search_result( conn, op, LDAP_SUCCESS, NULL, NULL, NULL, NULL, 0 );
	return 1;
}


int
null_back_db_config(
	BackendDB	*be,
	const char	*fname,
	int			lineno,
	int			argc,
	char		**argv )
{
	struct null_info *ni = (struct null_info *) be->be_private;

	if ( ni == NULL ) {
		fprintf( stderr, "%s: line %d: null database info is null!\n",
			fname, lineno );
		return 1;
	}

	/* bind requests allowed */
	if ( strcasecmp( argv[0], "bind" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing <on/off> in \"bind <on/off>\" line\n",
			         fname, lineno );
			return 1;
		}
		ni->bind_allowed = strcasecmp( argv[1], "off" );

	/* anything else */
	} else {
		fprintf( stderr,
"%s: line %d: unknown directive \"%s\" in null database definition (ignored)\n",
		         fname, lineno, argv[0] );
	}

	return 0;
}


int
null_back_db_init( BackendDB *be )
{
	be->be_private = ch_calloc( 1, sizeof(struct null_info) );
	return 0;
}

int
null_back_db_destroy(
    Backend	*be
)
{
	free( be->be_private );
	return 0;
}


int
null_back_initialize(
    BackendInfo	*bi
)
{
	bi->bi_open = 0;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = null_back_db_init;
	bi->bi_db_config = null_back_db_config;
	bi->bi_db_open = 0;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = null_back_db_destroy;

	bi->bi_op_bind = null_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = null_back_search;
	bi->bi_op_compare = null_back_compare;
	bi->bi_op_modify = null_back_modify;
	bi->bi_op_modrdn = null_back_modrdn;
	bi->bi_op_add = null_back_add;
	bi->bi_op_delete = null_back_delete;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_acl_group = 0;
	bi->bi_acl_attribute = 0;
	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

#ifdef SLAPD_NULL_DYNAMIC
int back_null_LTX_init_module(
	int argc,
	char *argv[] )
{
    BackendInfo bi;

    memset( &bi, '\0', sizeof(bi) );
    bi.bi_type = "null";
    bi.bi_init = null_back_initialize;

    backend_add(&bi);
    return 0;
}
#endif /* SLAPD_NULL_DYNAMIC */

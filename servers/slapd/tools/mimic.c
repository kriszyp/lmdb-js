/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Mimic unused interfaces of slapd...
 * needed for linking.
 */
#include "portable.h"

#include <stdio.h>

#include "../slap.h"

/* needed by WIN32 and back-monitor */
time_t starttime;

/* because Versionstr is used in back-monitor */
const char Versionstr[] = "";

/* bogus ../results.c */
int str2result(
	char* s,
	int *code, 
	char **matched,
	char **info )
{
	assert(0);
    return 0;
}

void
send_ldap_disconnect(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*text
)
{
	assert(0);
}

void
send_ldap_extended(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
    const char	*text,
	BerVarray refs,
    const char	*rspoid,
	struct berval *rspdata,
	LDAPControl **ctrls
)
{
	assert(0);
}

void
send_ldap_sasl(
    Connection	*conn,
    Operation	*op,
    ber_int_t	err,
    const char	*matched,
    const char	*text,
	BerVarray refs,
	LDAPControl **ctrls,
	struct berval *cred
)
{
	assert(0);
}

void
send_ldap_result(
	Connection  *conn, 
	Operation   *op,
	ber_int_t     err,
	const char    *matched,
	const char    *text,
	BerVarray refs,
	LDAPControl **ctrls
)        
{
	assert(0);
}

void
send_search_result(
	Connection  *conn, 
	Operation   *op,
	ber_int_t     err,
	const char    *matched,
	const char    *text,
	BerVarray refs,
	LDAPControl **ctrls,
	int		nentries
)        
{
	assert(0);
}

int
send_search_entry(
	Backend *be,
	Connection  *conn, 
	Operation   *op,
	Entry	*e,
	AttributeName	*attrs,
	int		attrsonly,
	LDAPControl **ctrls
)        
{
	assert(0);
	return -1;
}

int send_search_reference(
	Backend *be,
	Connection  *conn, 
	Operation   *op,
	Entry	*e,
	BerVarray	refs,
	LDAPControl **ctrls,
	BerVarray	*v2refs
)
{
	assert(0);
	return -1;
}

int slap_sasl_init(void)
{
	return LDAP_SUCCESS;
}

int slap_sasl_destroy(void)
{
	return LDAP_SUCCESS;
}

int slap_sasl_setpass(
	Connection      *conn,
	Operation       *op,
	const char      *reqoid,
	struct berval   *reqdata,
	char            **rspoid,
	struct berval   **rspdata,
	LDAPControl     *** rspctrls,
	const char      **text )
{
	return LDAP_SUCCESS;
}

int slap_sasl_config(
	int cargc,
	char **cargv,
	char *line,
	const char *fname,
	int lineno )
{
	return LDAP_SUCCESS;
}


void connection2anonymous( Connection *c )
{
	assert(0);
}

Connection * connection_first( ber_socket_t *b )
{
	assert(0);
	return NULL;
}

Connection * connection_next( Connection *c, ber_socket_t *b )
{
	assert(0);
	return NULL;
}

unsigned long connections_nextid(void)
{
	return 0;
}

void connection_done( Connection *c )
{
	assert(0);
}

const char * connection_state2str( int state )
{
	assert(0);
	return NULL;
}

void replog( Backend *be, Operation *op,
	struct berval *dn, struct berval *ndn, void *change)
{
	assert(0);
}

int add_replica_info( Backend *be, const char *host )
{
	return 0;
}

int add_replica_suffix( Backend *be, int nr, const char *suffix )
{
	return 0;
}

int add_replica_attrs( Backend *be, int nr, char *attrs, int exclude )
{
	return 0;
}

int parse_limits( Backend *be, const char *fname, int lineno, int argc, char **argv )
{
	return 0;
}

int parse_limit( const char *arg, struct slap_limits_set *limit )
{
	return 0;
}

int get_limits( Backend *be, struct berval *ndn, struct slap_limits_set **limit )
{
	return 0;
}

int read_root_dse_file ( const char *file )
{
	return 0;
}

Attribute *
slap_operational_subschemaSubentry( Backend *be )
{
	return NULL;
}

Attribute *
slap_operational_hasSubordinate( int hs )
{
	return NULL;
}

Listener **
slapd_get_listeners(void)
{
	return NULL;
}

int
slap_modrdn2mods(
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	Entry		*e,
	LDAPRDN		*oldrdn,
	LDAPRDN		*newrdn,
	int		deleteoldrdn,
	Modifications	**pmod )
{
	return 0;
}


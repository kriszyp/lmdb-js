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

#ifdef WIN32
time_t starttime;
#endif

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
	struct berval **refs,
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
	struct berval **refs,
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
	struct berval **refs,
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
	struct berval **refs,
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
	char	**attrs,
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
	struct berval **refs,
	int scope,
	LDAPControl **ctrls,
	struct berval ***v2refs
)
{
	assert(0);
	return -1;
}

struct berval **get_entry_referrals(
	Backend *be, Connection *conn, Operation *op, Entry *e )
{
	assert(0);
	return NULL;
}

int slap_sasl_init(void)
{
	return LDAP_SUCCESS;
}

int slap_sasl_destroy(void)
{
	return LDAP_SUCCESS;
}

char * slap_sasl_secprops( const char *in )
{
	return NULL;
}

void connection2anonymous( Connection *c )
{
	assert(0);
}

void replog( Backend *be, Operation *op, char *dn, void *change)
{
	assert(0);
}

void slap_mods_free( Modifications *ml )
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

int parse_limits( Backend *be, const char *fname, int lineno, int argc, char **argv )
{
	return 0;
}

int parse_limit( const char *arg, struct slap_limits_set *limit )
{
	return 0;
}

int get_limits( Backend *be, const char *ndn, struct slap_limits_set **limit )
{
	return 0;
}

/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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
    char	*rspoid,
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

int sasl_init(void) {
	return 0;
}

int sasl_destroy(void) {
	return 0;
}

#ifdef HAVE_CYRUS_SASL
int sasl_bind(
    Connection          *conn,
    Operation           *op,
    char                *dn,
    char                *ndn,
    char                *mech,
    struct berval       *cred,
    char                **edn)
{
	return -1;
}
#endif

/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Mimic unused interfaces of slapd...
 * needed for linking.
 */
#include "portable.h"

#include <stdio.h>

#include "../slap.h"

#ifdef LDAP_SYNCREPL
#include "ldap_rq.h"
#endif

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
send_ldap_disconnect( Operation	*op, SlapReply *rs )
{
	assert(0);
}

void
slap_send_ldap_extended(
    Operation	*op, SlapReply *rs
)
{
	assert(0);
}

void
slap_send_ldap_intermediate_resp(
	Operation *op, SlapReply *rs
)
{
	assert(0);
}

void
send_ldap_sasl( Operation *op, SlapReply *rs )
{
	assert(0);
}

void
slap_send_ldap_result( Operation *op, SlapReply *rs )
{
	assert(0);
}

int
slap_send_search_entry( Operation *op, SlapReply *rs )
{
	assert(0);
	return -1;
}

int
slap_send_search_reference( Operation *op, SlapReply *rs )
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

int slap_sasl_setpass( Operation *op, SlapReply *rs )
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

void replog( Operation *op )
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
	Operation	*op, SlapReply *rs,
	Entry		*e,
	LDAPRDN		oldrdn,
	LDAPRDN		newrdn,
	Modifications	**pmod )
{
	return 0;
}

int
slap_mods2entry(
	Modifications *mods,
	Entry **e,
	int repl_user,
	int dup,
	const char **text,
	char *textbuf, size_t textlen )
{
	return 0;
}

int
slap_entry2mods(
	Entry *e,
	Modifications **mods,
	const char **text
)
{
	return 0;
}

int slap_sasl_getdn( Connection *conn, Operation *op, char *id, int len,
	char *user_realm, struct berval *dn, int flags )
{
	return -1;
}

int slap_sasl_authorized( Operation *op,
	struct berval *authcDN, struct berval *authzDN )
{
	return -1;
}

int slap_mods_check( Modifications *ml, int update, const char **text,
	char *textbuf, size_t textlen, void *ctx )
{
	return -1;
}

int slap_mods_opattrs( Operation *op, Modifications *mods,
	Modifications **modtail, const char **text,
	char *textbuf, size_t textlen )
{
	return -1;
}

int root_dse_info( Connection *conn, Entry **entry, const char **text )
{
	return -1;
}

#ifdef LDAP_SYNCREPL
struct runqueue_s syncrepl_rq;

void init_syncrepl( )
{
	return;
}

void* do_syncrepl( void *ctx, void *arg )
{
	return NULL;
}

char** str2clist( char ***out, char *in, const char *brkstr )
{
	return NULL;
}

void syncrepl_add_glue( syncinfo_t *si, LDAP *ld, Operation *op, Entry *e,
				Modifications *modlist, int syncstate, struct berval* syncUUID,
				struct berval* syncCookie )
{
	return;
}

#if 0
struct berval *commit_csn( Operation *op )
{
	return NULL;
}

void rewind_commit_csn( Operation *op )
{
	return;
}

void graduate_commit_csn( Operation *op )
{
	return;
}

void update_context_csn( Backend *be, struct berval *context_csn )
{
	return;
}

Entry *create_context_csn_entry( Backend *be, struct berval *context_csn )
{
	return NULL;
}
#endif
#endif

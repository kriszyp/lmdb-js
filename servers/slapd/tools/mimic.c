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
send_ldap_result(
	Connection  *conn, 
	Operation   *op,
	int     err,
	char    *matched,
	char    *text
)        
{
	assert(0);
}

void
send_ldap_search_result(
	Connection  *conn, 
	Operation   *op,
	int     err,
	char    *matched,
	char    *text,
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
	int		attrsonly
)        
{
	assert(0);
	return -1;
}

/* extended.c - ldbm backend extended routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

struct exop {
	char *oid;
	SLAP_EXTENDED_FN	extended;
} exop_table[] = {
	{ LDAP_EXOP_X_MODIFY_PASSWD, ldbm_back_exop_passwd },
	{ NULL, NULL }
};

int
ldbm_back_extended(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
	char		*reqoid,
    struct berval	*reqdata,
	char		**rspoid,
    struct berval	**rspdata,
	LDAPControl *** rspctrls,
	char**	text,
    struct berval *** refs 
)
{
	int i;

	for( i=0; exop_table[i].oid != NULL; i++ ) {
		if( strcmp( exop_table[i].oid, reqoid ) == 0 ) {
			return (exop_table[i].extended)(
				be, conn, op,
				reqoid, reqdata,
				rspoid, rspdata, rspctrls, text, refs );
		}
	}

	*text = ch_strdup("not supported within naming context");
	return LDAP_OPERATIONS_ERROR;
}


/* extended.c - bdb backend extended routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

static struct exop {
	char *oid;
	BI_op_extended	*extended;
} exop_table[] = {
	{ LDAP_EXOP_MODIFY_PASSWD, bdb_exop_passwd },
	{ NULL, NULL }
};

int
bdb_extended(
	Backend		*be,
	Connection		*conn,
	Operation		*op,
	const char		*reqoid,
	struct berval	*reqdata,
	char		**rspoid,
	struct berval	**rspdata,
	LDAPControl *** rspctrls,
	const char**	text,
	BerVarray	*refs 
)
{
	int i;

	for( i=0; exop_table[i].oid != NULL; i++ ) {
		if( strcmp( exop_table[i].oid, reqoid ) == 0 ) {
			return (exop_table[i].extended)(
				be, conn, op,
				reqoid, reqdata,
				rspoid, rspdata, rspctrls,
				text, refs );
		}
	}

	*text = "not supported within naming context";
	return LDAP_UNWILLING_TO_PERFORM;
}


/* slapcommon.h - common definitions for the slap tools */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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

#ifndef SLAPCOMMON_H_
#define SLAPCOMMON_H_ 1

#define SLAPD_TOOLS 1
#include "slap.h"

enum slaptool {
	SLAPADD=1,	/* LDIF -> database tool */
	SLAPCAT,	/* database -> LDIF tool */
	SLAPDN,		/* DN check w/ syntax tool */
	SLAPINDEX,	/* database index tool */
	SLAPPASSWD,	/* password generation tool */
	SLAPTEST,	/* slapd.conf test tool */
	SLAPAUTH,	/* test authz-regexp and authc/authz stuff */
	SLAPLAST
};

#define SLAP_TOOL_CTXCSN_KEEP	0
#define SLAP_TOOL_CTXCSN_ENTRY	1
#define SLAP_TOOL_CTXCSN_BATCH	2

typedef struct tool_vars {
	Backend *tv_be;
	int tv_verbose;
	int tv_update_ctxcsn;
	int tv_retrieve_ctxcsn;
	int tv_retrieve_synccookie;
	int tv_replica_promotion;
	int tv_replica_demotion;
	char    *tv_replica_id_string;
	char    **tv_replica_id_strlist;
	int     *tv_replica_id_list;
	int tv_continuemode;
	int tv_nosubordinates;
	int tv_dryrun;
	struct berval tv_sub_ndn;
	FILE	*tv_ldiffp;
	struct berval tv_authcID;
	struct berval tv_authzID;
} tool_vars;

extern tool_vars tool_globals;

#define	be tool_globals.tv_be
#define verbose tool_globals.tv_verbose
#define update_ctxcsn tool_globals.tv_update_ctxcsn
#define retrieve_ctxcsn tool_globals.tv_retrieve_ctxcsn
#define retrieve_synccookie tool_globals.tv_retrieve_synccookie
#define replica_promotion tool_globals.tv_replica_promotion
#define replica_demotion tool_globals.tv_replica_demotion
#define replica_id_string tool_globals.tv_replica_id_string
#define replica_id_strlist tool_globals.tv_replica_id_strlist
#define replica_id_list tool_globals.tv_replica_id_list
#define continuemode tool_globals.tv_continuemode
#define nosubordinates tool_globals.tv_nosubordinates
#define dryrun tool_globals.tv_dryrun
#define sub_ndn tool_globals.tv_sub_ndn
#define ldiffp tool_globals.tv_ldiffp
#define authcID tool_globals.tv_authcID
#define authzID tool_globals.tv_authzID

void slap_tool_init LDAP_P((
	const char* name,
	int tool,
	int argc, char **argv ));

void slap_tool_destroy LDAP_P((void));

#endif /* SLAPCOMMON_H_ */

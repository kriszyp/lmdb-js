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
#include "../slap.h"

enum slaptool {
	SLAPCAT=1,	/* database -> LDIF tool */
	SLAPADD,	/* LDIF -> database tool */
	SLAPINDEX,	/* database index tool */
	SLAPTEST	/* database testing tool */
};

#define SLAP_TOOL_CTXCSN_KEEP	0
#define SLAP_TOOL_CTXCSN_ENTRY	1
#define SLAP_TOOL_CTXCSN_BATCH	2

extern	char	*progname;
extern	char	*conffile;
extern	Backend *be;
extern	int		appendmode;
extern	int		verbose;
extern	int		update_ctxcsn;
extern	int		retrieve_ctxcsn;
extern	int		retrieve_synccookie;
extern	int		replica_promotion;
extern	int		replica_demotion;
extern	char    *replica_id_string;
extern	char    **replica_id_strlist;
extern	int     *replica_id_list;
extern	int		continuemode;
extern	int		nosubordinates;
extern	int		dryrun;
extern	struct berval	sub_ndn;

extern	char	*ldiffile;
extern	FILE	*ldiffp;

void slap_tool_init LDAP_P((
	const char* name,
	int tool,
	int argc, char **argv ));

void slap_tool_destroy LDAP_P((void));

#endif /* SLAPCOMMON_H_ */

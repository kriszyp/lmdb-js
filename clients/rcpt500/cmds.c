/* $OpenLDAP$ */
/*
 * cmds.c: command table for rcpt500 (X.500 email query responder)
 *
 * 18 June 1992 by Mark C Smith
 * Copyright (c) 1992 The Regents of The University of Michigan
 * All Rights Reserved
 */

#include "portable.h"

#include <ac/stdlib.h>
#include "rcpt500.h"

struct command cmds[] = {
	"help",		help_cmd,	/* help must be the first command */
	"query for",	query_cmd,	/* must come before "query for" */
	"query",	query_cmd,
	"find",		query_cmd,
	"read",		query_cmd,
	"search for",	query_cmd,	/* must come before "search" */
	"search",	query_cmd,
	"lookup",	query_cmd,
	"look up",	query_cmd,
	"show",		query_cmd,
	"finger",	query_cmd,
	"whois",	query_cmd,
	"who is",	query_cmd,
	"locate",	query_cmd,
	NULL,		NULL		/* end of command list */
};

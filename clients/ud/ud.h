/*
 * Copyright (c) 1991, 1992, 1993 
 * Regents of the University of Michigan.  All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#define MAX_VALUES	1000

/*****************************************************************************
 **
 **		Limits which ud imposes.  Also subject to change.
 **
 *****************************************************************************/
 
/*
 *  Names are parsed somewhat like 'awk' parses them.  This is the
 *  maximum number of components we store away.
 *
 *  The isnamesepartor() macro should return TRUE if x is equal to one of the
 *  characters that delimits name fields.  The ignorechar() macro should
 *  return TRUE if it is equal to a character that should be ignored when
 *  parsing names.
 */
#define MAX_NAME_COMPS		8
#define isnamesepartor(x)	(isspace(x))
#define isignorechar(x)		(((x) == '.') || ((x) == '_'))

/*
 *  Quite often a search will turn up more than one match.  When it does we
 *  print out a list of the matches, and ask the user to select the one that
 *  s/he wants.  This defines how many we will save and show.
 */
#define MAX_NUM_NAMES		128

/*
 *  When a user displays a group, we will automatically print out this many
 *  members and subscribers.  If the number is greater than this, we will
 *  prompt the user before printing them.
 */
#define TOO_MANY_TO_PRINT	16

/*
 *  This is the default size of a tty if we can't figure out the actual size.
 */
#define DEFAULT_TTY_HEIGHT	24
#define DEFAULT_TTY_WIDTH	80

/*
 *  The number of attributes we know about must be less than this number.
 *  Don't add lots of attributes to the list in globals.c without checking
 *  this number too.
 */
#define MAX_ATTRS	64

/*****************************************************************************
 **
 **		No user servicable parts beyond this point.
 **
 *****************************************************************************/

/*
 *  Generic buffer sizes.
 */
#define SMALL_BUF_SIZE		 16
#define MED_BUF_SIZE		128
#define LARGE_BUF_SIZE		512

/*
 *  Used to specify the operation in x_group().
 */
#define G_JOIN		0
#define G_RESIGN	1

/*
 *  Authentication method we will be using.
 */
#ifdef HAVE_KERBEROS
#define UD_AUTH_METHOD		LDAP_AUTH_KRBV4
#else
#define UD_AUTH_METHOD		LDAP_AUTH_SIMPLE
#endif

/*
 *  TRUE and FALSE - just in case we need them.
 */
#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

/*
 *  Bound status.
 */
#define UD_NOT_BOUND	0	/* bound only as the default defined above */
#define UD_BOUND	1	/* bound as an actual Directory entity */

/* 
 *  Debug masks.
 */
#define	D_TRACE		0x0001
#define	D_FIND		0x0002
#define D_GROUPS	0x0004
#define D_MODIFY	0x0008
#define D_PARSE		0x0010
#define D_PRINT		0x0020
#define D_AUTHENTICAT	0x0040
#define D_INITIALIZE	0x0080

/*
 *  Used in the flags field of an attribute structure.
 */
#define ATTR_FLAG_NONE		0x0000
#define ATTR_FLAG_PERSON	0x0001
#define ATTR_FLAG_GROUP		0x0002
#define ATTR_FLAG_PERSON_MOD	0x0010
#define ATTR_FLAG_GROUP_MOD	0x0020
#define ATTR_FLAG_MAY_EDIT	0x0040
#define ATTR_FLAG_SEARCH	0x0100
#define ATTR_FLAG_READ		0x0200
#define ATTR_FLAG_IS_A_DATE	0x0800
#define ATTR_FLAG_IS_A_DN	0x1000
#define ATTR_FLAG_IS_A_URL	0x2000
#define ATTR_FLAG_IS_A_BOOL	0x4000
#define ATTR_FLAG_IS_MULTILINE	0x8000

LDAP_BEGIN_DECL

/*
 *  These are the structures we use when parsing an answer we get from the LDAP
 *  server.
 */
struct attribute {
	char *quipu_name;
	char *output_string;
	void (*mod_func)();
	unsigned short flags;
	int number_of_values;
	char **values;
};

struct entry {
	char may_join;
	int  subscriber_count;
	char *DN;
	char *name;
	struct attribute attrs[MAX_ATTRS];
};

LDAP_END_DECL

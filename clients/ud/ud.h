/* $OpenLDAP$ */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
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
#define isnamesepartor(x)	(isspace((unsigned char) (x)))
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
	void (*mod_func) LDAP_P(( char *who, int attr_idx ));
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



/*
 * Variables
 */

/* in globals.c: */
extern struct attribute attrlist[];/* complete list of attrs */
/* in main.c: */
extern char copyright[];
extern char *default_bind_object;
extern char *bound_dn;
extern char *group_base;
extern char *search_base;	/* search base */
extern int lpp;
extern int verbose;		/* verbose mode flag */
extern int col_size;
extern int bind_status;
extern LDAP *ld;		/* our ldap descriptor */
extern LDAPFiltDesc *lfdp;	/* LDAP filter descriptor */
#ifdef DEBUG
extern int debug;		/* debug flag */
#endif
/* in print.c: */
extern struct entry Entry;
extern int	dmsize[];
/* in version.c: */
extern char Version[];


/*
 * Functions
 */

/* in auth.c: */
int  auth	LDAP_P(( char *who, int implicit ));
#if defined(HAVE_KERBEROS) && defined(_AC_KRB_H)
int  krbgetpass LDAP_P(( char *u, char *in, char *re, char *pw, C_Block key ));
void destroy_tickets LDAP_P(( void ));
#endif

/* in edit.c: */
void edit	LDAP_P(( char *who ));

/* in find.c: */
int  vrfy	LDAP_P(( char *dn ));
LDAPMessage *find	LDAP_P(( char *who, int quiet ));
int  pick_one	LDAP_P(( int i ));
void print_list	LDAP_P(( LDAPMessage *list, char **names, int *matches ));
int  find_all_subscribers	LDAP_P(( char **sub, char *group ));
char *fetch_boolean_value	LDAP_P(( char *who, struct attribute attr ));

/* in globals.c: */

/* in group.c: */
void add_group	LDAP_P(( char *name ));
void remove_group	LDAP_P(( char *name ));
void x_group	LDAP_P(( int action, char *name ));
void bulk_load	LDAP_P(( char *group ));
void purge_group	LDAP_P(( char *group ));
void tidy_up	LDAP_P(( void ));
void mod_addrDN	LDAP_P(( char *group, int offset ));
int  my_ldap_modify_s	LDAP_P(( LDAP *ldap, char *group, LDAPMod **mods ));
void list_groups	LDAP_P(( char *who ));
void list_memberships	LDAP_P(( char *who ));

/* in help.c: */
void print_help	LDAP_P(( char *s ));

/* in main.c: */
#ifdef DEBUG
#endif

void do_commands	LDAP_P(( void )) LDAP_GCCATTR((noreturn));
void status	LDAP_P(( void ));
void change_base	LDAP_P(( int type, char **base, char *s ));
void initialize_client	LDAP_P(( void ));
RETSIGTYPE  attn	LDAP_P(( int sig ));
#if !defined(NO_TERMCAP) && defined(TIOCGWINSZ)
RETSIGTYPE  chwinsz	LDAP_P(( int sig ));
#endif

/* in mod.c: */
void modify	LDAP_P(( char *who ));
void change_field	LDAP_P(( char *who, int attr_idx ));
char *get_value	LDAP_P(( char *id, char *prompt ));
void set_boolean	LDAP_P(( char *who, int attr_idx ));
#ifdef UOFM
void set_updates	LDAP_P(( char *who, int dummy ));
#endif
void print_mod_list	LDAP_P(( int group ));
int  perform_action	LDAP_P(( char *choice, char *dn, int group ));
void mod_perror	LDAP_P(( LDAP *ld ));

/* in print.c: */
void parse_answer	LDAP_P(( LDAPMessage *s ));
void add_value	LDAP_P(( struct attribute *attr, LDAPMessage *ep, char *ap ));
void print_an_entry	LDAP_P(( void ));
void print_values	LDAP_P(( struct attribute A ));
void print_DN	LDAP_P(( struct attribute A ));
void clear_entry	LDAP_P(( void ));
int  attr_to_index	LDAP_P(( char *s ));
void initialize_attribute_strings	LDAP_P(( void ));
void print_URL	LDAP_P(( struct attribute A ));
void print_one_URL	LDAP_P(( char *s, int l_lead, char *tag, int u_lead ));

/* in string_to_key.c: */
#if defined(HAVE_KERBEROS) && !defined(openbsd) && defined(_AC_KRB_H)
#if defined(HAVE_AFS_KERBEROS) || !defined(HAVE_KERBEROS_V)
void  des_string_to_key	LDAP_P(( char *str, des_cblock *key ));
#endif
#if defined(HAVE_AFS_KERBEROS)
void ka_StringToKey LDAP_P(( char *str, char *cell, des_cblock *key ));
#endif
#endif

/* in util.c: */
void printbase	LDAP_P(( char *lead, char *s ));
void fetch_buffer	LDAP_P(( char *buffer, int length, FILE *where ));
void fatal	LDAP_P(( char *s )) LDAP_GCCATTR((noreturn));
int  isgroup	LDAP_P(( void ));
void format	LDAP_P(( char *str, int width, int lead ));
void format2	LDAP_P(( char *s, char *ft, char *t, int fi, int i, int w ));
char *strip_ignore_chars	LDAP_P(( char *cp ));
char *code_to_str	LDAP_P(( int i ));
char *friendly_name	LDAP_P(( char *s ));
#ifdef UOFM
int  isauniqname	LDAP_P(( char *s ));
#endif
int  isadn	LDAP_P(( char *s ));
char *my_ldap_dn2ufn	LDAP_P(( char *s ));
int  isaurl	LDAP_P(( char *s ));
int  isadate	LDAP_P(( char *s ));
void *Malloc	LDAP_P(( unsigned int size ));
void Free	LDAP_P(( void *ptr ));
char *nextstr	LDAP_P(( char *s ));
void free_mod_struct	LDAP_P(( LDAPMod *modp ));
void StrFreeDup	LDAP_P(( char **ptr, char *new_value ));
int  confirm_action	LDAP_P(( char *msg ));

LDAP_END_DECL

/* $OpenLDAP$ */
/*
 * rcpt500.h: includes for rcpt500 (X.500 email query responder)
 *
 * 16 June 1992 by Mark C Smith
 * Copyright (c) 1992 The Regents of The University of Michigan
 * All Rights Reserved
 */

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

struct msginfo {
    char	*msg_subject;
    char	*msg_replyto;	/* actually could be from From: line */
    char	*msg_date;
    char	*msg_messageid;
    int		msg_command;
    char	*msg_arg;
};

struct command {
	char	*cmd_text;	/* text for command, e.g. "HELP" */
  	/* pointer to handler function */
	int	(*cmd_handler) LDAP_P((struct msginfo *msgp, char *reply));
};


#define MAXSIZE		8096


/*
 * functions
 */
int	help_cmd  LDAP_P((struct msginfo *msgp, char *reply));
int	query_cmd LDAP_P((struct msginfo *msgp, char *reply));

/*
 * externs
 */

/* cmds.c */
extern struct command cmds[];
/* main.c */
extern int dosyslog;
#ifdef LDAP_CONNECTIONLESS
extern int do_cldap;
#endif
extern int derefaliases;
extern int sizelimit;
extern int rdncount;
extern int ldapport;
extern char *ldaphost;
extern char *searchbase;
extern char *dapuser;
extern char *filterfile;
extern char *templatefile;

LDAP_END_DECL

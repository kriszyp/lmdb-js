/*
 * rcpt500.h: includes for rcpt500 (X.500 email query responder)
 *
 * 16 June 1992 by Mark C Smith
 * Copyright (c) 1992 The Regents of The University of Michigan
 * All Rights Reserved
 */

struct msginfo {
    char	*msg_subject;
    char	*msg_replyto;	/* actually could be from From: line */
    char	*msg_date;
    char	*msg_messageid;
    int		msg_command;
    char	*msg_arg;
};

struct command {
    char        *cmd_text;              /* text for command, e.g. "HELP" */
    int        (*cmd_handler)();        /* pointer to handler function */
};


#define MAXSIZE		8096


/*
 * functions
 */
int	help_cmd();
int	query_cmd();

/*
 * externs
 */
extern struct command cmds[];

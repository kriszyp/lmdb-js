/* shell.h - shell backend header file */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef SLAPD_SHELL_H
#define SLAPD_SHELL_H

#include "external.h"

LDAP_BEGIN_DECL

#if defined(HAVE_RECVMSG) && !defined(NO_THREADS)
#  define SHELL_SURROGATE_PARENT
#endif

#ifdef SHELL_SURROGATE_PARENT

extern ldap_pvt_thread_mutex_t shell_surrogate_index_mutex;
extern ldap_pvt_thread_mutex_t shell_surrogate_fd_mutex[2];
extern int                     shell_surrogate_fd[2];
extern pid_t                   shell_surrogate_pid;

typedef struct berval Cmd_info;
#define MAKE_CMD_INFO(args)  make_cmd_info( args )
#define IS_NULLCMD(cmd)      ((cmd).bv_val == NULL)

extern void make_surrogate_parent LDAP_P(( void ));

#else /* !SHELL_SURROGATE_PARENT */

typedef char **Cmd_info;
#define MAKE_CMD_INFO(args)  ldap_charray_dup( args )
#define IS_NULLCMD(cmd)      ((cmd) == NULL)

#endif /* SHELL_SURROGATE_PARENT */

struct shellinfo {
	Cmd_info si_bind;	/* cmd + args to exec for bind	  */
	Cmd_info si_unbind;	/* cmd + args to exec for unbind  */
	Cmd_info si_search;	/* cmd + args to exec for search  */
	Cmd_info si_compare;	/* cmd + args to exec for compare */
	Cmd_info si_modify;	/* cmd + args to exec for modify  */
	Cmd_info si_modrdn;	/* cmd + args to exec for modrdn  */
	Cmd_info si_add;	/* cmd + args to exec for add	  */
	Cmd_info si_delete;	/* cmd + args to exec for delete  */
	Cmd_info si_abandon;	/* cmd + args to exec for abandon */
};

struct slap_backend_db;
struct slap_conn;
struct slap_op;

extern pid_t forkandexec LDAP_P((
	Cmd_info args,
	FILE **rfp,
	FILE **wfp));

extern void print_suffixes LDAP_P((
	FILE *fp,
	struct slap_backend_db *bd));

extern int read_and_send_results LDAP_P((
	struct slap_backend_db *bd,
	struct slap_conn *conn,
	struct slap_op *op,
	FILE *fp,
	AttributeName *attrs,
	int attrsonly));

LDAP_END_DECL

#endif

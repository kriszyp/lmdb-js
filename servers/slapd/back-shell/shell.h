/* shell.h - shell backend header file */
/* $OpenLDAP$ */

#ifndef SLAPD_SHELL_H
#define SLAPD_SHELL_H

#include "external.h"

LDAP_BEGIN_DECL

struct shellinfo {
	char	**si_bind;	/* cmd + args to exec for bind	  */
	char	**si_unbind;	/* cmd + args to exec for unbind  */
	char	**si_search;	/* cmd + args to exec for search  */
	char	**si_compare;	/* cmd + args to exec for compare */
	char	**si_modify;	/* cmd + args to exec for modify  */
	char	**si_modrdn;	/* cmd + args to exec for modrdn  */
	char	**si_add;	/* cmd + args to exec for add	  */
	char	**si_delete;	/* cmd + args to exec for delete  */
	char	**si_abandon;	/* cmd + args to exec for abandon */
};

struct slap_backend_db;
struct slap_conn;
struct slap_op;

extern pid_t forkandexec LDAP_P((
	char **args,
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
	char **attrs,
	int attrsonly));

LDAP_END_DECL

#endif

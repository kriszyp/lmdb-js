/*
 * Copyright (c) 1994, Strata Software Limited, Ottawa, Ontario, Canada.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to Eric Rosenquist and Strata Software Limited. The SSL name
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided "as is" without express or implied warranty.
 *
 *
 * 'saucer' LDAP command-line client source code.
 *
 * Author: Eric Rosenquist, 1994.
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <lber.h>
#include <ldap.h>

#define DN_MAXLEN	4096

typedef struct {
	char	*cmd;
	int		(*func)();
	char	*help_msg;
} CMDTABLE;

typedef enum {
	CMD_HELP,
	CMD_LIST,
	CMD_MOVETO,
	CMD_QUIT,
	CMD_SEARCH,
	CMD_SET,
	CMD_SHOW
} COMMAND;

char		*attrs_null[] = { "0.10", NULL };
char		*credentials;
char		default_dn[DN_MAXLEN];
char		*hostname = "127.0.0.1";
LDAP		*ld;
extern char	*optarg;
extern int	opterr;
extern int	optind;
int			option;
int			portnum = LDAP_PORT;
char		*progname;
char		true_filter[] = "objectClass=*";	/* Always succeeds */
char		*username;

int			cmd_help(char **cmdargv, int cmdargc);
int			cmd_list(char **cmdargv, int cmdargc);
int			cmd_moveto(char **cmdargv, int cmdargc);
int			cmd_quit(char **cmdargv, int cmdargc);
int			cmd_search(char **cmdargv, int cmdargc);
int			cmd_set(char **cmdargv, int cmdargc);
int			cmd_show(char **cmdargv, int cmdargc);
char		*make_dn(char *dn, int relative);
char		*skip_to_char(register char *s, register int c);
char		*skip_to_whitespace(register char *s);
char		*skip_whitespace(register char *s);
FILE		*user_tailor(void);

static char	*binary_attrs[] = { "audio", "jpegPhoto", "personalSignature", "photo" };

CMDTABLE	cmdtable[] = {
	"help"  , cmd_help  , "[command]",
	"list"  , cmd_list  , "[RDN-or-DN] [-absolute]",
	"moveto", cmd_moveto, "[RDN-or-DN] [-absolute]",
	"quit"  , cmd_quit  , "",
	"search", cmd_search, "<filter> [-object RDN-or-DN] [-absolute]\n\t\t[-scope base|onelevel|subtree]",
	"set"   , cmd_set   , "[-aliasderef never|search|find|always] [-sizelimit N] [-timelimit seconds]",
	"show"  , cmd_show  , "[RDN-or-DN] [-absolute]"
};


int bind_user(void)
{
	if (ldap_simple_bind_s(ld, username, credentials) != LDAP_SUCCESS) {
		ldap_perror(ld, progname);
		return 0;
	}
	if (username)
		printf("Bound to ldap server as `%s' (%s authentication)\n", username,
			   credentials ? "simple" : "no");
	else
		puts("Bound anonymously to ldap server");

	return 1;
}

int cmd_help(char **cmdargv, int cmdargc)
{
	int		i;

	if (cmdargc == 2) {
		for (i = 0; i < sizeof(cmdtable) / sizeof(cmdtable[0]); i++)
			if (strncasecmp(cmdargv[1], cmdtable[i].cmd, strlen(cmdargv[1])) == 0) {
				show_syntax(i);
				return 0;
			}
		cmdargc = 1;	/* Command not found - make it display the list of commands */
	}

	if (cmdargc == 1) {
		puts("\nType 'help <command>' for help on a particular command.\n\n"
			 "Supported commands are:");
		for (i = 0; i < sizeof(cmdtable) / sizeof(cmdtable[0]); i++)
			printf("  %s\n", cmdtable[i].cmd);
		puts("\nArguments to commands are separated by whitespace.  Single (')\n"
			 "or double (\") quotes must be used around arguments that contain\n"
			 "embedded whitespace characters.\n");
	} else
		show_syntax(CMD_HELP);

	return 0;
}

int cmd_list(char **cmdargv, int cmdargc)
{
	char		*dn      = NULL;
	int			errflag  = 0;
	int			i;
	static char	*opts[]  = { "absolute" };
	int			relative = 1;
	LDAPMessage	*result;

	for (i = 1; i < cmdargc; i++) {
		if (cmdargv[i][0] == '-') {
			switch (table_lookup(cmdargv[i] + 1, opts, sizeof(opts) / sizeof(opts[0]))) {
			case 0:
				relative = 0;
				break;
			default:
				errflag = 1;
			}
		} else {
			if (dn)
				errflag = 1;
			else
				dn = cmdargv[i];
		}
	}

	if (errflag) {
		show_syntax(CMD_LIST);
		return 0;
	}

	if (ldap_search(ld, make_dn(dn, relative), LDAP_SCOPE_ONELEVEL,
					true_filter, attrs_null, 1) == -1) {
		ldap_perror(ld, progname);
		return 0;
	}

	if (ldap_result(ld, LDAP_RES_ANY, 1, (struct timeval *)0, &result) == -1) {
		ldap_perror(ld, progname);
		return 0;
	}

	display_search_results(result);
		
	return 0;
}

int cmd_moveto(char **cmdargv, int cmdargc)
{
	char		*dn      = NULL;
	int			errflag  = 0;
	char		**exploded_dn;
	int			i;
	static char	*opts[]  = { "absolute" };
	int			relative = 1;

	for (i = 1; i < cmdargc; i++) {
		if (cmdargv[i][0] == '-') {
			switch (table_lookup(cmdargv[i] + 1, opts, sizeof(opts) / sizeof(opts[0]))) {
			case 0:
				relative = 0;
				break;
			default:
				errflag = 1;
			}
		} else {
			if (dn)
				errflag = 1;
			else
				dn = cmdargv[i];
		}
	}

	if (errflag) {
		show_syntax(CMD_MOVETO);
		return 0;
	}

	if (dn) {
		if (is_whitespace(dn))
			default_dn[0] = 0;
		else {
			if (strcmp(dn, "..") == 0) {
				/* Move up one level */
				if (exploded_dn = ldap_explode_dn(default_dn, 0)) {
					if (exploded_dn[0]) {
						char	**rdn;

						default_dn[0] = 0;
						for (rdn = exploded_dn + 1; *rdn; rdn++) {
							if (default_dn[0])
								strcat(default_dn, ", ");
							strcat(default_dn, *rdn);
						}
					}
					ldap_value_free(exploded_dn);
				}
			} else {
				/* Use ldap_explode_dn() to parse the string & test its syntax */
				if (exploded_dn = ldap_explode_dn(dn, 1)) {
					if (relative  &&  !is_whitespace(default_dn)) {
						char	buf[DN_MAXLEN];

						strcpy(default_dn, strcat(strcat(strcpy(buf, dn), ", "), default_dn));
					} else
						strcpy(default_dn, dn);
					ldap_value_free(exploded_dn);
				} else
					puts("Invalid distinguished name.");
			}
		}
	}

	printf("Distinguished name suffix is `%s'\n", default_dn);

	return 0;
}

int cmd_quit(char **cmdargv, int cmdargc)
{
	return 1;
}

int cmd_search(char **cmdargv, int cmdargc)
{
	char		*dn           = NULL;
	int			errflag       = 0;
	char		*filter       = NULL;
	int			i, j;
	static char	*opts[]       = { "absolute", "object", "scope" };
	int			relative      = 1;
	LDAPMessage	*result;
	static char	*scope_opts[] = { "base", "onelevel", "subtree" };
	static int	scope_vals[]  = { LDAP_SCOPE_BASE, LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE };
	static int	search_scope  = LDAP_SCOPE_ONELEVEL;

	for (i = 1; i < cmdargc; i++) {
		if (cmdargv[i][0] == '-') {
			switch (table_lookup(cmdargv[i] + 1, opts, sizeof(opts) / sizeof(opts[0]))) {
			case 0:
				relative = 0;
				break;
			case 1:
				if (++i < cmdargc)
					dn = cmdargv[i];
				else
					errflag = 1;
				break;
			case 2:
				if ((++i < cmdargc)  &&
					(j = table_lookup(cmdargv[i], scope_opts, sizeof(scope_opts) / sizeof(scope_opts[0]))) >= 0)
					search_scope = scope_vals[j];
				else
					errflag = 1;
				break;
			default:
				errflag = 1;
			}
		} else {
			if (filter)
				errflag = 1;
			else
				filter = cmdargv[i];
		}
	}

	if (errflag  ||  !filter) {
		show_syntax(CMD_SEARCH);
		return 0;
	}

	if (ldap_search(ld, make_dn(dn, relative), search_scope, filter, attrs_null, 0) == -1) {
		ldap_perror(ld, progname);
		return 0;
	}

	if (ldap_result(ld, LDAP_RES_ANY, 1, (struct timeval *)0, &result) == -1) {
		ldap_perror(ld, progname);
		return 0;
	}

	display_search_results(result);
		
	return 0;
}

int cmd_set(char **cmdargv, int cmdargc)
{
	static char	*alias_opts[] = { "never", "search", "find", "always" };
	int			errflag       = 0;
	int			i, j;
	static char	*opts[]       = { "aliasderef", "sizelimit", "timelimit" };

	for (i = 1; i < cmdargc; i++) {
		if (cmdargv[i][0] == '-') {
			switch (table_lookup(cmdargv[i] + 1, opts, sizeof(opts) / sizeof(opts[0]))) {
			case 0:
				if ((++i < cmdargc)  &&
					(j = table_lookup(cmdargv[i], alias_opts, sizeof(alias_opts) / sizeof(alias_opts[0]))) >= 0)
					ld->ld_deref = j;
				else
					errflag = 1;
				break;
			case 1:
				if (++i < cmdargc)
					ld->ld_sizelimit = atoi(cmdargv[i]);
				else
					errflag = 1;
				break;
			case 2:
				if (++i < cmdargc)
					ld->ld_timelimit = atoi(cmdargv[i]);
				else
					errflag = 1;
				break;
			default:
				errflag = 1;
			}
		} else
			errflag = 1;
	}

	if (errflag)
		show_syntax(CMD_SET);
	else
		printf("Alias dereferencing is %s, Sizelimit is %d entr%s, Timelimit is %d second%s.\n",
			   alias_opts[ld->ld_deref],
			   ld->ld_sizelimit, ld->ld_sizelimit == 1 ? "y" : "ies",
			   ld->ld_timelimit, ld->ld_timelimit == 1 ? ""  : "s");

	return 0;
}

int cmd_show(char **cmdargv, int cmdargc)
{
	char		*dn      = NULL;
	LDAPMessage	*entry;
	int			errflag  = 0;
	int			i;
	static char	*opts[]  = { "absolute" };
	int			relative = 1;
	LDAPMessage	*result;

	for (i = 1; i < cmdargc; i++) {
		if (cmdargv[i][0] == '-') {
			switch (table_lookup(cmdargv[i] + 1, opts, sizeof(opts) / sizeof(opts[0]))) {
			case 0:
				relative = 0;
				break;
			default:
				errflag = 1;
			}
		} else {
			if (dn)
				errflag = 1;
			else
				dn = cmdargv[i];
		}
	}

	if (errflag) {
		show_syntax(CMD_SHOW);
		return 0;
	}

	if (ldap_search(ld, make_dn(dn, relative), LDAP_SCOPE_BASE, true_filter, NULL, 0) == -1) {
		ldap_perror(ld, progname);
		return 0;
	}

	if (ldap_result(ld, LDAP_RES_ANY, 1, (struct timeval *)0, &result) == -1) {
		ldap_perror(ld, progname);
		return 0;
	}

	display_search_results(result);
		
	return 0;
}

display_search_results(LDAPMessage *result)
{
	BerElement	*cookie;
	int			i;
	LDAPMessage	*entry;
	int			maxname;
	char		*s;

	for (entry = ldap_first_entry(ld, result); entry; entry = ldap_next_entry(ld, entry)) {
		if (s = ldap_get_dn(ld, entry)) {
			printf("  %s\n", s);
			free(s);
		}

		/* Make one pass to calculate the length of the longest attribute name */
		maxname = 0;
		for (s = ldap_first_attribute(ld, entry, &cookie); s; s = ldap_next_attribute(ld, entry, cookie))
			if ((i = strlen(s)) > maxname)
				maxname = i;

		/* Now print the attributes and values */
		for (s = ldap_first_attribute(ld, entry, &cookie); s; s = ldap_next_attribute(ld, entry, cookie)) {
			char	**values;

			if (table_lookup(s, binary_attrs, sizeof(binary_attrs) / sizeof(binary_attrs[0])) >= 0)
				continue;	/* Skip this attribute - it's binary */

			printf("    %-*s - ", maxname, s);

			/* Now print each of the values for the given attribute */
			if (values = ldap_get_values(ld, entry, s)) {
				char	**val;

				for (val = values; *val; ) {
					char	*nl;
					char	*v = *val;

					/* Watch out for values that have embedded \n characters */
					while (nl = strchr(v, '\n')) {
						*nl = 0;
						puts(v);
						v = nl + 1;
						if (*v)
							printf("    %*s", maxname + 3, "");
					}
					if (*v)
						puts(v);
					if (*++val)
						printf("    %*s", maxname + 3, "");
				}
				ldap_value_free(values);
			} else
				putchar('\n');
		}
	}

	if (ldap_result2error(ld, result, 0))
		ldap_perror(ld, progname);
}

int do_command(char *cmd)
{
	char	*cmdargv[128];
	int		cmdargc = 0;
	int		i;

	/* Tokenize the input command, allowing for quoting */
	for (;;) {
		cmd = skip_whitespace(cmd);
		if (!cmd  ||  !*cmd)
			break;	/* end of input */

		cmdargv[cmdargc++] = cmd;
		if (*cmd == '\''  ||  *cmd == '"') {
			cmdargv[cmdargc - 1]++;		/* Skip over the opening quote */
			cmd = skip_to_char(cmd + 1, *cmd);
			if (!cmd  ||  !*cmd) {
				puts("Command is missing a trailing quote");
				return 0;
			}
			*cmd++ = 0;
		} else {
			cmd = skip_to_whitespace(cmd);
			if (cmd  &&  *cmd)
				*cmd++ = 0;
		}
	}

#ifdef DEBUG
	printf("cmdargc = %d\n", cmdargc);
	for (i = 0; i < cmdargc; i++)
		puts(cmdargv[i]);
#endif
	
	if (cmdargv[0][0] == '?')
		return cmd_help(cmdargv, cmdargc);

	for (i = 0; i < sizeof(cmdtable) / sizeof(cmdtable[0]); i++)
		if (strncasecmp(cmdargv[0], cmdtable[i].cmd, strlen(cmdargv[0])) == 0)
			return (*cmdtable[i].func)(cmdargv, cmdargc);

	if (!is_whitespace(cmdargv[0])) {
		printf("Unrecognized command - %s\n", cmdargv[0]);
		cmd_help(cmdargv, 1);
	}

	return 0;
}

void do_commands(FILE *file)
{
	char	cmd_buf[BUFSIZ];
	int		tty = isatty(fileno(file));

	for (;;) {
		if (tty)
			printf("Cmd? ");
		if (!fgets(cmd_buf, sizeof(cmd_buf), file))
			break;
		if (do_command(cmd_buf))
			break;
	}
}

int is_whitespace(register char *s)
{
	if (!s)
		return 1;

	while (*s  &&  isspace((unsigned char) *s))
		++s;

	return !*s;
}

int main(int argc, char **argv)
{
	int		error_flag = 0;
	FILE	*rc;

	progname = argv[0];
	while ((option = getopt(argc, argv, "h:p:u:c:d:")) != EOF)
		switch (option) {
		case 'c':
			credentials = optarg;
			break;
		case 'd':
#ifdef LDAP_DEBUG
			lber_debug = atoi(optarg);
			ldap_debug = atoi(optarg);
#endif
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'p':
			portnum = atoi(optarg);
			break;
		case 'u':
			username = optarg;
			break;
		case '?':
			error_flag = 1;
		}

	if (error_flag) {
		fprintf(stderr, "usage: %s [-h host] [-p portnumber] [-u X500UserName]\n\t[-c credentials] [-d debug-level]\n",
				progname);
		exit(2);
	}

	rc = user_tailor();

	if (!(ld = ldap_open(hostname, portnum))) {
		fprintf(stderr, "%s: unable to connect to server at host `%s' on port %d\n",
				progname, hostname, portnum);
		exit(2);
	}

	if (!bind_user())
		return 1;

	if (rc) {
		do_commands(rc);
		fclose(rc);
	}
	do_commands(stdin);

	ldap_unbind(ld);

	return 0;
}

char *make_dn(char *dn, int relative)
{
	static char	dn_buf[DN_MAXLEN];
	char		*s;

	if (!dn)
		dn = "";

	if (!default_dn[0]  ||  !relative)
		return dn;

	if (!dn[0])
		return default_dn;

	return strcat(strcat(strcpy(dn_buf, dn), ", "), default_dn);
}

show_syntax(int cmdnum)
{
	printf("Syntax: %s %s\n", cmdtable[cmdnum].cmd, cmdtable[cmdnum].help_msg);
}

char *skip_to_char(register char *s, register int c)
{
	if (!s)
		return s;

	while (*s  &&  *s != c)
		++s;

	return s;
}

char *skip_to_whitespace(register char *s)
{
	if (!s)
		return s;

	while (*s  &&  !isspace((unsigned char) *s))
		++s;

	return s;
}

char *skip_whitespace(register char *s)
{
	if (!s)
		return s;

	while (*s  &&  isspace((unsigned char) *s))
		++s;

	return s;
}

int table_lookup(char *word, char **table, int table_count)
{
	register int	i;
	int				wordlen;

	if (!word  ||  !*word)
		return -1;

	wordlen = strlen(word);

	for (i = 0; i < table_count; i++)
		if (strncasecmp(word, table[i], wordlen) == 0)
			return i;
	return -1;
}

FILE *user_tailor(void)
{
	char	rcfile[BUFSIZ];

	rcfile[0] = 0;

#ifdef unix
	{
#include <pwd.h>
		struct passwd	*pwent;

		if (pwent = getpwuid(getuid()))
			strcat(strcpy(rcfile, pwent->pw_dir), "/");
		strcat(rcfile, ".saucerrc");
	}
#else
	strcpy(rcfile, "saucer.rc");
#endif

	return fopen(rcfile, "r");
}

/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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
 *
 * The University of Michigan would like to thank the following people for
 * their contributions to this piece of software:
 *
 *	Robert Urquhart    <robert@sfu.ca>
 *	Simon Fraser University, Academic Computing Services
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <setjmp.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include <ac/signal.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/termios.h>
#include <ac/time.h>
#include <ac/unistd.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include <lber.h>
#include <ldap.h>

#include "ldap_defaults.h"
#include "ud.h"

/*
 *  Used with change_base() to indicate which base we are changing.
 */
#define BASE_SEARCH     0
#define BASE_GROUPS     1

#define	iscom(x)	(!strncasecmp((x), cmd, strlen(cmd)))

static char *server = NULL;
static char *config_file = UD_CONFIG_FILE;
static char *filter_file = FILTERFILE;
static int ldap_port = 0;
static int dereference = TRUE;

char *default_bind_object = NULL;

char *bound_dn;			/* bound user's Distinguished Name */
char *group_base;		/* place in LDAP tree where groups are */
char *search_base;		/* place in LDAP tree where searches start */

static jmp_buf env;		/* spot to jump to on an interrupt */

int lpp;			/* lines per page */
int verbose;			/* 1 if verbose mode on */
int col_size;			/* characters across on the screen */
int bind_status;		/* user's bind status */

LDAP *ld;			/* LDAP descriptor */
LDAPFiltDesc *lfdp;		/* LDAP filter descriptor */

#ifdef DEBUG
int debug;			/* debug flag */
#endif
int ldebug;			/* library debug flag */

#ifndef HAVE_MKVERSION
char Version[] = OPENLDAP_PACKAGE " " OPENLDAP_VERSION " UserDirectory (ud)";
#endif

int
main( int argc, char **argv )
{
	register int c;				/* for parsing argv */
	register char *cp;			/* for parsing Version */

	verbose = 1;

	/*  handle argument list */
	while ((c = getopt(argc, argv, "c:d:Df:l:p:s:u:vV")) != -1) {
		switch (c) {
		case 'l' :
			ldebug |= (int) strtol(optarg, (char **) NULL, 0);
			break;
		case 'd' :
#ifdef DEBUG
			debug |= (int) strtol(optarg, (char **) NULL, 0);
#endif
			break;
		case 's' :
			server = strdup(optarg);
			break;
		case 'c' :
			filter_file = strdup(optarg);
			break;
		case 'f' :
			config_file = optarg;
			break;
		case 'p' :
			ldap_port = atoi(optarg);
			break;
		case 'u' :
			default_bind_object = strdup(optarg);
			break;
		case 'v' :
			verbose = 1;	/* this is the default anyways... */
			break;
		case 'V' :
			verbose = 0;
			break;
		case 'D' :
			printf("\n\n  Debug flag values\n\n");
			printf("    1  function trace\n");
			printf("    2  find() information\n");
			printf("    4  group information\n");
			printf("    8  mod() information\n");
			printf("   16  parsing information\n");
			printf("   32  output information\n");
			printf("   64  authentication information\n");
			printf("  128  initialization information\n\n");
			format("These are masks, and may be added to form multiple debug levels.  For example, '-d 35' would perform a function trace, print out information about the find() function, and would print out information about the output routines too.", 75, 2);
			exit( EXIT_SUCCESS );
		default:
			fprintf(stderr, "Usage: %s [-c filter-config-file] [-d debug-level] [-l ldap-debug-level] [-s server] [-p port] [-V]\n", argv[0]);
			exit( EXIT_FAILURE);
			/* NOTREACHED */
		}
	}

	/* just print the first line of Version[] */
	cp = strchr(Version, '\t');
	if (cp != NULL)
		*cp = '\0';
	printf(Version);
	fflush( stdout );

#ifdef SIGPIPE
	(void) SIGNAL (SIGPIPE, SIG_IGN);
#endif

	initialize_client();
	initialize_attribute_strings();

	/* now tackle the user's commands */
	do_commands();
	/* NOTREACHED */

	return 0;
}

void
do_commands( void )
{
	LDAPMessage *mp;			/* returned by find() */
	register char *cp;			/* misc char pointer */
	register char *ap;			/* misc char pointer */
	static char cmd[MED_BUF_SIZE];		/* holds the command */
	static char input[MED_BUF_SIZE];	/* buffer for input */

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->do_commands()\n");
#endif
	if (verbose) 
		printf("\n  Enter a command.  If you need help, type 'h' or '?' and hit RETURN.\n\n");
	/* jump here on an interrupt */
	(void) setjmp(env);
	for (;;) {
		printf("* ");
		fflush(stdout);
		cp = input;
/* Temporary kludge - if cp is null, dumps core under Solaris */
		if (cp == NULL)
			break;
		fetch_buffer(input, sizeof(input), stdin);
		if (*input == '\0') {
			putchar('\n');
			continue;
		}
		while (isspace((unsigned char)*cp))
			cp++;	
		ap = cmd;
		if (memset(cmd, '\0', sizeof(cmd)) == NULL)
			fatal("memset");
		while (!isspace((unsigned char)*cp) && (*cp != '\0'))
			*ap++ = *cp++;
		if (iscom("status"))
			status();
		else if (iscom("stop") || iscom("quit"))
			break;
		else if (iscom("cb") || iscom("cd") || iscom("moveto")) {
			while (isspace((unsigned char)*cp) && (*cp != '\0'))
				cp++;
			if (!strncasecmp(cp, "base", 4))
				cp += 4;
			change_base(BASE_SEARCH, &search_base, nextstr(cp));
		}
		else if (iscom("memberships"))
			(void) list_memberships(nextstr(cp));
		else if (iscom("list"))
			(void) list_groups(nextstr(cp));
		else if (iscom("groupbase"))
			change_base(BASE_GROUPS, &group_base, nextstr(cp));
		else if (iscom("find") || iscom("display") || iscom("show")) {
			cp = nextstr(cp);
			if ((mp = find(cp, FALSE)) != NULL) {
				parse_answer(mp);
				print_an_entry();
				ldap_msgfree(mp);
			}
			else
				printf(" Could not find \"%s\".\n", cp);
		}
#ifdef UOFM
		else if (iscom("vedit") && isatty( 1 )) {
#else
		else if (iscom("vedit")) {
#endif
			(void) edit(nextstr(cp));
		}
		else if (iscom("modify") || iscom("change") || iscom("alter"))
			(void) modify(nextstr(cp));
		else if (iscom("bind") || iscom("iam"))
			(void) auth(nextstr(cp), 0);
		else if ((cmd[0] == '?') || iscom("help"))
			print_help(nextstr(cp));
		else if (iscom("join") || iscom("subscribe")) 
			(void) x_group(G_JOIN, nextstr(cp));
		else if (iscom("resign") || iscom("unsubscribe"))
			(void) x_group(G_RESIGN, nextstr(cp));
		else if (!strncasecmp("create", cmd, strlen(cmd)))
			add_group(nextstr(cp));
		else if (!strncasecmp("remove", cmd, strlen(cmd)))
			remove_group(nextstr(cp));
		else if (!strncasecmp("purge", cmd, strlen(cmd)))
			purge_group(nextstr(cp));
		else if (!strncasecmp("verbose", cmd, strlen(cmd))) {
			verbose = 1 - verbose;
			if (verbose)
				printf("  Verbose mode has been turned on.\n");
		}
		else if (!strncasecmp("dereference", cmd, strlen(cmd))) {
			int deref;
			dereference = 1 - dereference;
			if (dereference == 1) {
				deref = LDAP_DEREF_ALWAYS;
			} else {
				deref = LDAP_DEREF_NEVER;
			}
			ldap_set_option(ld, LDAP_OPT_DEREF, (void *) &deref);
		}
		else if (!strncasecmp("tidy", cmd, strlen(cmd)))
			tidy_up();
		else if (cmd[0] == '\0')
			putchar('\n');
		else
			printf("  Invalid command.  Type \"help commands.\"\n");
	}
	printf(" Thank you!\n");
	
	ldap_unbind(ld);
#ifdef HAVE_KERBEROS
	destroy_tickets();
#endif
	exit( EXIT_SUCCESS );
	/* NOTREACHED */
}

void
status( void )
{
	register char **rdns;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->status()\n");
#endif
	printf("  Current server is %s", server != NULL ? server : "<default>" );
	if ( ld != NULL ) {
		char *host = NULL;
		
		ldap_get_option(ld, LDAP_OPT_HOST_NAME, &host);

		if ( host != NULL &&
			( server == NULL || strcasecmp( host, server ) != 0 ) )
		{
			printf( " (%s)", host );
		}
	}
	putchar( '\n' );
	printbase("  Search base is ", search_base);
	printbase("  Group  base is ", group_base);
	if ( bound_dn != NULL ) {
		rdns = ldap_explode_dn(bound_dn, TRUE);
		printf("  Bound as \"%s\"\n", *rdns);
		ldap_value_free(rdns);
	} else {
		printf("  Bound as Nobody\n" );
	}
	printf( "  Verbose mode is %sabled\n", ( verbose ? "en" : "dis" ));
	if ( ld != NULL ) {
		int deref = LDAP_DEREF_NEVER;
		ldap_get_option(ld, LDAP_OPT_DEREF, &deref);
		printf( "  Aliases are %sbeing dereferenced\n",
			( deref == LDAP_DEREF_ALWAYS ) ? "" : "not" );
	}
}

void
change_base( int type, char **base, char *s )
{
	register char *cp;			/* utility pointers */
	char **rdns;				/* for parsing */
	char *output_string;			/* for nice output */
	int num_picked;				/* # of selected base */
	int j;					/* used with num_picked */
	int i = 1;				/* index into choices array */
	int matches;				/* # of matches found */
	int rest = 1;				/* # left to display */
	char tmp[MED_BUF_SIZE];			/* temporary buffer */
	static char *choices[MED_BUF_SIZE];	/* bases from which to choose */
	static char resp[SMALL_BUF_SIZE];	/* for prompting user */
	static char buf[MED_BUF_SIZE];
	static char *attrs[] = { "objectClass", NULL };
	LDAPMessage *mp;			/* results from a search */
	LDAPMessage *ep;			/* for going thru bases */

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->change_base(%s, %s)\n", s, s);
#endif
	/*
	 *  If s is NULL we need to prompt the user for an argument.
	 */
	if (s == NULL) {
		if (verbose) {
			printf("  You need to specify how the base is to be changed.  Valid choices are:\n");
			printf("     ?       - list the choices immediately below this level\n");
			printf("     ..      - move up one level in the Directory tree\n");
			printf("     root    - move to the root of the Directory tree\n");
			printf("     default - move to the default level built into this program\n");
			printf("     <entry> - move to the entry specified\n");
		}
		printf("  Change base to? ");
		fflush(stdout);
		fetch_buffer(buf, sizeof(buf), stdin);
		if ((buf != NULL) && (buf[0] != '\0'))
			s = buf;
		else
			return;
	}

	/* set the output string */
	if (type == BASE_SEARCH)
		output_string = "  Search base is now ";
	else if (type == BASE_GROUPS)
		output_string = "  Group base is now ";

	if (!strcasecmp(s, "root")) {
		StrFreeDup(base, NULL);
		printbase("  Search base is ", *base);
		return;
	}

	/*
	 *  User wants to ascend one level in the LDAP tree.
	 *  Easy:  Just strip off the first element of the
	 *  current search base, unless it's the root, in
	 *  which case we just do nothing.
	 */
	if (!strcasecmp(s, "..")) {
		if (*base == NULL) {
			printf("  You are already at the root\n");
			return;
		}
		cp = strchr(*base, '=');
		cp++;
		/*
		 *  If there isn't a second "=" in the base, then this was
		 *  a one element base, and so now it should be NULL.
		 */
		if ((cp = strchr(cp, '=')) == NULL)
			StrFreeDup(base, NULL);
		else {
			/*
			 *  Back up to the start of this
			 *
			 *	attr=value
			 *
			 *  sequence now that 'cp' is pointing to the '='.
			 */
			while(!isspace((unsigned char)*cp))
				cp--;
			cp++;
			/*
			 *  Goofy, but need to do it this way since both *base
			 *  and cp point into the same chunk of memory, and
			 *  we want to free *base, but keep part of it around.
			 */
			cp = strdup(cp);
			StrFreeDup(base, cp);
			Free(cp);
		}
		printbase(output_string, *base);
		return;
	}

	/* user wants to see what is directly below this level */
	if (*s == '?') {
		/*
		 *  Fetch the list of entries directly below this level.
		 *  Once we have the list, we will print it for the user, one
		 *  screenful at a time.  At the end of each screen, we ask
		 *  the user if they want to see more.  They can also just
		 *  type a number at that point too.
		 */
		if (ldap_search_s(ld, *base, LDAP_SCOPE_ONELEVEL, "(|(objectClass=quipuNonLeafObject)(objectClass=externalNonLeafObject))", attrs, FALSE, &mp) != LDAP_SUCCESS) {
			int ld_errno = 0;
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
			if ((ld_errno == LDAP_TIMELIMIT_EXCEEDED) ||
			    (ld_errno == LDAP_SIZELIMIT_EXCEEDED)) {
				if (verbose) {
					printf("  Your query was too general and a limit was exceeded.  The results listed\n");
					printf("  are not complete.  You may want to try again with a more refined query.\n\n");
				}
				else
					printf("  Time or size limit exceeded.  Partial results follow.\n\n");
			} else {
				ldap_perror(ld, "ldap_search_s");
				return;
			}
		}
		if ((matches = ldap_count_entries(ld, mp)) < 1) {
			printf("  There is nothing below this level.\n");
			(void) ldap_msgfree(mp);
			return;
		}
		num_picked = 0;
		printf(" There are %d choices:\n", matches);
		for (ep = ldap_first_entry(ld, mp); ep != NULL; ep = ldap_next_entry(ld, ep)) {
			/*
			 *  Put the last component of the DN into 'lastDN'.
			 *  If we are at the root level, convert any country
			 *  codes to recognizable names for printing.
			 */
			choices[i] = ldap_get_dn(ld, ep);
			rdns = ldap_explode_dn(choices[i], TRUE);
			printf(" %2d. %s\n", i, friendly_name(*rdns));
			(void) ldap_value_free(rdns);
			i++;
			if ((rest++ > (lpp - 3)) && (i < matches)) {
				printf("More? ");
				fflush(stdout);
				fetch_buffer(resp, sizeof(resp), stdin);
				if ((resp[0] == 'n') || (resp[0] == 'N'))
					break;
				else if (((num_picked = atoi(resp)) != 0) && (num_picked < i))
					break;
				rest = 1;
			}
		}
		for (;;) {
			if (num_picked != 0) {
				j = num_picked;
				num_picked = 0;
			}
			else {
				printf(" Which number? ");
				fflush(stdout);
				fetch_buffer(resp, sizeof(resp), stdin);
				j = atoi(resp);
			}
			if (j == 0) {
				(void) ldap_msgfree(mp);
				for (i = 0; i < matches; i++)
					ldap_memfree(choices[i]);
				return;
			}
			if ((j < 1) || (j >= i))
				printf(" Invalid number\n");
			else {
				StrFreeDup(base, choices[j]);
				printbase(output_string, *base);
				(void) ldap_msgfree(mp);
				for (i = 0; choices[i] != NULL; i++)
					ldap_memfree(choices[i]);
				return;
			}
		}
	}
	/* set the search base back to the original default value */
	else if (!strcasecmp(s, "default")) {
		if (type == BASE_SEARCH)
			StrFreeDup(base, NULL);
		else if (type == BASE_GROUPS)
			StrFreeDup(base, UD_WHERE_GROUPS_ARE_CREATED);
		printbase(output_string, *base);
	}
	/* they typed in something -- see if it is legit */
	else {
		/* user cannot do something like 'cb 33' */
		if (atoi(s) != 0) {
			printf("  \"%s\" is not a valid search base\n", s);
			printf("  Base unchanged.\n");
			printf("  Try using 'cb ?'\n");
			return;
		}
		/* was it a fully-specified DN? */
		if (vrfy(s)) {
			StrFreeDup(base, s);
			printbase(output_string, *base);
			return;
		}
		/* was it a RDN relative to the current base? */
		sprintf(tmp, "ou=%s, %s", s, *base);
		if (vrfy(tmp)) {
			StrFreeDup(base, tmp);
			printbase(output_string, *base);
			return;
		}
		printf("  \"%s\" is not a valid base\n  Base unchanged.\n", s);
	}
}

void
initialize_client( void )
{
	FILE *fp;				/* for config file */
	static char buffer[MED_BUF_SIZE];	/* for input */
#ifdef HAVE_GETPWUID
	struct passwd *pw;			/* for getting the home dir */
#endif
	register char *cp;			/* for fiddling with buffer */
	char *config;				/* config file to use */
	static char bp[1024];			/* for tty set-up */

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->initialize_client()\n");
#endif

	if (ldebug) {
		ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ldebug );
		ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &ldebug );
	}

	/*
	 *  A per-user config file has precedence over any system-wide
	 *  config file, if one exists.
	 */
#ifdef HAVE_GETPWUID
	if ((pw = getpwuid((uid_t) geteuid())) == (struct passwd *) NULL)
		config = config_file;
	else {
		if (pw->pw_dir == NULL)
			config = config_file;
		else {
			sprintf(buffer, "%s/%s", pw->pw_dir,
			    UD_USER_CONFIG_FILE);
			if (access(buffer, R_OK) == 0)
				config = buffer;
			else
				config = config_file;
		}
	}
#else
	config = config_file;
#endif /* getpwduid() */
#ifdef DEBUG
	if (debug & D_INITIALIZE)
		printf("Using config file %s\n", config);
#endif

	/*
	 *  If there is a config file, read it.
	 *
	 *  Could have lines that look like this:
	 *
	 *	server <ip-address or domain-name>
	 *	base   <default search base>
	 *	groupbase <default place where groups are created>
	 *
	 */
	if ((fp = fopen(config, "r")) != NULL) {
		while (fgets(buffer, sizeof(buffer), fp) != NULL) {
			buffer[strlen(buffer) - 1] = '\0';
			if (!strncasecmp(buffer, "server", 6)) {
				if (server != NULL)
					continue;
				cp = buffer + 6;
				while (isspace((unsigned char)*cp))
					cp++;
				if ((*cp == '\0') || (*cp == '\n'))
					continue;
				server = strdup(cp);
			} 
			else if (!strncasecmp(buffer, "host", 4)) {
				if (server != NULL)
					continue;
				cp = buffer + 4;
				while (isspace((unsigned char)*cp))
					cp++;
				if ((*cp == '\0') || (*cp == '\n'))
					continue;
				server = strdup(cp);
			}
			else if (!strncasecmp(buffer, "base", 4)) {
				cp = buffer + 4;
				while (isspace((unsigned char)*cp))
					cp++;
				if ((*cp == '\0') || (*cp == '\n'))
					continue;
				search_base = strdup(cp);
			}
			else if (!strncasecmp(buffer, "groupbase", 9)) {
				cp = buffer + 9;
				while (isspace((unsigned char)*cp))
					cp++;
				if ((*cp == '\0') || (*cp == '\n'))
					continue;
				group_base = strdup(cp);
			}
			else
				fprintf(stderr, "?? -> %s\n", buffer);
		}
	}
	if (group_base == NULL)
		group_base = strdup(UD_WHERE_GROUPS_ARE_CREATED);

	/*
	 *  Set up our LDAP connection.  The values of retry and timeout
	 *  are meaningless since we will immediately be doing a null bind
	 *  because we want to be sure to use TCP, not UDP.
	 */
	if ((ld = ldap_init(server, ldap_port)) == NULL) {
		fprintf(stderr, "  Initialization of LDAP session failed.\n");
		exit( EXIT_FAILURE );
		/* NOTREACHED */
	}
	if (ldap_bind_s(ld, (char *) default_bind_object, NULL,
	    LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
		int ld_errno = 0;
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);

		fprintf(stderr, "  The LDAP Directory is temporarily unavailable.  Please try again later.\n");
		if (ld_errno != LDAP_UNAVAILABLE)
			ldap_perror(ld, "  ldap_bind_s");
		exit( EXIT_FAILURE );
		/* NOTREACHED */
	}
	{
		int deref = LDAP_DEREF_ALWAYS;
		ldap_set_option(ld, LDAP_OPT_DEREF, (void *) &deref);
	}
	bind_status = UD_NOT_BOUND;
	if ( default_bind_object != NULL ) {
		bound_dn = strdup(default_bind_object);
	} else {
		bound_dn = NULL;
	}

	/* enabled local caching of ldap results, 15 minute lifetime */
	ldap_enable_cache( ld, 60 * 15, 0 );		/* no memory limit */

	/* initialize the search filters */
	if ((lfdp = ldap_init_getfilter(filter_file)) == NULL) {
		fprintf(stderr, "  Problem with ldap_init_getfilter\n");
		fatal(filter_file);
		/*NOTREACHED*/
	}

	/* terminal initialization stuff goes here */
	lpp = DEFAULT_TTY_HEIGHT;
	col_size = DEFAULT_TTY_WIDTH;

	(void) SIGNAL (SIGINT, attn);

#ifndef NO_TERMCAP
	{
	char *term;

	if (((term = getenv("TERM")) == NULL) || (tgetent(bp, term) <= 0))
		return;
	else {
#ifdef TIOCGWINSZ
		struct winsize win;		/* for tty set-up */
		if (ioctl(fileno(stdout), TIOCGWINSZ, &win) >= 0) {
			if ((lpp = win.ws_row) == 0)
				lpp = tgetnum("li");
			if ((col_size = win.ws_col) == 0)
				col_size = tgetnum("co");
			if ((lpp <= 0) || tgetflag("hc"))
				lpp = DEFAULT_TTY_HEIGHT;
			if ((col_size <= 0) || tgetflag("hc"))
				col_size = DEFAULT_TTY_WIDTH;
			(void) SIGNAL (SIGWINCH, chwinsz);
		} else
#endif
		{
			lpp = tgetnum("li");
			col_size = tgetnum("co");
		}
	}
	}
#endif
}

RETSIGTYPE
attn( int sig )
{
	fflush(stderr);
	fflush(stdout);
	printf("\n\n  INTERRUPTED!\n");

	(void) SIGNAL (SIGINT, attn);

	longjmp(env, 1);
}

#if !defined(NO_TERMCAP) && defined(TIOCGWINSZ)
RETSIGTYPE
chwinsz( int sig )
{
	struct winsize win;

	(void) SIGNAL (SIGWINCH, SIG_IGN);
	if (ioctl(fileno(stdout), TIOCGWINSZ, &win) != -1) {
		if (win.ws_row != 0)
			lpp = win.ws_row;
		if (win.ws_col != 0)
			col_size = win.ws_col;
	}

	(void) SIGNAL (SIGWINCH, chwinsz);
}
#endif

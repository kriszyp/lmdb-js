/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/sysexits.h>
#include <ac/syslog.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <ldap.h>

#include "fax500.h"
#include "ldap_defaults.h"

#define USER		0
#define GROUP_ERRORS	1
#define GROUP_REQUEST	2
#define GROUP_MEMBERS	3

#define ERRORS	"errors"
#define REQUEST	"request"
#define MEMBERS	"members"

LDAP	*ld;
char	*errorsfrom = NULL;
char	*mailfrom = NULL;
char	*host = NULL;
int	hostlen = 0;

int	identity;
#define	MAIL500	1	
#define	FAX500	2

typedef struct errs {
	int		e_code;
#define E_USERUNKNOWN		1
#define E_AMBIGUOUS		2
#define E_NOEMAIL		3
#define E_NOREQUEST		4
#define E_NOERRORS		5
#define E_BADMEMBER		6
#define E_JOINMEMBERNOEMAIL	7
#define E_MEMBERNOEMAIL		8
#define E_NOFAXNUM		9
#define E_JOINMEMBERNOFAXNUM	10
#define E_MEMBERNOFAXNUM	11
#define	E_FAXTOEMAILMBR		12

	char		*e_addr;
	LDAPMessage	*e_msg;
} Error;

typedef struct groupto {
	char	*g_dn;
	char	*g_errorsto;
	char	**g_members;
} Group;

typedef struct baseinfo {
	char	*b_dn;		/* dn to start searching at */
	char	b_rdnpref;	/* give rdn's preference when searching? */
	char	*b_filter[3];	/* filter to apply - name substituted for %s */
				/* (up to three of them) */
} Base;

Base	base[] = 
	{ "ou=People, o=University of Michigan, c=US", 0,
		"uid=%s", "cn=%s", NULL,
	  "ou=System Groups, ou=Groups, o=University of Michigan, c=US", 1,
		"(&(cn=%s)(associatedDomain=%h))", NULL, NULL,
	  "ou=User Groups, ou=Groups, o=University of Michigan, c=US", 1,
		"(&(cn=%s)(associatedDomain=%h))", NULL, NULL,
	  NULL
	};

char	*sendmailargs[] = { FAX_SENDMAIL, "-oMrX.500", "-odi", "-oi", "-f", NULL, NULL };

static char	*attrs[] = { "objectClass", "title", "postaladdress",
			"telephoneNumber", "mail", "description",
			"errorsTo", "rfc822ErrorsTo", "requestsTo",
			"rfc822RequestsTo", "joinable", "cn", "member",
			"facsimileTelephoneNumber", NULL };


static void do_address(char *name, char ***to, int *nto, Group **togroups, int *ngroups, Error **err, int *nerr, int type);
static int  do_group(LDAPMessage *e, char *dn, char ***to, int *nto, Group **togroups, int *ngroups, Error **err, int *nerr);
static void do_group_members(LDAPMessage *e, char *dn, char ***to, int *nto, Group **togroups, int *ngroups, Error **err, int *nerr);
static void send_message(char **to);
static void send_errors(Error *err, int nerr);
static void do_noemailorfax(FILE *fp, Error *err, int namelen, int errtype);
static void do_ambiguous(FILE *fp, Error *err, int namelen);
static int  count_values(char **list);
static void add_to(char ***list, int *nlist, char **new);
static int  isgroup(LDAPMessage *e);
static void add_error(Error **err, int *nerr, int code, char *addr, LDAPMessage *msg);
static void add_group(char *dn, Group **list, int *nlist);
static void unbind_and_exit(int rc) LDAP_GCCATTR((noreturn));
static int  group_loop(char *dn);
static void send_group(Group *group, int ngroup);
static int  has_attributes(LDAPMessage *e, char *attr1, char *attr2);
static char **get_attributes_mail_dn(LDAPMessage *e, char *attr1, char *attr2);
static char *canonical(char *s);
static int  connect_to_x500 (void);
static void do_group_errors (LDAPMessage *e, char *dn, char ***to, int *nto, Error **err, int *nerr);
static void do_group_request (LDAPMessage *e, char *dn, char ***to, int *nto, Error **err, int *nerr);
static void add_member (char *gdn, char *dn, char ***to, int *nto, Group **togroups, int *ngroups, Error **err, int *nerr);


int
main ( int argc, char **argv )
{
	char		*myname;
	char		**tolist;
	Error		*errlist;
	Group		*togroups;
	int		numto, ngroups, numerr, nargs;
	int		i, j;

	while ( (i = getopt( argc, argv, "f:h:m:" )) != EOF ) {
		switch( i ) {
		case 'f':	/* who it's from & where errors should go */
			mailfrom = strdup( optarg );
			for ( j = 0; sendmailargs[j] != NULL; j++ ) {
				if ( strcmp( sendmailargs[j], "-f" ) == 0 ) {
					sendmailargs[j+1] = mailfrom;
					break;
				}
			}
			break;

		case 'h':	/* hostname */
			host = strdup( optarg );
			hostlen = strlen(host);
			break;

				/* mailer-daemon address - who we should */
		case 'm':	/* say errors come from */
			errorsfrom = strdup( optarg );
			break;

		default:
			syslog( LOG_ALERT, "unknown option" );
			break;
		}
	}

	if ( (myname = strrchr( argv[0], '/' )) == NULL )
		myname = strdup( argv[0] );
	else
		myname = strdup( myname + 1 );
	if (!strcmp(myname, "mail500")) {
		identity = MAIL500;
	} else if (!strcmp(myname, "fax500")) {
		identity = FAX500;
	} else {
		/* I give up, I must be mail500 */
		identity = MAIL500;
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

#ifdef LOG_MAIL
	openlog( myname, OPENLOG_OPTIONS, LOG_MAIL );
#else
	openlog( myname, OPENLOG_OPTIONS );
#endif

	if ( mailfrom == NULL ) {
		syslog( LOG_ALERT, "required argument -f not present" );
		exit( EX_TEMPFAIL );
	}
	if ( errorsfrom == NULL ) {
		syslog( LOG_ALERT, "required argument -m not present" );
		exit( EX_TEMPFAIL );
	}
	if ( host == NULL ) {
		syslog( LOG_ALERT, "required argument -h not present" );
		exit( EX_TEMPFAIL );
	}

	if ( connect_to_x500() != 0 )
		exit( EX_TEMPFAIL );

	setuid( geteuid() );
/*
{
	char	buf[1024];
	int	i;

	strcpy( buf, argv[0] );
	for ( i = 1; i < argc; i++ ) {
		strcat( buf, " " );
		strcat( buf, argv[i] );
	}

	syslog( LOG_ALERT, "args: (%s)", buf );
}
*/
	numto = 0;
	add_to( &tolist, &numto, sendmailargs );
	nargs = numto;
	ngroups = numerr = 0;
	togroups = NULL;
	errlist = NULL;
	for ( i = optind; i < argc; i++ ) {
		char	*s;
		int	type;

		for ( j = 0; argv[i][j] != '\0'; j++ ) {
			if ( argv[i][j] == '.' || argv[i][j] == '_' )
				argv[i][j] = ' ';
		}

		type = USER;
		if ( (s = strrchr( argv[i], '-' )) != NULL ) {
			s++;

			if ( strcmp( s, ERRORS ) == 0 ) {
				type = GROUP_ERRORS;
				*(--s) = '\0';
			} else if ( strcmp( s, REQUEST ) == 0 ) {
				type = GROUP_REQUEST;
				*(--s) = '\0';
			} else if ( strcmp( s, MEMBERS ) == 0 ) {
				type = GROUP_MEMBERS;
				*(--s) = '\0';
			}
		}

		do_address( argv[i], &tolist, &numto, &togroups, &ngroups,
		    &errlist, &numerr, type );
	}

	/*
	 * If we have both errors and successful deliveries to make or if
	 * if there are any groups to deliver to, we basically need to read
	 * the message twice.  So, we have to put it in a tmp file.
	 */

	if ( numerr > 0 && numto > nargs || ngroups > 0 ) {
		FILE	*fp;
		char	buf[BUFSIZ];

		umask( 077 );
		if ( (fp = tmpfile()) == NULL ) {
			syslog( LOG_ALERT, "could not open tmp file" );
			unbind_and_exit( EX_TEMPFAIL );
		}

		/* copy the message to a temp file */
		while ( fgets( buf, sizeof(buf), stdin ) != NULL ) {
			if ( fputs( buf, fp ) == EOF ) {
				syslog( LOG_ALERT, "error writing tmpfile" );
				unbind_and_exit( EX_TEMPFAIL );
			}
		}

		if ( dup2( fileno( fp ), 0 ) == -1 ) {
			syslog( LOG_ALERT, "could not dup2 tmpfile" );
			unbind_and_exit( EX_TEMPFAIL );
		}

		fclose( fp );
	}

	/* deal with errors */
	if ( numerr > 0 ) {
		(void) rewind( stdin );
		send_errors( errlist, numerr );
	}

	(void) ldap_unbind( ld );

	/* send to groups with errorsTo */
	if ( ngroups > 0 ) {
		(void) rewind( stdin );
		send_group( togroups, ngroups );
	}

	/* send to expanded aliases and groups w/o errorsTo */
	if ( numto > nargs ) {
		(void) rewind( stdin );
		send_message( tolist );
	}

	return( EX_OK );
}

static int
connect_to_x500( void )
{
	int sizelimit = FAX_MAXAMBIGUOUS;
	int deref = LDAP_DEREF_ALWAYS;

	if ( (ld = ldap_init( NULL, 0 )) == NULL ) {
		syslog( LOG_ALERT, "ldap_init failed" );
		return( -1 );
	}

	ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);
	ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

	if ( ldap_simple_bind_s( ld, NULL, NULL ) != LDAP_SUCCESS ) {
		syslog( LOG_ALERT, "ldap_simple_bind_s failed" );
		return( -1 );
	}

	return( 0 );
}


static void
do_address(
	char		*name,
	char		***to,
	int		*nto,
	Group		**togroups,
	int		*ngroups,
	Error		**err,
	int		*nerr,
	int		type
)
{
	int		rc, b, f, match;
	LDAPMessage	*e, *res;
	struct timeval	timeout;
	char		*dn;
	char		filter[1024];
	char		**mail;
	char		**fax;

	/*
	 * Look up the name in X.500, add the appropriate addresses found
	 * to the to list, or to the err list in case of error.  Groups are
	 * handled by the do_group routine, individuals are handled here.
	 * When looking up name, we follow the bases hierarchy, looking
	 * in base[0] first, then base[1], etc.  For each base, there is
	 * a set of search filters to try, in order.  If something goes
	 * wrong here trying to contact X.500, we exit with EX_TEMPFAIL.
	 * If the b_rdnpref flag is set, then we give preference to entries
	 * that matched name because it's their rdn, otherwise not.
	 */

	timeout.tv_sec = FAX_TIMEOUT;
	timeout.tv_usec = 0;
	for ( b = 0, match = 0; !match && base[b].b_dn != NULL; b++ ) {
		for ( f = 0; base[b].b_filter[f] != NULL; f++ ) {
			char	*format, *p, *argv[3];
			int	argc;

			for ( argc = 0; argc < 3; argc++ ) {
				argv[argc] = NULL;
			}

			format = strdup( base[b].b_filter[f] );
			for ( argc = 0, p = format; *p; p++ ) {
				if ( *p == '%' ) {
					switch ( *++p ) {
					case 's':	/* %s is the name */
						argv[argc] = name;
						break;

					case 'h':	/* %h is the host */
						*p = 's';
						argv[argc] = host;
						break;

					default:
						syslog( LOG_ALERT,
						    "unknown format %c", *p );
						break;
					}

					argc++;
				}
			}

			/* three names ought to do... */
			sprintf( filter, format, argv[0], argv[1], argv[2] );
			free( format );

			res = NULL;
			rc = ldap_search_st( ld, base[b].b_dn,
			    LDAP_SCOPE_SUBTREE, filter, attrs, 0, &timeout,
			    &res );

			/* some other trouble - try again later */
			if ( rc != LDAP_SUCCESS &&
			    rc != LDAP_SIZELIMIT_EXCEEDED ) {
				syslog( LOG_ALERT, "return %d from X.500", rc );
				unbind_and_exit( EX_TEMPFAIL );
			}

			if ( (match = ldap_count_entries( ld, res )) != 0 )
				break;

			ldap_msgfree( res );
		}

		if ( match )
			break;
	}

	/* trouble - try again later */
	if ( match == -1 ) {
		syslog( LOG_ALERT, "error parsing result from X.500" );
		unbind_and_exit( EX_TEMPFAIL );
	}

	/* no matches - bounce with user unknown */
	if ( match == 0 ) {
		add_error( err, nerr, E_USERUNKNOWN, name, NULL );
		return;
	}

	/* more than one match - bounce with ambiguous user? */
	if ( match > 1 ) {
		LDAPMessage	*next, *tmpres = NULL;
		char		*dn;
		char		**xdn;

		/* not giving rdn preference - bounce with ambiguous user */
		if ( base[b].b_rdnpref == 0 ) {
			add_error( err, nerr, E_AMBIGUOUS, name, res );
			return;
		}

		/*
		 * giving rdn preference - see if any entries were matched
		 * because of their rdn.  If so, collect them to deal with
		 * later (== 1 we deliver, > 1 we bounce).
		 */

		for ( e = ldap_first_entry( ld, res ); e != NULL; e = next ) {
			next = ldap_next_entry( ld, e );
			dn = ldap_get_dn( ld, e );
			xdn = ldap_explode_dn( dn, 1 );

			/* XXX bad, but how else can we do it? XXX */
			if ( strcasecmp( xdn[0], name ) == 0 ) {
				ldap_delete_result_entry( &res, e );
				ldap_add_result_entry( &tmpres, e );
			}

			ldap_value_free( xdn );
			free( dn );
		}

		/* nothing matched by rdn - go ahead and bounce */
		if ( tmpres == NULL ) {
			add_error( err, nerr, E_AMBIGUOUS, name, res );
			return;

		/* more than one matched by rdn - bounce with rdn matches */
		} else if ( (match = ldap_count_entries( ld, tmpres )) > 1 ) {
			add_error( err, nerr, E_AMBIGUOUS, name, tmpres );
			return;

		/* trouble... */
		} else if ( match < 0 ) {
			syslog( LOG_ALERT, "error parsing result from X.500" );
			unbind_and_exit( EX_TEMPFAIL );
		}

		/* otherwise one matched by rdn - send to it */
		ldap_msgfree( res );
		res = tmpres;
	}

	/*
	 * if we get this far, it means that we found a single match for
	 * name.  for a user, we deliver to the mail attribute or bounce
	 * with address and phone if no mail attr.  for a group, we
	 * deliver to all members or bounce to rfc822ErrorsTo if no members.
	 */

	/* trouble */
	if ( (e = ldap_first_entry( ld, res )) == NULL ) {
		syslog( LOG_ALERT, "error parsing entry from X.500" );
		unbind_and_exit( EX_TEMPFAIL );
	}

	dn = ldap_get_dn( ld, e );

	if ( type == GROUP_ERRORS ) {
		/* sent to group-errors - resend to [rfc822]ErrorsTo attr */
		do_group_errors( e, dn, to, nto, err, nerr );

	} else if ( type == GROUP_REQUEST ) {
		/* sent to group-request - resend to [rfc822]RequestsTo attr */
		do_group_request( e, dn, to, nto, err, nerr );

	} else if ( type == GROUP_MEMBERS ) {
		/* sent to group-members - expand */
		do_group_members( e, dn, to, nto, togroups, ngroups, err,
		    nerr );

	} else if ( isgroup( e ) ) {
		/* 
		 * sent to group - resend from [rfc822]ErrorsTo if it's there,
		 * otherwise, expand the group
		 */

		do_group( e, dn, to, nto, togroups, ngroups, err, nerr );

		ldap_msgfree( res );

	} else {
		/*
		 * sent to user - mail attribute => add it to the to list,
		 * otherwise bounce
		 */
		switch (identity) {
		case FAX500 :	
			if ( (mail = ldap_get_values( ld, e, 
			     "facsimileTelephoneNumber" )) != NULL ) {
				char *fdn;
				char **ufn;
				int i;

				fdn = ldap_get_dn( ld, e );
				ufn = ldap_explode_dn( fdn, 1 );
				/* Convert spaces to underscores for rp */
				for (i = 0; ufn[0][i] != '\0'; i++) {
					if (ufn[0][i] == ' ') {
						ufn[0][i] = '_';
					}
				}
				*mail = faxtotpc(*mail, ufn[0]);
				
				add_to(to, nto, mail);

				if (fdn != NULL) {
					free(fdn);
				}
				ldap_value_free( ufn );
				ldap_value_free( mail );
				ldap_msgfree( res );
			} else {
				add_error( err, nerr, E_NOFAXNUM, 
					   name, res );
			}
			break;
		case MAIL500 :
			if ( (mail = ldap_get_values( ld, e, "mail" ))
			     != NULL ) {
				add_to( to, nto, mail );

				ldap_value_free( mail );
				ldap_msgfree( res );
			} else {
				add_error( err, nerr, E_NOEMAIL, 
					   name, res );
			}
			break;
		}
	}

	free( dn );

	return;
}

static int
do_group(
	LDAPMessage	*e,
	char		*dn,
	char		***to,
	int		*nto,
	Group		**togroups,
	int		*ngroups,
	Error		**err,
	int		*nerr
)
{
	/*
	 * If this group has an rfc822ErrorsTo attribute, we need to
	 * arrange for errors involving this group to go there, not
	 * to the sender.  Since sendmail only has the concept of a
	 * single sender, we arrange for errors to go to groupname-errors,
	 * which we then handle specially when (if) it comes back to us
	 * by expanding to all the rfc822ErrorsTo addresses.  If it has no
	 * rfc822ErrorsTo attribute, we call do_group_members() to expand
	 * the group.
	 */

	if ( group_loop( dn ) ) {
		return( -1 );
	}

	if ( has_attributes( e, "rfc822ErrorsTo", "errorsTo" ) ) {
		add_group( dn, togroups, ngroups );

		return( 0 );
	}

	do_group_members( e, dn, to, nto, togroups, ngroups, err, nerr );

	return( 0 );
}

/* ARGSUSED */
static void
do_group_members(
	LDAPMessage	*e,
	char		*dn,
	char		***to,
	int		*nto,
	Group		**togroups,
	int		*ngroups,
	Error		**err,
	int		*nerr
)
{
	int		i, rc;
	char		*ndn;
	char		**mail, **member, **joinable;
	char		filter[256];
	LDAPMessage	*ee, *res;
	struct timeval	timeout;

	/*
	 * if all has gone according to plan, we've already arranged for
	 * errors to go to the [rfc822]ErrorsTo attributes (if they exist),
	 * so all we have to do here is arrange to send to the
	 * rfc822Mailbox attribute, the member attribute, and anyone who
	 * has joined the group by setting memberOfGroup equal to the
	 * group dn.
	 */

	/* add members in the group itself - mail attribute */
	if ( (mail = ldap_get_values( ld, e, "mail" )) != NULL ) {
		/* 
		 * These are only email addresses - impossible 
		 * to have a fax number
		 */
		switch (identity) {
		case FAX500 :
			/* XXX How do we want to inform sender that the */
			/* group they sent to has email-only members? */
			break;
		case MAIL500 :
			add_to( to, nto, mail );
			break;
		}

		ldap_value_free( mail ); 
	}

	/* add members in the group itself - member attribute */
	if ( (member = ldap_get_values( ld, e, "member" )) != NULL ) {
		for ( i = 0; member[i] != NULL; i++ ) {
			add_member( dn, member[i], to, nto, togroups,
			    ngroups, err, nerr );
		}

		ldap_value_free( member );
	}

	/* add members who have joined by setting memberOfGroup */
	if ( (joinable = ldap_get_values( ld, e, "joinable" )) != NULL ) {
		if ( strcasecmp( joinable[0], "FALSE" ) == 0 ) {
			ldap_value_free( joinable );
			return;
		}
		ldap_value_free( joinable );

		sprintf( filter, "(memberOfGroup=%s)", dn );

		timeout.tv_sec = FAX_TIMEOUT;
		timeout.tv_usec = 0;

		/* for each subtree to look in... */
		{
			int sizelimit = FAX_MAXMEMBERS;
			ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);
		}	
		for ( i = 0; base[i].b_dn != NULL; i++ ) {
			/* find entries that have joined this group... */
			rc = ldap_search_st( ld, base[i].b_dn,
			    LDAP_SCOPE_SUBTREE, filter, attrs, 0, &timeout,
			    &res );

			if ( rc == LDAP_SIZELIMIT_EXCEEDED ||
			    rc == LDAP_TIMELIMIT_EXCEEDED ) {
				syslog( LOG_ALERT,
				    "group search limit exceeded %d", rc );
				unbind_and_exit( EX_TEMPFAIL );
			}

			if ( rc != LDAP_SUCCESS ) {
				syslog( LOG_ALERT, "group search bad return %d",
				    rc );
				unbind_and_exit( EX_TEMPFAIL );
			}

			/* for each entry that has joined... */
			for ( ee = ldap_first_entry( ld, res ); ee != NULL;
			    ee = ldap_next_entry( ld, ee ) ) {
				if ( isgroup( ee ) ) {
					ndn = ldap_get_dn( ld, ee );

					if ( do_group( e, ndn, to, nto,
					    togroups, ngroups, err, nerr )
					    == -1 ) {
						syslog( LOG_ALERT,
						    "group loop (%s) (%s)",
						    dn, ndn );
					}

					free( ndn );

					continue;
				}

				/* add them to the to list */
				switch (identity) {
				case FAX500 :	
					if ( (mail = ldap_get_values( ld, ee, 
					      "facsimileTelephoneNumber" )) 
					      != NULL ) {
						char *fdn;
						char **ufn;
						int i;

						fdn = ldap_get_dn( ld, ee );
						ufn = ldap_explode_dn( fdn, 1 );
						/* 
						 * Convert spaces to 
						 * underscores for rp
						 */
						for (i = 0; ufn[0][i] != '\0'; 
						     i++) {
							if (ufn[0][i] == ' ') {
								ufn[0][i] = '_';
							}
						}
						*mail = faxtotpc(*mail, ufn[0]);
						add_to(to, nto, mail);

						ldap_value_free( mail );
						ldap_msgfree( res );
					} else {
						ndn = ldap_get_dn( ld, ee );

						add_error( err, nerr,
						    E_JOINMEMBERNOFAXNUM, ndn, 
						    NULL );

						free( ndn );
					}
					break;
				case MAIL500 :
					if ( (mail = ldap_get_values( ld, ee, 
					     "mail" )) != NULL ) {
						add_to( to, nto, mail );

						ldap_value_free( mail );

					/* else generate a bounce */
					} else {
						ndn = ldap_get_dn( ld, ee );

						add_error( err, nerr,
						    E_JOINMEMBERNOEMAIL, ndn, 
						    NULL );

						free( ndn );
					}
					break;
				}
			}

			ldap_msgfree( res );
		}
		{
			int sizelimit = FAX_MAXAMBIGUOUS;
			ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);
		}	
	}

	return;
}

static void
add_member(
	char		*gdn,
	char		*dn,
	char		***to,
	int		*nto,
	Group		**togroups,
	int		*ngroups,
	Error		**err,
	int		*nerr
)
{
	char		*ndn;
	char		**mail;
	int		rc;
	LDAPMessage	*res, *e;
	struct timeval	timeout;

	timeout.tv_sec = FAX_TIMEOUT;
	timeout.tv_usec = 0;
	if ( (rc = ldap_search_st( ld, dn, LDAP_SCOPE_BASE, "(objectclass=*)",
	    attrs, 0, &timeout, &res )) != LDAP_SUCCESS ) {
		if ( rc == LDAP_NO_SUCH_OBJECT ) {
			add_error( err, nerr, E_BADMEMBER, dn, NULL );

			return;
		} else {
			syslog( LOG_ALERT, "member search bad return %d", rc );

			unbind_and_exit( EX_TEMPFAIL );
		}
	}

	if ( (e = ldap_first_entry( ld, res )) == NULL ) {
		syslog( LOG_ALERT, "member search error parsing entry" );

		unbind_and_exit( EX_TEMPFAIL );
	}
	ndn = ldap_get_dn( ld, e );

	/* allow groups within groups */
	if ( isgroup( e ) ) {
		if ( do_group( e, ndn, to, nto, togroups, ngroups, err, nerr )
		    == -1 ) {
			syslog( LOG_ALERT, "group loop (%s) (%s)", gdn, ndn );
		}

		free( ndn );

		return;
	}

	switch (identity) {
	case FAX500 :	
		if ( (mail = ldap_get_values( ld, e, 
		     "facsimileTelephoneNumber" )) != NULL ) {
			char *fdn;
			char **ufn;
			int i;
			fdn = ldap_get_dn( ld, e );
			ufn = ldap_explode_dn( fdn, 1 );
			/* Convert spaces to underscores for rp */
			for (i = 0; ufn[0][i] != '\0'; i++) {
				if (ufn[0][i] == ' ') {
					ufn[0][i] = '_';
				}
			}
			*mail = faxtotpc(*mail, ufn[0]);
			add_to(to, nto, mail);

			ldap_value_free( mail );
			ldap_msgfree( res );
		} else {
			add_error( err, nerr, E_MEMBERNOFAXNUM, ndn, NULL );
		}
		break;
	case MAIL500 :
		/* send to the member's mail attribute */
		if ( (mail = ldap_get_values( ld, e, "mail" )) != NULL ) {
			add_to( to, nto, mail );

			ldap_value_free( mail );

		/* else generate a bounce */
		} else {
			add_error( err, nerr, E_MEMBERNOEMAIL, ndn, NULL );
		}

		free( ndn );
	}
	return;
}

static void
do_group_request(
	LDAPMessage	*e,
	char		*dn,
	char		***to,
	int		*nto,
	Error		**err,
	int		*nerr
)
{
	char		**requeststo;

	if ( (requeststo = get_attributes_mail_dn( e, "rfc822RequestsTo",
	    "requestsTo" )) != NULL ) {
		add_to( to, nto, requeststo );

		ldap_value_free( requeststo );
	} else {
		add_error( err, nerr, E_NOREQUEST, dn, NULL );
	}
}

static void
do_group_errors(
	LDAPMessage	*e,
	char		*dn,
	char		***to,
	int		*nto,
	Error		**err,
	int		*nerr
)
{
	char		**errorsto;

	if ( (errorsto = get_attributes_mail_dn( e, "rfc822ErrorsTo",
	    "errorsTo" )) != NULL ) {
		add_to( to, nto, errorsto );

		ldap_value_free( errorsto );
	} else {
		add_error( err, nerr, E_NOERRORS, dn, NULL );
	}
}

static void
send_message( char **to )
{
	int	pid;
#ifndef HAVE_WAITPID
	WAITSTATUSTYPE  status;
#endif


	/* parent */
	if ( (pid = fork()) != 0 ) {
#ifdef HAVE_WAITPID
		waitpid( pid, (int *) NULL, 0 );
#else
		wait4( pid, &status, WAIT_FLAGS, 0 );
#endif
	/* child */
	} else {
		/* to includes sendmailargs */
		execv( FAX_SENDMAIL, to );

		syslog( LOG_ALERT, "execv failed" );

		exit( EX_TEMPFAIL );
	}
}

static void
send_group( Group *group, int ngroup )
{
	int	i, pid;
	char	**argv;
	int	argc;
	char	*iargv[7];
#ifndef HAVE_WAITPID
	WAITSTATUSTYPE  status;
#endif

	for ( i = 0; i < ngroup; i++ ) {
		(void) rewind( stdin );

		iargv[0] = FAX_SENDMAIL;
		iargv[1] = "-f";
		iargv[2] = group[i].g_errorsto;
		iargv[3] = "-oMrX.500";
		iargv[4] = "-odi";
		iargv[5] = "-oi";
		iargv[6] = NULL;

		argv = NULL;
		argc = 0;
		add_to( &argv, &argc, iargv );
		add_to( &argv, &argc, group[i].g_members );


		/* parent */
		if ( (pid = fork()) != 0 ) {
#ifdef HAVE_WAITPID
			waitpid( pid, (int *) NULL, 0 );
#else
			wait4( pid, &status, WAIT_FLAGS, 0 );
#endif
		/* child */
		} else {
			execv( FAX_SENDMAIL, argv );

			syslog( LOG_ALERT, "execv failed" );

			exit( EX_TEMPFAIL );
		}
	}

	return;
}

static void
send_errors( Error *err, int nerr )
{
	int		i, namelen;
	FILE		*fp;
	char		buf[1024];

	sprintf( buf, "%s -oMrX.500 -odi -oi -f %s %s", FAX_SENDMAIL, errorsfrom,
	    mailfrom );
	if ( (fp = popen( buf, "w" )) == NULL ) {
		syslog( LOG_ALERT, "could not popen sendmail for errs" );
		return;
	}

	fprintf( fp, "To: %s\n", mailfrom );
	fprintf( fp, "From: %s\n", errorsfrom );
	fprintf( fp, "Subject: undeliverable mail\n" );
	fprintf( fp, "\n" );
	fprintf( fp, "The following errors occurred when trying to deliver the attached mail:\n" );
	for ( i = 0; i < nerr; i++ ) {
		namelen = strlen( err[i].e_addr );
		fprintf( fp, "\n" );

		switch ( err[i].e_code ) {
		case E_USERUNKNOWN:
			fprintf( fp, "%s: User unknown\n", err[i].e_addr );
			break;

		case E_BADMEMBER:
			fprintf( fp, "%s: Group member does not exist\n",
			    err[i].e_addr );
			break;

		case E_NOREQUEST:
			fprintf( fp, "%s: Group exists but has no request address\n",
			    err[i].e_addr );
			break;

		case E_NOERRORS:
			fprintf( fp, "%s: Group exists but has no errors-to address\n",
			    err[i].e_addr );
			break;

		case E_AMBIGUOUS:
			do_ambiguous( fp, &err[i], namelen );
			break;

		case E_NOEMAIL:
			do_noemailorfax( fp, &err[i], namelen, E_NOEMAIL );
			break;

		case E_MEMBERNOEMAIL:
			fprintf( fp, "%s: Group member exists but does not have an email address\n",
			    err[i].e_addr );
			break;

		case E_JOINMEMBERNOEMAIL:
			fprintf( fp, "%s: User has joined group but does not have an email address\n",
			    err[i].e_addr );
			break;

		case E_NOFAXNUM:
			do_noemailorfax( fp, &err[i], namelen, E_NOFAXNUM );
			break;

		case E_MEMBERNOFAXNUM:
			fprintf( fp, "%s: Group member exists but does not have a fax number\n",
			    err[i].e_addr );
			break;

		case E_JOINMEMBERNOFAXNUM:
			fprintf( fp, "%s: User has joined group but does not have a fax number\n",
			    err[i].e_addr );
			break;

		default:
			syslog( LOG_ALERT, "unknown error %d", err[i].e_code );
			unbind_and_exit( EX_TEMPFAIL );
			break;
		}
	}

	fprintf( fp, "\n------- The original message sent:\n\n" );

	while ( fgets( buf, sizeof(buf), stdin ) != NULL ) {
		fputs( buf, fp );
	}

	if ( pclose( fp ) == -1 ) {
		syslog( LOG_ALERT, "pclose failed" );
		unbind_and_exit( EX_TEMPFAIL );
	}

	return;
}


static void
do_noemailorfax( FILE *fp, Error *err, int namelen, int errtype )
{
	int		i, last;
	char		*dn, *rdn;
	char		**ufn, **vals;

	if (errtype == E_NOFAXNUM) {
		fprintf(fp, "%s: User has no facsimile number registered.\n",
	    		err->e_addr );
	} else if (errtype == E_NOEMAIL) {
		fprintf(fp, "%s: User has no email address registered.\n",
	    		err->e_addr );
	}
	fprintf( fp, "%*s  Name, title, postal address and phone for '%s':\n\n",
	    namelen, " ", err->e_addr );

	/* name */
	dn = ldap_get_dn( ld, err->e_msg );
	ufn = ldap_explode_dn( dn, 1 );
	rdn = strdup( ufn[0] );
	if ( strcasecmp( rdn, err->e_addr ) == 0 ) {
		if ( (vals = ldap_get_values( ld, err->e_msg, "cn" ))
		    != NULL ) {
			for ( i = 0; vals[i]; i++ ) {
				last = strlen( vals[i] ) - 1;
				if ( isdigit((unsigned char) vals[i][last]) ) {
					rdn = strdup( vals[i] );
					break;
				}
			}

			ldap_value_free( vals );
		}
	}
	fprintf( fp, "%*s  %s\n", namelen, " ", rdn );
	free( dn );
	free( rdn );
	ldap_value_free( ufn );

	/* titles or descriptions */
	if ( (vals = ldap_get_values( ld, err->e_msg, "title" )) == NULL &&
	    (vals = ldap_get_values( ld, err->e_msg, "description" ))
	    == NULL ) {
		fprintf( fp, "%*s  No title or description registered\n",
		    namelen, " " );
	} else {
		for ( i = 0; vals[i] != NULL; i++ ) {
			fprintf( fp, "%*s  %s\n", namelen, " ", vals[i] );
		}

		ldap_value_free( vals );
	}

	/* postal address */
	if ( (vals = ldap_get_values( ld, err->e_msg, "postalAddress" ))
	    == NULL ) {
		fprintf( fp, "%*s  No postal address registered\n", namelen,
		    " " );
	} else {
		fprintf( fp, "%*s  ", namelen, " " );
		for ( i = 0; vals[0][i] != '\0'; i++ ) {
			if ( vals[0][i] == '$' ) {
				fprintf( fp, "\n%*s  ", namelen, " " );
				while ( isspace((unsigned char) vals[0][i+1]) )
					i++;
			} else {
				fprintf( fp, "%c", vals[0][i] );
			}
		}
		fprintf( fp, "\n" );

		ldap_value_free( vals );
	}

	/* telephone number */
	if ( (vals = ldap_get_values( ld, err->e_msg, "telephoneNumber" ))
	    == NULL ) {
		fprintf( fp, "%*s  No phone number registered\n", namelen,
		    " " );
	} else {
		for ( i = 0; vals[i] != NULL; i++ ) {
			fprintf( fp, "%*s  %s\n", namelen, " ", vals[i] );
		}

		ldap_value_free( vals );
	}
}

/* ARGSUSED */
static void
do_ambiguous( FILE *fp, Error *err, int namelen )
{
	int		i, last;
	char		*dn, *rdn;
	char		**ufn, **vals;
	LDAPMessage	*e;

	i = ldap_result2error( ld, err->e_msg, 0 );

	fprintf( fp, "%s: Ambiguous user.  %s%d matches found:\n\n",
	    err->e_addr, i == LDAP_SIZELIMIT_EXCEEDED ? "First " : "",
	    ldap_count_entries( ld, err->e_msg ) );

	for ( e = ldap_first_entry( ld, err->e_msg ); e != NULL;
	    e = ldap_next_entry( ld, e ) ) {
		dn = ldap_get_dn( ld, e );
		ufn = ldap_explode_dn( dn, 1 );
		rdn = strdup( ufn[0] );
		if ( strcasecmp( rdn, err->e_addr ) == 0 ) {
			if ( (vals = ldap_get_values( ld, e, "cn" )) != NULL ) {
				for ( i = 0; vals[i]; i++ ) {
					last = strlen( vals[i] ) - 1;
					if ( isdigit((unsigned char) vals[i][last]) ) {
						rdn = strdup( vals[i] );
						break;
					}
				}

				ldap_value_free( vals );
			}
		}

		if ( isgroup( e ) ) {
			vals = ldap_get_values( ld, e, "description" );
		} else {
			vals = ldap_get_values( ld, e, "title" );
		}

		fprintf( fp, "    %-20s %s\n", rdn, vals ? vals[0] : "" );
		for ( i = 1; vals && vals[i] != NULL; i++ ) {
			fprintf( fp, "                         %s\n", vals[i] );
		}

		free( dn );
		free( rdn );
		ldap_value_free( ufn );
		if ( vals != NULL )
			ldap_value_free( vals );
	}
}

static int
count_values( char **list )
{
	int	i;

	for ( i = 0; list && list[i] != NULL; i++ )
		;	/* NULL */

	return( i );
}

static void
add_to( char ***list, int *nlist, char **new )
{
	int	i, nnew, oldnlist;

	nnew = count_values( new );

	oldnlist = *nlist;
	if ( *list == NULL || *nlist == 0 ) {
		*list = (char **) malloc( (nnew + 1) * sizeof(char *) );
		*nlist = nnew;
	} else {
		*list = (char **) realloc( *list, *nlist * sizeof(char *) +
		    nnew * sizeof(char *) + sizeof(char *) );
		*nlist += nnew;
	}

	for ( i = 0; i < nnew; i++ ) {
		(*list)[i + oldnlist] = strdup( new[i] );
	}
	(*list)[*nlist] = NULL;

	return;
}

static int
isgroup( LDAPMessage *e )
{
	int	i;
	char	**oclist;

	oclist = ldap_get_values( ld, e, "objectClass" );

	for ( i = 0; oclist[i] != NULL; i++ ) {
		if ( strcasecmp( oclist[i], "rfc822MailGroup" ) == 0 ) {
			ldap_value_free( oclist );
			return( 1 );
		}
	}
	ldap_value_free( oclist );

	return( 0 );
}

static void
add_error( Error **err, int *nerr, int code, char *addr, LDAPMessage *msg )
{
	if ( *nerr == 0 ) {
		*err = (Error *) malloc( sizeof(Error) );
	} else {
		*err = (Error *) realloc( *err, (*nerr + 1) * sizeof(Error) );
	}

	(*err)[*nerr].e_code = code;
	(*err)[*nerr].e_addr = strdup( addr );
	(*err)[*nerr].e_msg = msg;
	(*nerr)++;

	return;
}

static void
add_group( char *dn, Group **list, int *nlist )
{
	int	i, namelen;
	char	**ufn;

	for ( i = 0; i < *nlist; i++ ) {
		if ( strcmp( dn, (*list)[i].g_dn ) == 0 ) {
			syslog( LOG_ALERT, "group loop 2 detected (%s)", dn );
			return;
		}
	}

	ufn = ldap_explode_dn( dn, 1 );
	namelen = strlen( ufn[0] );

	if ( *nlist == 0 ) {
		*list = (Group *) malloc( sizeof(Group) );
	} else {
		*list = (Group *) realloc( *list, (*nlist + 1) *
		    sizeof(Group) );
	}

	/* send errors to groupname-errors@host */
	(*list)[*nlist].g_errorsto = (char *) malloc( namelen + sizeof(ERRORS)
	    + hostlen + 2 );
	sprintf( (*list)[*nlist].g_errorsto, "%s-%s@%s", ufn[0], ERRORS, host );
	(void) canonical( (*list)[*nlist].g_errorsto );

	/* send to groupname-members@host - make it a list for send_group */
	(*list)[*nlist].g_members = (char **) malloc( 2 * sizeof(char *) );
	(*list)[*nlist].g_members[0] = (char *) malloc( namelen +
	    sizeof(MEMBERS) + hostlen + 2 );
	sprintf( (*list)[*nlist].g_members[0], "%s-%s@%s", ufn[0], MEMBERS,
	    host );
	(void) canonical( (*list)[*nlist].g_members[0] );
	(*list)[*nlist].g_members[1] = NULL;

	/* save the group's dn so we can check for loops above */
	(*list)[*nlist].g_dn = strdup( dn );

	(*nlist)++;

	ldap_value_free( ufn );

	return;
}

static void
unbind_and_exit( int rc )
{
	int	i;

	if ( (i = ldap_unbind( ld )) != LDAP_SUCCESS )
		syslog( LOG_ALERT, "ldap_unbind failed %d\n", i );

	exit( rc );
}

static char *
canonical( char *s )
{
	char	*saves = s;

	for ( ; *s != '\0'; s++ ) {
		if ( *s == ' ' )
			*s = '.';
	}

	return( saves );
}

static int
group_loop( char *dn )
{
	int		i;
	static char	**groups;
	static int	ngroups;

	for ( i = 0; i < ngroups; i++ ) {
		if ( strcmp( dn, groups[i] ) == 0 )
			return( 1 );
	}

	if ( ngroups == 0 )
		groups = (char **) malloc( sizeof(char *) );
	else
		groups = (char **) realloc( groups,
		    (ngroups + 1) * sizeof(char *) );

	groups[ngroups++] = strdup( dn );

	return( 0 );
}

static int
has_attributes( LDAPMessage *e, char *attr1, char *attr2 )
{
	char	**attr;

	if ( (attr = ldap_get_values( ld, e, attr1 )) != NULL ) {
		ldap_value_free( attr );
		return( 1 );
	}

	if ( (attr = ldap_get_values( ld, e, attr2 )) != NULL ) {
		ldap_value_free( attr );
		return( 1 );
	}

	return( 0 );
}

static char **
get_attributes_mail_dn( LDAPMessage *e, char *attr1, char *attr2 )
{
	LDAPMessage	*ee, *res;
	char		**vals, **dnlist, **mail;
	int		nto, i, rc;
	struct timeval	timeout;

	vals = ldap_get_values( ld, e, attr1 );
	for ( nto = 0; vals != NULL && vals[nto] != NULL; nto++ )
		;	/* NULL */

	if ( (dnlist = ldap_get_values( ld, e, attr2 )) != NULL ) {
		timeout.tv_sec = FAX_TIMEOUT;
		timeout.tv_usec = 0;

		for ( i = 0; dnlist[i] != NULL; i++ ) {
			if ( (rc = ldap_search_st( ld, dnlist[i],
			    LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0,
			    &timeout, &res )) != LDAP_SUCCESS ) {
				if ( rc != LDAP_NO_SUCH_OBJECT ) {
					unbind_and_exit( EX_TEMPFAIL );
				}

				syslog( LOG_ALERT, "bad (%s) dn (%s)", attr2,
				    dnlist[i] );

				continue;
			}

			if ( (ee = ldap_first_entry( ld, res )) == NULL ) {
				syslog( LOG_ALERT, "error parsing x500 entry" );
				continue;
			}

			if ( (mail = ldap_get_values( ld, ee, "mail" ))
			    != NULL ) {
				add_to( &vals, &nto, mail );

				ldap_value_free( mail );
			}

			ldap_msgfree( res );
		}
	}

	return( vals );
}

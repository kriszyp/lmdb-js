/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1991, 1992 Regents of the University of Michigan.
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
#include <ac/krb.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include <lber.h>
#include <ldap.h>

#include "ldap_defaults.h"
#include "ud.h"

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
static char tktpath[20];	/* ticket file path */
static int kinit();
static int valid_tgt();
#endif

static void set_bound_dn(char *s);


int
auth( char *who, int implicit )
{
	int rc;			/* return code from ldap_bind() */
	char *passwd = NULL;	/* returned by getpassphrase() */
	char **rdns;		/* for fiddling with the DN */
	int authmethod;
	int name_provided;	/* was a name passed in? */
#ifdef HAVE_GETPWUID
	struct passwd *pw;	/* for getting user id */
#else
	char *user;
#endif
	char uidname[20];
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	char **krbnames;	/* for kerberos names */
	int kinited, ikrb;
	char buf[5];
	extern int krb_debug;
#endif
	LDAPMessage *mp;	/* returned from find() */
	static char prompt[MED_BUF_SIZE];	/* place for us to sprintf the prompt */
	static char name[MED_BUF_SIZE];	/* place to store the user's name */
	static char password[MED_BUF_SIZE];	/* password entered by user */

#ifdef DEBUG
	if (debug & D_TRACE)
		fprintf(stderr, "auth(%s, NULL)\n", who);
#endif
	name_provided = ( who != NULL );

	/*
	 *  The user needs to bind.  If <who> is not specified, we
	 *  assume that authenticating as user id is what user wants.
	 */
	if (who == NULL && implicit) {
		uidname[0] = '\0';

#ifdef HAVE_GETPWUID
		if ((pw = getpwuid((uid_t)geteuid())) != (struct passwd *) NULL) {
			sprintf(uidname, "uid=%s", pw->pw_name);
		}
#else
		user = getenv("USER");
		if(user == NULL) user = getenv("USERNAME");
		if(user == NULL) user = getenv("LOGNAME");

		if(user != NULL) {
			sprintf(uidname, "uid=%s", user);
		}
#endif

		if(uidname[0] != '\0') {
			who = uidname;
		}
	}

	if ( who == NULL ) {
		if ( implicit )
			printf( "You must first authenticate yourself to the Directory.\n" );
#ifdef UOFM
		printf("  What is your name or uniqname? ");
#else
		printf("  What is your name or user id? ");
#endif
		fflush(stdout);
		fetch_buffer(name, sizeof(name), stdin);
		if (name[0] == '\0')
			return( -1 );
		who = name;
	}

#ifdef DEBUG
	if (debug & D_AUTHENTICAT)
		printf("  Authenticating as \"%s\"\n", who);
#endif

	/*
	 *  Bail out if the name is bogus.  If not, strip off the junk
	 *  at the start of the DN, build a prompt, and get a password 
	 *  from the user.  Then perform the ldap_bind().
	 */
	if ((mp = find(who, TRUE)) == NULL) {
		printf("  I could not find \"%s\" in the Directory.\n", who);
		printf("  I used a search base of ");
		printbase("", search_base);
		printf("\n");
#ifdef DEBUG
		if (debug & D_AUTHENTICAT)
			printf("  Could not find \"%s\"\n", who);
#endif
		return(-1);
	}

	/*
	 *  Fill in the Entry structure.  May be handy later.
	 */
	(void) parse_answer(mp);

	rdns = ldap_explode_dn(Entry.DN, TRUE);
	printf("  Authenticating to the directory as \"%s\"...\n", *rdns );

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	/*
	 * First, if the user has a choice of auth methods, ask which
	 * one they want to use.  if they want kerberos, ask which
	 * krbname they want to bind as.
	 */

	if ( (krbnames = ldap_get_values( ld, mp, "krbName" )) != NULL ) {
		int 	choice, hassimple;

		hassimple = (ldap_compare_s( ld, Entry.DN, 
				"userPassword", "x" ) == LDAP_COMPARE_FALSE);
		(void) ldap_msgfree(mp);

		/* if we're running as a server (e.g., out of inetd) */
		if ( ! isatty( 1 ) ) {
			strcpy( tktpath, LDAP_TMPDIR LDAP_DEFSEP "ud_tktXXXXXX" );
			mktemp( tktpath );
			krb_set_tkt_string( tktpath );
		}

		kinited = valid_tgt( krbnames );

		if ( hassimple && !kinited ) {
			printf("  Which password would you like to use?\n");
			printf("    1 -> LDAP password\n");
#ifdef UOFM
			printf("    2 -> UMICH password (aka Uniqname or Kerberos password)\n");
#else
			printf("    2 -> Kerberos password\n");
#endif

			do {
				printf("  Enter 1 or 2: ");
				fflush(stdout);

				fetch_buffer(buf, sizeof(buf), stdin);
				choice = atoi(buf);
			} while (choice != 1 && choice != 2);

			authmethod = (choice == 1 ? LDAP_AUTH_SIMPLE :
			    LDAP_AUTH_KRBV4);
		} else {
			authmethod = LDAP_AUTH_KRBV4;
		}
	} else {
		authmethod = LDAP_AUTH_SIMPLE;
		(void) ldap_msgfree(mp);
	}

	/*
	 * if they are already kinited, we don't need to ask for a 
	 * password.
	 */

	if ( authmethod == LDAP_AUTH_KRBV4 ) {
		if ( ! kinited ) {
			if ( krbnames[1] != NULL ) {
				int	i;

				/* ask which one to use */
#ifdef UOFM
				printf("  Which UMICH (aka Kerberos or uniqname) name would you like to use?\n");
#else
				printf("  Which Kerberos name would you like to use?\n");
#endif
				for ( i = 0; krbnames[i] != NULL; i++ ) {
					printf( "    %d -> %s\n", i + 1,
					    krbnames[i] );
				}
				do {
					printf("  Enter a number between 1 and %d: ", i );
					fflush( stdout );

					fetch_buffer(buf, sizeof(buf), stdin);
					ikrb = atoi(buf) - 1;
				} while ( ikrb > i - 1 || ikrb < 0 );
			} else {
				ikrb = 0;
			}

			/* kinit */
			if ( kinit( krbnames[ikrb] ) != 0 ) {
				(void) ldap_value_free(rdns);
				(void) ldap_value_free(krbnames);
				return(-1);
			}
		}
	} else {
#endif
		authmethod = LDAP_AUTH_SIMPLE;
		sprintf(prompt, "  Enter your LDAP password: ");
		do {
			passwd = getpassphrase(prompt);
		} while (passwd != NULL && *passwd == '\0');
		if (passwd == NULL) {
			(void) ldap_value_free(rdns);
			return(0);
		}
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	}
	(void) ldap_value_free(krbnames);
#endif
	ldap_flush_cache( ld );
	rc = ldap_bind_s(ld, Entry.DN, passwd, authmethod);
	if (rc != LDAP_SUCCESS) {
		int ld_errno;
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
		if (ld_errno == LDAP_NO_SUCH_ATTRIBUTE)
			fprintf(stderr, "  Entry has no password\n");
		else if (ld_errno == LDAP_INVALID_CREDENTIALS)
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
			if ( authmethod == LDAP_AUTH_KRBV4 ) {
				fprintf(stderr, "  The Kerberos credentials are invalid.\n");
			} else {
#endif
				fprintf(stderr, "  The password you provided is incorrect.\n");
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
			}
#endif
		else
			ldap_perror(ld, "ldap_bind_s" );
		(void) ldap_bind_s(ld, default_bind_object,
			 (char *) NULL, LDAP_AUTH_SIMPLE);
		if (default_bind_object == NULL)
			set_bound_dn(NULL);
		else
			set_bound_dn(default_bind_object);
		bind_status = UD_NOT_BOUND;
		if (verbose)
			printf("  Authentication failed.\n\n");
		(void) ldap_value_free(rdns);
		return(-1);
	}
	else if (verbose)
		printf("  Authentication successful.\n\n");
	else
		printf("\n");
	set_bound_dn(Entry.DN);
	bind_status = UD_BOUND;
	if (passwd != NULL)
		(void) strcpy(password, passwd);
	(void) ldap_value_free(rdns);
	return(0);
}

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND

#define FIVEMINS	( 5 * 60 )
#define TGT		"krbtgt"

static int
valid_tgt( char **names )
{
	int		i;
	char		name[ ANAME_SZ ], inst[ INST_SZ ], realm[ REALM_SZ ];
	CREDENTIALS	cred;

	for ( i = 0; names[i] != NULL; i++ ) {
		if ( kname_parse( name, inst, realm, names[i] ) != KSUCCESS ) {
			fprintf( stderr, "Bad format for krbName %s\n",
			    names[i] );
			fprintf( stderr, "Contact x500@umich.edu\n" );
			return( 0 );
		}

#ifdef HAVE_AFS_KERBEROS
		/*
		 * realm must be uppercase for krb_ routines
		 */
		ldap_pvt_str2upper( realm );
#endif /* HAVE_AFS_KERBEROS */

		/*
		* check ticket file for a valid ticket granting ticket
		* my check is: have ticket granting ticket and it is good for
		* at least 5 more minutes
		*/
		if ( krb_get_cred( TGT, realm, realm,
		    &cred ) == KSUCCESS && time( 0 ) + FIVEMINS <
		    cred.issue_date + (u_char)cred.lifetime * FIVEMINS ) {
			return( 1 );
		}
	}

	return( 0 );
}

static char *kauth_name;

#ifndef HAVE_KTH_KERBEROS

/*ARGSUSED*/
int
krbgetpass( char *user, char *inst, char *realm, char *pw, C_Block key )
{
	char	*p, lcrealm[ REALM_SZ ], prompt[256], *passwd;

#ifdef UOFM
	sprintf(prompt, "  Enter the UMICH password (same as Uniqname or Kerberos password)\n  for %s: ", kauth_name );
#else
	sprintf(prompt, "  Enter Kerberos password for %s: ", kauth_name );
#endif
	do {
		passwd = getpassphrase(prompt);
	} while (passwd != NULL && *passwd == '\0');
	if (passwd == NULL) {
		return(-1);
	}

#ifdef HAVE_AFS_KERBEROS
	strcpy( lcrealm, realm );
	for ( p = lcrealm; *p != '\0'; ++p ) {
		*p = TOLOWER( (unsigned char) *p );
	}

	ka_StringToKey( passwd, lcrealm, key );
#else /* HAVE_AFS_KERBEROS */
	string_to_key( passwd, key );
#endif /* HAVE_AFS_KERBEROS */

	return( 0 );
}
#endif /* HAVE_KTH_KERBEROS */

static int
kinit( char *kname )
{
	int	rc;
	char	name[ ANAME_SZ ], inst[ INST_SZ ], realm[ REALM_SZ ];

	kauth_name = kname;

	if ( kname_parse( name, inst, realm, kname ) != KSUCCESS ) {
		fprintf( stderr, "Bad format for krbName %s\n",
		    kname );
		fprintf( stderr, "Contact x500@umich.edu\n" );
		return( -1 );
	}

#ifdef HAVE_AFS_KERBEROS
	/* realm must be uppercase for AFS krb_ routines */
	ldap_pvt_str2upper( realm );
#endif /* HAVE_AFS_KERBEROS */

#ifdef HAVE_KTH_KERBEROS
	/* Kth kerberos knows how to do both string to keys */
	rc = krb_get_pw_in_tkt( name, inst, realm, TGT, realm,
		DEFAULT_TKT_LIFE, 0 );
#else
	rc = krb_get_in_tkt( name, inst, realm, TGT, realm,
	    DEFAULT_TKT_LIFE, krbgetpass, NULL, NULL );
#endif

	if ( rc != KSUCCESS ) {
		switch ( rc ) {
		case SKDC_CANT:
			fprintf( stderr, "Can't contact Kerberos server for %s\n", realm );
			break;
		default:
			fprintf( stderr, "%s: %s\n", name, krb_err_txt[ rc ] );
			break;
		}
		return( -1 );
	}

	return( 0 );
}

void
destroy_tickets( void )
{
	if ( *tktpath != '\0' ) {
		unlink( tktpath );
	}
}
#endif

static void
set_bound_dn( char *s )
{
	if (bound_dn != NULL)
		Free(bound_dn);
	bound_dn = (s == NULL) ? NULL : strdup(s);
}

/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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

#include <ldap.h>

#include "ldap_defaults.h"
#include "ud.h"

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
	if ( authmethod != LDAP_AUTH_KRBV4 )
#endif
	{
		authmethod = LDAP_AUTH_SIMPLE;
		sprintf(prompt, "  Enter your LDAP password: ");
		do {
			passwd = getpassphrase(prompt);
		} while (passwd != NULL && *passwd == '\0');
		if (passwd == NULL) {
			(void) ldap_value_free(rdns);
			return(0);
		}
	}

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
			} else
#endif
			{
				fprintf(stderr, "  The password you provided is incorrect.\n");
			}
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

static void
set_bound_dn( char *s )
{
	if (bound_dn != NULL)
		Free(bound_dn);
	bound_dn = (s == NULL) ? NULL : strdup(s);
}

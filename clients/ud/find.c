/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>

#include <ldap.h>

#include "ud.h"

static int num_picked = 0;	/* used when user picks entry at More prompt */


int
vrfy( char *dn )
{
	LDAPMessage *results = NULL;
	static char *attrs[2] = { "1.1", NULL };
	int ld_errno = 0;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->vrfy(%s)\n", dn);
#endif
	/* verify that this DN exists in the directory */
	(void) ldap_search_s(ld, dn, LDAP_SCOPE_BASE, NULL, attrs, TRUE, &results);
	(void) ldap_msgfree(results);

	ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);

	if ((ld_errno == LDAP_NO_SUCH_OBJECT) || (ld_errno == LDAP_INVALID_DN_SYNTAX))
		return(0);
	else if (ld_errno == LDAP_SUCCESS)
		return(1);
	else {
		ldap_perror(ld, "ldap_search");
		return(0);
	}
}
	

static LDAPMessage *
disambiguate( LDAPMessage *result, int matches, char **read_attrs, char *who )
{
	int choice;			/* entry that user chooses */
	int i;
	char *namelist[MAX_NUM_NAMES];	/* names found */
	char response[SMALL_BUF_SIZE];	/* results from user */
	char *name = NULL;		/* DN to lookup */
	LDAPMessage *mp = NULL;
	int ld_errno = 0;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->disambiguate(%x, %d, %x, %s)\n", result, matches, 
							read_attrs, who);
#endif

	ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);

	/*
	 *  If we are here, it means that we got back multiple answers.
	 */
	if ((ld_errno == LDAP_TIMELIMIT_EXCEEDED)
	    || (ld_errno == LDAP_SIZELIMIT_EXCEEDED)) {
		if (verbose) {
			printf("  Your query was too general and a limit was exceeded.  The results listed\n");
			printf("  are not complete.  You may want to try again with a more refined query.\n\n");
		}
		else
			printf("  Time or size limit exceeded.  Partial results follow.\n\n");
	}
	printf("  %1d names matched \"%s\".\n", matches, who);
	for (;;) {
		printf("  Do you wish to see a list of names? ");
		fflush(stdout);
		(void) memset(response, '\0', sizeof(response));
		fetch_buffer(response, sizeof(response), stdin);
		switch (response[0]) {
		case 'n' :
		case 'N' :
		case '\0' :
		case '\n' :
			return(NULL);
			/* NOTREACHED */
		case 'y' :
		case 'Y' :
			print_list(result, namelist, &matches);
			if (num_picked == 0)
				choice = pick_one(matches);
			else
				choice = num_picked;
			num_picked = 0;
			if (choice >= 0)
				name = strdup(namelist[choice]);
			/*
			 *  Now free up all of the pointers allocated in
			 *  namelist.  The print_list() routine that filled
			 *  in this collection of strings starts at 1, not 0.
			 */
			for (i = 1; namelist[i] != NULL; i++)
				Free(namelist[i]);
			if (choice < 0) {
				if (name != NULL)
					Free(name);
				return(NULL);
			}
#ifdef DEBUG
			if (debug & D_FIND) {
				printf("  Calling ldap_search_s()\n");
				printf("     ld = 0x%x\n", ld);
				printf("     search base = %s\n", name);
				printf("     scope = LDAP_SCOPE_BASE\n");
				printf("     filter = (objectClass=*)\n");
				for (i = 0; read_attrs[i] != NULL; i++)
					printf("     read_attrs[%d] = %s\n", i, read_attrs[i]);
				printf("     read_attrs[%d] = NULL\n", i);
				printf("     attrsonly = FALSE\n");
				printf("     &mp = 0x%x\n", &mp);
			}
#endif
			if (ldap_search_s(ld, name, LDAP_SCOPE_BASE, NULL, read_attrs, FALSE, &mp) != LDAP_SUCCESS) {
				ldap_perror(ld, "ldap_search_s");
				Free(name);
				ldap_msgfree(mp);
				return(NULL);
			}
			Free(name);
			return(mp);
			/* NOTREACHED */
		default :
			printf("  Please enter 'y', 'n', or RETURN.\n");
			break;
		}
	}
}

LDAPMessage *
find( char *who, int quiet )
{
	register int i, j, k;		/* general ints */
	int matches;			/* from ldap_count_entries() */
	int admonished = FALSE;
	static int attrs_set = 0;
	static char *read_attrs[MAX_ATTRS];	/* attrs to use in a read op */
	static char *search_attrs[MAX_ATTRS];	/* attrs to use in a srch op */
	static int rc;			/* return from ldap_search */
	LDAPMessage *ldtmp, *res;	/* results returned from search */
	char name[MED_BUF_SIZE];
	char response[SMALL_BUF_SIZE];
	char *cp, *dn, **rdns;
	LDAPFiltInfo *fi;

#ifdef DEBUG
	if (debug & D_TRACE)
		fprintf(stderr, "->find(%s)\n", who);
#endif
	/* did not specify a 'who' */
	if (who == NULL) {
		printf("  Locate whose entry? ");
		fflush(stdout);
		fetch_buffer(name, sizeof(name), stdin);
		if (name[0] != '\0')
			who = name;
		else
			return(NULL);
	}
	if (attrs_set == 0) {
		j = k = 0;
		attrs_set = 1;
		for (i = 0; attrlist[i].quipu_name != NULL; i++) {
			if (attrlist[i].flags & ATTR_FLAG_READ)
				read_attrs[j++] = attrlist[i].quipu_name;
			if (attrlist[i].flags & ATTR_FLAG_SEARCH)
				search_attrs[k++] = attrlist[i].quipu_name;
		}
		read_attrs[j] = NULL;
		search_attrs[k] = NULL;
	}

#if LDAP_UFN
	/*
	 *  If the user-supplied name has any commas in it, we
	 *  assume that it is a UFN, and do everything right
	 *  here.  If we don't find it, treat it as NOT a UFN.
	 */
	if (strchr(who, ',') != NULL) {
		int	savederef, deref;
#ifdef DEBUG
		if (debug & D_FIND)
			printf("\"%s\" appears to be a UFN\n", who);
#endif
		ldap_get_option(ld, LDAP_OPT_DEREF, &savederef);
		deref = LDAP_DEREF_FINDING;
		ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

		if ((rc = ldap_ufn_search_s(ld, who, search_attrs, FALSE, &res)) !=
		    LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED &&
		    rc != LDAP_TIMELIMIT_EXCEEDED) {
			ldap_perror(ld, "ldap_ufn_search_s");
			ldap_set_option(ld, LDAP_OPT_DEREF, &savederef);
			return(NULL);
		}
		if ((matches = ldap_count_entries(ld, res)) < 0) {
			ldap_perror(ld, "ldap_count_entries");
			ldap_set_option(ld, LDAP_OPT_DEREF, &savederef);
			return(NULL);
		} else if (matches == 1) {
			dn = ldap_get_dn(ld, ldap_first_entry(ld, res));
			rc = ldap_search_s(ld, dn, LDAP_SCOPE_BASE, NULL, read_attrs, FALSE, &res);
			ldap_memfree(dn);
			if (rc != LDAP_SUCCESS) {
				ldap_perror(ld, "ldap_search_s");
				return(NULL);
			}
			ldap_set_option(ld, LDAP_OPT_DEREF, &savederef);
			return(res);
		} else if (matches > 1 ) {
			return disambiguate( res, matches, read_attrs, who );
		}
		ldap_set_option(ld, LDAP_OPT_DEREF, &savederef);
	}
#endif

	/*
	 *  Old users of the MTS *USERDIRECTORY will likely wrap the name
	 *  in quotes.  Not only is this unnecessary, but it also won't work.
	 */
	for (cp = strchr(who, '"'); cp != NULL; cp = strchr(cp, '"')) {
		if (!admonished) {
			printf("  You do not need to enclose names in quotes.\n");
			admonished = TRUE;
		}
		*cp++ = ' ';
		if (*cp == '\0')
			break;
	}

	/*
	 *  It wasn't a UFN, so look it up in the usual method.
	 */
	for (fi = ldap_getfirstfilter(lfdp, "ud", who); fi != NULL;
	     fi = ldap_getnextfilter(lfdp)) {
#ifdef DEBUG
		if (debug & D_FIND)
			printf("Searching, filter = %s\n", fi->lfi_filter);
#endif

		if ((rc = ldap_search_s(ld, search_base, fi->lfi_scope, 
		fi->lfi_filter, search_attrs, FALSE, &res)) != LDAP_SUCCESS &&
	    	rc != LDAP_SIZELIMIT_EXCEEDED && rc != LDAP_TIMELIMIT_EXCEEDED) {
			ldap_perror(ld, "ldap_search_s");
			ldap_msgfree(res);
			return(NULL);
		}
		if ((matches = ldap_count_entries(ld, res)) < 0) {
			ldap_perror(ld, "ldap_count_entries");
			ldap_msgfree(res);
			return(NULL);
		}
		else if (matches == 1) {
			dn = ldap_get_dn(ld, ldap_first_entry(ld, res));
			ldap_msgfree(res);
			if (!quiet)
				printf("  Found one %s match for \"%s\"\n", 
							fi->lfi_desc, who);
			if (!fi->lfi_isexact) {
				rdns = ldap_explode_dn(dn, TRUE);
				printf("  Do you mean %s? ", *rdns);
				(void) ldap_value_free(rdns);
				fflush(stdout);
				fetch_buffer(response, sizeof(response), stdin);
				if ((response[0] == 'n') || (response[0] == 'N'))
				{
					ldap_memfree(dn);
					return(NULL);
				}
			}
#ifdef DEBUG
			if (debug & D_FIND) {
				printf("  Calling ldap_search_s()\n");
				printf("     ld = 0x%x\n", ld);
				printf("     dn = %s\n", dn);
				printf("     scope = LDAP_SCOPE_BASE\n");
				printf("     filter = %s\n", "(objectClass=*)");
				for (i = 0; read_attrs[i] != NULL; i++)
					printf("     read_attrs[%d] = %s\n", i, read_attrs[i]);
				printf("     read_attrs[%d] = NULL\n", i);
				printf("     attrsonly = FALSE\n");
				printf("     &results = 0x%x\n", &res);
			}
#endif
			if (ldap_search_s(ld, dn, LDAP_SCOPE_BASE, NULL, read_attrs, FALSE, &res) != LDAP_SUCCESS) {
				ldap_perror(ld, "ldap_search_s");
				ldap_msgfree(res);
				res = NULL;
			}
			ldap_memfree(dn);
			return(res);
		}
		else if (matches > 0) {
			ldtmp = disambiguate(res, matches, read_attrs, who);
			ldap_msgfree(res);
			return(ldtmp);
		}
		/* if we're here, there were zero matches */
		ldap_msgfree(res);
	}
	return(NULL);
}

int
pick_one( int i )
{
	int n;
	char user_pick[SMALL_BUF_SIZE];

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->pick_one(%d)\n", i);
#endif
	
	/* make the user pick an entry */
	for (;;) {
		printf("  Enter the number of the name you want or Q to quit: ");
		fflush(stdout);
		fetch_buffer(user_pick, sizeof(user_pick), stdin);
		if (user_pick[0] == 'q' || user_pick[0] == 'Q')
			return(-1);
		n = atoi(user_pick);
		if ((n > 0) && (n <= i))
			return(n);
		printf("  Invalid response\n");
	}
	/* NOTREACHED */
}

void
print_list( LDAPMessage *list, char **names, int *matches )
{
	char **rdns, **cpp;
	char resp[SMALL_BUF_SIZE];
	register LDAPMessage *ep;
	register int i = 1;
	register int rest = 4;		/* 4, not 1 */

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->print_list(%x, %x, %x)\n", list, names, matches);
#endif
	/* print a list of names from which the user will select */
	for (ep = ldap_first_entry(ld, list); ep != NULL; ep = ldap_next_entry(ld, ep)) {
		
		names[i] = ldap_get_dn(ld, ep);
		rdns = ldap_explode_dn(names[i], TRUE);
		cpp = ldap_get_values(ld, ep, "title");
		if (cpp == NULL)
			printf(" %3d. %s\n", i, *rdns);
		else
			printf(" %3d. %s, %s\n", i, *rdns, *cpp);
		ldap_value_free(rdns);
		ldap_value_free(cpp);
		i++;
		if ((rest++ > (lpp - 1)) && (i < *matches)) {
again:
			printf("  More? ");
			fflush(stdout);
			fetch_buffer(resp, sizeof(resp), stdin);
			if ((resp[0] == 'n') || (resp[0] == 'N'))
				break;
			else if ((num_picked = atoi(resp)) != 0) {
				if (num_picked < i)
					break;
				else
					goto again;
			}
			rest = 1;
		}
	}
	*matches = i - 1;
	names[i] = NULL;
	return;
}

int
find_all_subscribers( char **sub, char *group )
{
	int count;
	LDAPMessage *result;
	static char *attributes[] = { "cn", NULL };
	char filter[MED_BUF_SIZE];
	register LDAPMessage *ep;
	register int i = 0;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->find_all_subscribers(%x, %s)\n", sub, group);
#endif

	sprintf(filter, "%s=%s", "memberOfGroup", group);
	if (ldap_search_s(ld, search_base, LDAP_SCOPE_SUBTREE, filter, attributes, FALSE, &result) != LDAP_SUCCESS) {
		int ld_errno = 0;
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
		if (ld_errno == LDAP_NO_SUCH_ATTRIBUTE)
			return(0);
		ldap_perror(ld, "ldap_search_s");
		return(0);
	}
	count = ldap_count_entries(ld, result);
	if (count < 1) {
		ldap_msgfree(result);
		return(0);
	}
	if ( count > MAX_VALUES ) {
		printf( "  Only retrieving the first %d subscribers....\n",
			MAX_VALUES );
	}

	for (ep = ldap_first_entry(ld, result); i < MAX_VALUES && ep != NULL; ep = ldap_next_entry(ld, ep)) {
		sub[i++] = ldap_get_dn(ld, ep);
#ifdef DEBUG
		if (debug & D_PARSE)
			printf("sub[%d] = %s\n", i - 1, sub[i - 1]);
#endif
	}
	sub[i] = NULL;
	ldap_msgfree(result);
	return(count);
}

char *
fetch_boolean_value( char *who, struct attribute attr )
{
	LDAPMessage *result;		/* from the search below */
	register LDAPMessage *ep;	/* entry pointer */
	register char **vp;		/* for parsing the result */
	static char *attributes[] = { NULL, NULL };

#ifdef DEBUG
        if (debug & D_TRACE)
		printf("->fetch_boolean_value(%s, %s)\n", who, attr.quipu_name);
#endif
	attributes[0] = attr.quipu_name;
	if (ldap_search_s(ld, who, LDAP_SCOPE_BASE, NULL, attributes, FALSE, &result) != LDAP_SUCCESS) {
		int ld_errno = 0;
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
		if (ld_errno == LDAP_NO_SUCH_ATTRIBUTE)
			return("FALSE");
		ldap_perror(ld, "ldap_search_s");
		ldap_msgfree(result);
		return(NULL);
	}

	/*
	 *  We did a read on one name and only asked for one attribute.
	 *  There's no reason to loop through any of these structures.
	 *
	 *  If ldap_first_attribute() returns NULL, then this entry did
	 *  not have this particular attribute.
	 */
	ep = ldap_first_entry(ld, result);
	if ((vp = (char **) ldap_get_values(ld, ep, attr.quipu_name)) == NULL) {
		ldap_msgfree(result);
		return("FALSE");
	}
	else {
		ldap_msgfree(result);
		if (!strcasecmp(*vp, "TRUE")) {
			ldap_value_free(vp);
			return("TRUE");
		}
		else if (!strcasecmp(*vp, "FALSE")) {
			ldap_value_free(vp);
			return("FALSE");
		}
		else {
			fprintf(stderr, "  Got garbage -> [%s]\n", *vp);
			ldap_value_free(vp);
			return(NULL);
		}
	}
}

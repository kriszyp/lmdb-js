/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1994  Regents of the University of Michigan.
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

#include <ac/signal.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/wait.h>
#include <ac/unistd.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include <lber.h>
#include <ldap.h>

#include "ldap_defaults.h"
#include "ud.h"

static int  load_editor( void );
static int  modifiable( char *s, short flag );
static int  print_attrs_and_values( FILE *fp, struct attribute *attrs, short flag );
static int  ovalues( char *attr );
static void write_entry( void );

static char *entry_temp_file;


void
edit( char *who )
{
	LDAPMessage *mp;			/* returned from find() */
	char *dn, **rdns;			/* distinguished name */
	char name[MED_BUF_SIZE];		/* entry to modify */

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->edit(%s)\n", who);
#endif
	/*
	 *  One must be bound in order to edit an entry.
	 */
	if (bind_status == UD_NOT_BOUND) {
		if (auth((char *) NULL, 1) < 0)
			return;
	}

	/*
	 *  First, decide what entry we are going to modify.  If the
	 *  user has not included a name on the modify command line,
	 *  we will use the person who was last looked up with a find
	 *  command.  If there is no value there either, we don't know
	 *  who to modify.
	 *
	 *  Once we know who to modify, be sure that they exist, and
	 *  parse out their DN.
	 */
	if (who == NULL) {
		if (verbose) {
			printf("  Enter the name of the person or\n");
			printf("  group whose entry you want to edit: ");
		}
		else
			printf("  Edit whose entry? ");
		fflush(stdout);
		fetch_buffer(name, sizeof(name), stdin);
		if (name[0] != '\0')
			who = name;
		else
			return;
	}
	if ((mp = find(who, TRUE)) == NULL) {
		(void) ldap_msgfree(mp);
		printf("  Could not locate \"%s\" in the Directory.\n", who);
		return;
	}
	dn = ldap_get_dn(ld, ldap_first_entry(ld, mp));
	rdns = ldap_explode_dn(dn, TRUE);
	ldap_memfree(dn);
	if (verbose) {
		printf("\n  Editing directory entry \"%s\"...\n", *rdns);
	}
	parse_answer(mp);
	(void) ldap_msgfree(mp);
	(void) ldap_value_free(rdns);
	if (load_editor() < 0)
		return;
	write_entry();
	(void) unlink(entry_temp_file);
	ldap_uncache_entry(ld, Entry.DN);
	return;
}

static int
load_editor( void )
{
	FILE *fp;
	char *cp, *editor = UD_DEFAULT_EDITOR;
	static char template[MED_BUF_SIZE];
#ifndef HAVE_SPAWNLP
	int pid;
	int status;
#endif
	int rc;
	
#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->load_editor()\n");
#endif

	/* write the entry into a temp file */
	(void) strcpy(template, "/tmp/udEdit.XXXXXX");
	if ((entry_temp_file = mktemp(template)) == NULL) {
		perror("mktemp");
		return(-1);
	}
	if ((fp = fopen(entry_temp_file, "w")) == NULL) {
		perror("fopen");
		return(-1);
	}
	fprintf(fp, "## Directory entry of %s\n", Entry.name);
	fprintf(fp, "##\n");
	fprintf(fp, "## Syntax is:\n");
	fprintf(fp, "## <attribute-name>\n");
	fprintf(fp, "## 	<TAB> <value 1>\n");
	fprintf(fp, "## 	<TAB>   :  :\n");
	fprintf(fp, "## 	<TAB> <value N>\n");
	fprintf(fp, "## Lines beginning with a hash mark are comments.\n");
	fprintf(fp, "##\n");
	fflush(fp);
	if (isgroup())
		rc = print_attrs_and_values(fp, Entry.attrs, ATTR_FLAG_GROUP_MOD);
	else
		rc = print_attrs_and_values(fp, Entry.attrs, ATTR_FLAG_PERSON_MOD);
	fclose(fp);

	if ( rc != 0 ) {
	    (void) unlink(entry_temp_file);
	    return( rc );
	}

	/* edit the temp file with the editor of choice */
	if ((cp = getenv("EDITOR")) != NULL)
		editor = cp;
	if (verbose) {
		char	*p;

		if (( p = strrchr( editor, '/' )) == NULL ) {
			p = editor;
		} else {
			++p;
		}
		printf("  Using %s as the editor...\n", p );
#ifndef HAVE_SPAWNLP
		sleep(2);
#endif
	}
#ifdef HAVE_SPAWNLP
	rc = _spawnlp( _P_WAIT, editor, editor, entry_temp_file, NULL );
	if(rc != 0) {
		fatal("spawnlp");
	}
#else
	if ((pid = fork()) == 0) {	
		/* child - edit the Directory entry */
		(void) SIGNAL(SIGINT, SIG_IGN);
		(void) execlp(editor, editor, entry_temp_file, NULL);
		/*NOTREACHED*/
		(void) fatal(editor);	
	}
	else if (pid > 0) {
		/* parent - wait until the child proc is done editing */
		RETSIGTYPE (*handler)();
		handler = SIGNAL(SIGINT, SIG_IGN);
		(void) wait(&status);
		(void) SIGNAL(SIGINT, handler);
	}
	else {
		fatal("fork");
		/*NOTREACHED*/
	}
#endif
	return(0);
}

static int
print_attrs_and_values( FILE *fp, struct attribute *attrs, short int flag )
{
	register int i, j;

	for (i = 0; attrs[i].quipu_name != NULL; i++) {
		if (!modifiable(attrs[i].quipu_name,
			(short) (flag|ATTR_FLAG_MAY_EDIT)))
		{
			continue;
		}

		fprintf(fp, "%s\n", attrs[i].quipu_name);
		if ( attrs[i].number_of_values > MAX_VALUES ) {
			printf("  The %s attribute has more than %d values.\n",
				attrs[i].quipu_name, MAX_VALUES );
			printf("  You cannot use the vedit command on this entry.  Sorry!\n" );
			return( -1 );
		}
		for (j = 0; j < attrs[i].number_of_values; j++)
			fprintf(fp, "\t%s\n", attrs[i].values[j]);
	}
	return( 0 );
}

static int
modifiable( char *s, short int flag )
{
	register int i;

	for (i = 0; attrlist[i].quipu_name != NULL; i++) {
		if (strcasecmp(s, attrlist[i].quipu_name))
			continue;
		if ((attrlist[i].flags & flag) == ATTR_FLAG_NONE)
			return(FALSE);
		return(TRUE);
	}
	/* should never be here */
	return(FALSE);
}

static void
write_entry( void )
{
	int i = 0, j, number_of_values = -1;

	FILE *fp;
	char *cp, line[LARGE_BUF_SIZE], *values[MAX_VALUES], **vp;

	LDAPMod *mods[MAX_ATTRS + 1];
	LDAPMod *modp = NULL;

	/* parse the file and write the values to the Directory */
	if ((fp = fopen(entry_temp_file, "r")) == NULL) {
		perror("fopen");
		return;
	}
	for (;;) {
		(void) fgets(line, sizeof(line), fp);
		if (feof(fp))
			break;
		line[strlen(line) - 1] = '\0';		/* kill newline */
		cp = line;
		if (*cp == '#')
			continue;
		if (isspace((unsigned char)*cp)) {	/* value */
			while (isspace((unsigned char)*cp))
				cp++;
			values[number_of_values++] = strdup(cp);
			if ( number_of_values >= MAX_VALUES ) {
				printf("  A maximum of %d values can be handled at one time.  Sorry!\n", MAX_VALUES );
				return;
			}
			continue;
		}
		/* attribute */
		while (isspace((unsigned char)*cp))
			cp++;
		/*
		 *  If the number of values is greater than zero, then we
		 *  know that this is not the first time through this
		 *  loop, and we also know that we have a little bit
		 *  of work to do:
		 *
		 *	o The modify operation needs to be changed from
		 *	  a DELETE to a REPLACE
		 *
		 *	o The list of values pointer needs to be changed
		 *	  from NULL, to a NULL-terminated list of char
		 *	  pointers.
		 */
		if (number_of_values > 0) {
			modp->mod_op = LDAP_MOD_REPLACE;
			if ((vp = (char **) Malloc(sizeof(char *) * (number_of_values + 2))) == (char **) NULL) {
				fatal("Malloc");
				/*NOTREACHED*/
			}
			modp->mod_values = vp;
			for (j = 0; j < number_of_values; j++) {
				*vp++ = strdup(values[j]);
				(void) Free(values[j]);
			}
			*vp = NULL;
		}
		/*
		 *  If there are no values, and there were no values to begin
		 *  with, then there is nothing to do.
		 */
		if ((number_of_values == 0) && (ovalues(modp->mod_type) == 0)) {
#ifdef DEBUG
			if (debug & D_MODIFY)
				printf(" %s has zero values - skipping\n",
						modp->mod_type);
#endif
			(void) Free(modp->mod_type);
			modp->mod_type = strdup(cp);
			modp->mod_op = LDAP_MOD_DELETE;
			modp->mod_values = NULL;
			continue;
		}
		/*
		 *  Fetch a new modify structure.
		 *
		 *  Assume a DELETE operation with no values.
		 */
		if ((modp = (LDAPMod *) Malloc(sizeof(LDAPMod))) == NULL) {
			fatal("Malloc");
			/*NOTREACHED*/
		}
		modp->mod_values = NULL;
		modp->mod_type = strdup(cp);
		modp->mod_op = LDAP_MOD_DELETE;
		mods[i++] = modp;
		number_of_values = 0;
	}
	fclose(fp);

	/* check the last one too */
	if (number_of_values > 0) {
		modp->mod_op = LDAP_MOD_REPLACE;
		/*
		 *  Fetch some value pointers.
		 *
		 *	number_of_values	To store the values
		 *		1		For the NULL terminator
		 *		1		In case we need it to store
		 *				the RDN as on of the values
		 *				of 'cn' in case it isn't there
		 */
		if ((vp = (char **) Malloc(sizeof(char *) * (number_of_values +
						 2))) == (char **) NULL) {
			fatal("Malloc");
			/*NOTREACHED*/
		}
		modp->mod_values = vp;
		for (j = 0; j < number_of_values; j++) {
			*vp++ = strdup(values[j]);
			(void) Free(values[j]);
		}
		*vp = NULL;
	}
	else if ((number_of_values == 0) && 
				(ovalues(mods[i - 1]->mod_type) == 0)) {
#ifdef DEBUG
		if (debug & D_MODIFY)
			printf(" %s has zero values - skipping\n",
					mods[i - 1]->mod_type);
#endif
		Free(mods[i - 1]->mod_type);
		Free(mods[i - 1]);
		i--;
	}
	mods[i] = (LDAPMod *) NULL;

	/* 
	 * If one of the mods pointers is 'cn', be sure that the RDN is one
	 * of the values.
	 */
	for (j = 0; j < i; j++) {
		if (strcasecmp("cn", mods[j]->mod_type))
			continue;
		/*
		 *  True only if there WERE values, but the person deleted
		 *  them all.
		 */
		if (mods[j]->mod_values == NULL) {
			mods[j]->mod_op = LDAP_MOD_REPLACE;
			if ((vp = (char **) Malloc(sizeof(char *) * 2)) == (char **) NULL) {
				fatal("Malloc");
				/*NOTREACHED*/
			}
			mods[j]->mod_values = vp;
			*vp++ = strdup(Entry.name);
			*vp = NULL;
			break;
		}
		/*
		 *  Be sure that one of the values of 'cn' is the RDN.
		 */
		for (vp = mods[j]->mod_values; *vp != NULL; vp++) {
			if (strcasecmp(*vp, Entry.DN))
				continue;
			break;
		}
		if (*vp == NULL) {
			*vp++ = strdup(Entry.name);
			*vp = NULL;
			break;
		}
	}
#ifdef DEBUG
	if (debug & D_MODIFY) {
		register int x, y;

		printf("  ld = 0x%x\n", ld);
		printf("  dn = [%s]\n", Entry.DN);
		for (x = 0; mods[x] != (LDAPMod *) NULL; x++) {
			printf("  mods[%d]->mod_op = %s\n", 
					x, code_to_str(mods[x]->mod_op));
			printf("  mods[%d]->mod_type = %s\n", 
							x, mods[x]->mod_type);
			if (mods[x]->mod_values == NULL)
				printf("  mods[%d]->mod_values = NULL\n", x);
			else {
				for (y = 0; mods[x]->mod_values[y] != NULL; y++)
				   printf("  mods[%d]->mod_values[%1d] = %s\n", 
						x, y, mods[x]->mod_values[y]);
				printf("  mods[%d]->mod_values[%1d] = NULL\n",
									x, y);
			}
			printf("\n");
		}
	}
#endif
	if (ldap_modify_s(ld, Entry.DN, mods))
		mod_perror(ld);
	else
		printf("  Modification complete.\n" );

	/* clean up */
	for (i = 0; mods[i] != NULL; i++)
		free_mod_struct(mods[i]);
	return;
}

static int
ovalues( char *attr )
{
	struct attribute *ap;

	/*
	 *  Lookup the attribute with quipu_name 'attr' in the Entry
	 *  structure and return the number of values.
	 */
	for (ap = Entry.attrs; ap->quipu_name != NULL; ap++) {
		if (!strcasecmp(ap->quipu_name, attr))
			return(ap->number_of_values);
	}
	/* should never get to this point unless 'attr' was something odd */
	return(0);
}

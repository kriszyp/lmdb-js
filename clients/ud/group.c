/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1993, 1994  Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/unistd.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include <ldap.h>

#include "ldap_defaults.h"
#include "ud.h"

static char * bind_and_fetch(char *name);


void
add_group( char *name )
{
	int idx = 0, prompt = 0;
	char tmp[BUFSIZ], dn[BUFSIZ];
	static LDAPMod *attrs[9];
	LDAPMod init_rdn,    init_owner,   init_domain,
		init_errors, init_request, init_joinable;
	char *init_rdn_value[2], *init_owner_value[2], *init_domain_value[2],
	  	*init_errors_value[MAX_VALUES], *init_joinable_value[2],
		*init_request_value[MAX_VALUES];

#ifdef DEBUG
	if (debug & D_TRACE) {
		if (name == NULL)
			printf("->add_group(NULL)\n");
		else
			printf("->add_group(%s)\n", name);
	}
#endif

	if (bind_status == UD_NOT_BOUND) {
		if (auth((char *) NULL, 1) < 0) {
			return;
		}
	}

	/*
	 *  If the user did not supply us with a name, prompt them for
	 *  a name.
	 */
	if ((name == NULL) || (*name == '\0') || !strcasecmp(name, "group")) {
		++prompt;
		printf("  Group to create? ");
		fflush(stdout);
		fetch_buffer(tmp, sizeof(tmp), stdin);
		if (tmp[0] == '\0')
			return;
		name = strdup(tmp);
	}

	/* remove quotes, dots, and underscores. */
	name = strip_ignore_chars(name);

#ifdef UOFM
	if (isauniqname(name)) {
		printf(" '%s' could be confused with a U-M uniqname.\n", name);
		printf(" You can create the group, but you need to make sure that\n");
		printf(" you reserve the uniqname for use as your groupname\n\n");
		printf(" Are you sure that you want to do this? ");
		fflush(stdout);
		fetch_buffer(tmp, sizeof(tmp), stdin);
		if (!(tmp[0] == 'y' || tmp[0] == 'Y'))
			return;
		printf("\n Be sure to contact your uniqname administrator to reserve\n");
		printf(" the uniqname '%s' for use as your group name.\n", name);
	}
#endif
	sprintf(dn, "cn=%s, %s", name, group_base);

	/*
	 *  Make sure that this group does not already exist.
	 */
	if (vrfy(dn) == TRUE) {
		printf("  The group \"%s\" already exists.\n", name);
		return;
	}

	/*
	 *  Take the easy way out:  Fill in some reasonable values for
	 *  the most important fields, and make the user use the modify
	 *  command to change them, or to give values to other fields.
	 */
	init_rdn_value[0] = name;
	init_rdn_value[1] = NULL;
	init_rdn.mod_op = LDAP_MOD_ADD;
	init_rdn.mod_type = "cn";
	init_rdn.mod_values = init_rdn_value;
	attrs[idx++] = &init_rdn;

	init_owner_value[0] = bound_dn;
	init_owner_value[1] = NULL;
	init_owner.mod_op = LDAP_MOD_ADD;
	init_owner.mod_type = "owner";
	init_owner.mod_values = init_owner_value;
	attrs[idx++] = &init_owner;

#ifdef UOFM
	init_domain_value[0] = "umich.edu";
#else
	init_domain_value[0] = ".";
#endif
	init_domain_value[1] = NULL;
	init_domain.mod_op = LDAP_MOD_ADD;
	init_domain.mod_type = "associatedDomain";
	init_domain.mod_values = init_domain_value;
	attrs[idx++] = &init_domain;

	init_errors_value[0] = bound_dn;
	init_errors_value[1] = NULL;
	init_errors.mod_op = LDAP_MOD_ADD;
	init_errors.mod_type = "ErrorsTo";
	init_errors.mod_values = init_errors_value;
	attrs[idx++] = &init_errors;

	init_request_value[0] = bound_dn;
	init_request_value[1] = NULL;
	init_request.mod_op = LDAP_MOD_ADD;
	init_request.mod_type = "RequestsTo";
	init_request.mod_values = init_request_value;
	attrs[idx++] = &init_request;

	init_joinable_value[0] = "FALSE";
	init_joinable_value[1] = NULL;
	init_joinable.mod_op = LDAP_MOD_ADD;
	init_joinable.mod_type = "joinable";
	init_joinable.mod_values = init_joinable_value;
	attrs[idx++] = &init_joinable;

	/* end it with a NULL */
	attrs[idx] = NULL;

#ifdef DEBUG
	if (debug & D_GROUPS) {
		LDAPMod **lpp;
		char **cpp;
		int i, j;
		printf("  About to call ldap_add()\n");
		printf("  ld = 0x%x\n", ld);
		printf("  dn = [%s]\n", dn);
		for (lpp = attrs, i = 0; *lpp != NULL; lpp++, i++) {
			printf("  attrs[%1d]  code = %s  type = %s\n", i, 
				code_to_str((*lpp)->mod_op), (*lpp)->mod_type);
			for (cpp = (*lpp)->mod_values, j = 0; *cpp != NULL; cpp++, j++)
				printf("    value #%1d = %s\n", j, *cpp);
			printf("    value #%1d = NULL\n", j);
		}
	}
#endif

	/*
	 *  Now add this to the LDAP Directory.
	 */
	if (ldap_add_s(ld, dn, attrs) != 0) {
		ldap_perror(ld, "  ldap_add_s");
		printf("  Group not added.\n");
		if (prompt) Free(name);
		return;
	}
	if (verbose)
		printf("  Group \"%s\" has been added to the Directory\n",
		       name);

	/*
	 *  We need to blow away the cache here.
	 *
	 *  Since we first looked up the name before trying to create it,
	 *  and that look-up failed, the cache will falsely claim that this
	 *  entry does not exist.
	 */
	(void) ldap_flush_cache(ld);
	if (prompt) Free(name);
	return;
}

void
remove_group( char *name )
{
	char *dn, tmp[BUFSIZ];

#ifdef DEBUG
	if (debug & D_TRACE) {
		if (name == NULL)
			printf("->remove_group(NULL)\n");
		else
			printf("->remove_group(%s)\n", name);
	}
#endif
	if ((dn = bind_and_fetch(name)) == NULL)
		return;

	printf("\n  The entry\n    '%s'\n  will be permanently removed from", dn);
	printf(" the Directory.\n  Are you absolutely sure that you want to" );
	printf(" remove this entire group? ");
	fflush(stdout);
	fetch_buffer(tmp, sizeof(tmp), stdin);
	if (!(tmp[0] == 'y' || tmp[0] == 'Y'))
		return;

	/*
	 *  Now remove this from the LDAP Directory.
	 */
	if (ldap_delete_s(ld, dn) != 0) {
		int ld_errno = 0;
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
		if (ld_errno == LDAP_INSUFFICIENT_ACCESS)
			printf("  You do not own the entry\n\t\"%s\".\n", dn);
		else
			ldap_perror(ld, "  ldap_delete_s");
		printf("  Group not removed.\n");
		Free(dn);
		return;
	}
	ldap_uncache_entry(ld, dn);
	if (verbose)
	{
	    if (name == NULL)
		printf("  The group has been removed.\n");
	    else
		printf("  The group \"%s\" has been removed.\n", name);
	}
	Free(dn);
	return;
}

void
x_group( int action, char *name )
{
	char **vp;
	char *values[2], *group_name;
	LDAPMod mod, *mods[2];
	static char *actions[] = { "join", "resign from", NULL };

#ifdef DEBUG
	if (debug & D_TRACE) {
		if (name == NULL)
			printf("->x_group(%d, NULL)\n", action);
		else
			printf("->x_group(%d, %s)\n", action, name);
	}
#endif

	/* the action desired sets the opcode to use */
	switch (action) {
	case G_JOIN:
		mod.mod_op = LDAP_MOD_ADD;
		break;
	case G_RESIGN:
		mod.mod_op = LDAP_MOD_DELETE;
		break;
	default:
		printf("x_group:  %d is not a known action\n", action);
	}

	if ((group_name = bind_and_fetch(name)) == NULL)
		return;
	vp = Entry.attrs[attr_to_index("joinable")].values;
	if (action == G_JOIN) {
		if (vp == NULL) {
			printf("  No one is permitted to join \"%s\"\n", group_name);
			Free(group_name);
			return;
		}
		if (!strcasecmp(*vp, "FALSE")) {
			printf("  No one is permitted to join \"%s\"\n", group_name);
			Free(group_name);
			return;
		}
	}

	/*  fill in the rest of the modification structure */
	mods[0] = &mod;
	mods[1] = (LDAPMod *) NULL;
	values[0] = Entry.DN;
	values[1] = NULL;
	mod.mod_type = "memberOfGroup";
	mod.mod_values = values;

#ifdef DEBUG
	if (debug & D_GROUPS) {
		register LDAPMod **lpp;
		register char **cp;
		register int i, j;
		printf("  About to call ldap_modify_s()\n");
		printf("  ld = 0x%x\n", ld);
		printf("  dn = [%s]\n", bound_dn);
		for (lpp = mods, i = 1; *lpp != NULL; lpp++, i++) {
			printf("  mods[%1d] code = %1d\n", i, (*lpp)->mod_op);
			printf("  mods[%1d] type = %s\n", i, (*lpp)->mod_type);
			for (cp = (*lpp)->mod_values, j = 1; *cp != NULL; cp++, j++)
				printf("  mods[%1d] v[%1d] = %s\n", i, j, *cp);
				
		}
	}
#endif

	if (ldap_modify_s(ld, bound_dn, mods)) {
		int ld_errno = 0;
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
		if ((action == G_JOIN) && (ld_errno == LDAP_TYPE_OR_VALUE_EXISTS))
			printf("  You are already subscribed to \"%s\"\n", group_name);
		else if ((action == G_RESIGN) && (ld_errno == LDAP_NO_SUCH_ATTRIBUTE))
			printf("  You are not subscribed to \"%s\"\n", group_name);
		else
			mod_perror(ld);
		Free(group_name);
		return;
	}
	ldap_uncache_entry(ld, bound_dn);
	if (verbose) {
		switch (action) {
		case G_JOIN:
			printf("  You are now subscribed to \"%s\"\n", group_name);
			break;
		case G_RESIGN:
			printf("  You are no longer subscribed to \"%s\"\n", group_name);
			break;
		}
	}
	Free(group_name);
	return;
}

void
bulk_load( char *group )
{
	register int idx_mail, idx_x500;
	register int count_mail, count_x500;
	char *values_mail[MAX_VALUES + 1], *values_x500[MAX_VALUES + 1];
	int added_mail_entries = FALSE, added_x500_entries = FALSE;
	char s[MED_BUF_SIZE];
	LDAPMod mod, *mods[2];
	LDAPMessage *lm;
	FILE *fp;
	int len;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->bulk_load(%s)\n", group);
#endif

	/* you lose if going through MichNet */
	if ( !isatty( 1 )) {
#ifdef UOFM
		printf("  Not allowed via UM-X500 connections.\n");
#endif
		return;
	}

	/* fetch entries from the file containing the e-mail addresses */
	printf("\n  File to load? ");
	fflush(stdout);
	fetch_buffer(s, sizeof(s), stdin);
	if (s[0] == '\0') {
		return;
		/*NOTREACHED*/
	}
	if ((fp = fopen(s, "r")) == NULL) {
		perror("bulk_load: fopen");
		return;
	}
	if (verbose)
		printf("  Loading group members from %s\n", s);

	/* load them in MAX_VALUES at a time */
	for (;;) {
		for (idx_mail = 0, idx_x500 = 0; 
		     idx_mail < MAX_VALUES && idx_x500 < MAX_VALUES; ) {
			(void) fgets(s, sizeof(s), fp);
			if (feof(fp))
				break;
			len = strlen(s) - 1;
			if (len == 0)
				continue;
			s[len] = '\0';
			if (strchr(s, '@'))
				values_mail[idx_mail++] = strdup(s);
			else {
				if ((lm = find(s, !verbose)) == (LDAPMessage *) NULL) {
					printf("  Could not locate \"%s\" -- skipping.\n", s);
				}
				else {
				    parse_answer(lm);
				    values_x500[idx_x500++] = strdup(Entry.DN);
				}
			}
		}
		values_mail[idx_mail] = NULL;
		values_x500[idx_x500] = NULL;
		count_mail = idx_mail;
		count_x500 = idx_x500;

		/*
		 *  Add the e-mail addresses.
		 */
		if (count_mail > 0) {
			mods[0] = &mod;
			mods[1] = (LDAPMod *) NULL;
			mod.mod_type = "mail";
			mod.mod_values = values_mail;
			if (added_mail_entries)
				mod.mod_op = LDAP_MOD_ADD;
			else
				mod.mod_op = LDAP_MOD_REPLACE;

#ifdef DEBUG
			if (debug & D_GROUPS) {
		    	register LDAPMod **lpp;
		    	register char **cp;
		    	register int i, j;
		    	printf("  About to call ldap_modify_s()\n");
		    	printf("  ld = 0x%x\n", ld);
		    	printf("  dn = [%s]\n", group);
		    	for (lpp = mods, i = 1; *lpp != NULL; lpp++, i++) {
		    		printf("  mods[%1d] code = %1d\n", i, (*lpp)->mod_op);
		    		printf("  mods[%1d] type = %s\n", i, (*lpp)->mod_type);
		    		for (cp = (*lpp)->mod_values, j = 1; *cp != NULL; cp++, j++)
			   		printf("  mods[%1d] v[%1d] = %s\n", i, j, *cp);
				}
			}
#endif
			if (ldap_modify_s(ld, group, mods))
				mod_perror(ld);
			for (idx_mail--; idx_mail >= 0; idx_mail--)
				Free(values_mail[idx_mail]);
			ldap_uncache_entry(ld, group);
			added_mail_entries = TRUE;

		}

		/*
		 *  Add the LDAP style names.
		 */
		if (count_x500 > 0) {
			mods[0] = &mod;
			mods[1] = (LDAPMod *) NULL;
			mod.mod_type = "member";
			mod.mod_values = values_x500;
			if (added_x500_entries)
				mod.mod_op = LDAP_MOD_ADD;
			else
				mod.mod_op = LDAP_MOD_REPLACE;

#ifdef DEBUG
			if (debug & D_GROUPS) {
		    	register LDAPMod **lpp;
		    	register char **cp;
		    	register int i, j;
		    	printf("  About to call ldap_modify_s()\n");
		    	printf("  ld = 0x%x\n", ld);
		    	printf("  dn = [%s]\n", group);
		    	for (lpp = mods, i = 1; *lpp != NULL; lpp++, i++) {
		    		printf("  mods[%1d] code = %1d\n", i, (*lpp)->mod_op);
		    		printf("  mods[%1d] type = %s\n", i, (*lpp)->mod_type);
		    		for (cp = (*lpp)->mod_values, j = 1; *cp != NULL; cp++, j++)
			   		printf("  mods[%1d] v[%1d] = %s\n", i, j, *cp);
				}
			}
#endif
			if (ldap_modify_s(ld, group, mods))
				mod_perror(ld);
			for (idx_x500--; idx_x500 >= 0; idx_x500--)
				Free(values_x500[idx_x500]);
			ldap_uncache_entry(ld, group);
			added_x500_entries = TRUE;

		}

		/*
		 *  If both counts were less than the maximum number we
		 *  can handle at a time, then we are done.
		 */
		if ((count_mail < MAX_VALUES) && (count_x500 < MAX_VALUES))
			break;
	}
	fclose(fp);
	return;
}

void
purge_group( char *group )
{
	int isclean = TRUE;
	LDAPMessage *lm;
	LDAPMod mod, *mods[2];
	char dn[BUFSIZ], tmp[BUFSIZ], *values[2], **vp, **rdns;

#ifdef DEBUG
	if (debug & D_TRACE) {
		if (group == NULL)
			printf("->purge_group(NULL)\n");
		else
			printf("->purge_group(%s)\n", group);
	}
#endif
	if (bind_status == UD_NOT_BOUND) {
		if (auth((char *) NULL, 1) < 0)
			return;
	}
	/*
	 *  If the user did not supply us with a name, prompt them for
	 *  a name.
	 */
	if ((group == NULL) || (*group == '\0')) {
		printf("Group to purge? ");
		fflush(stdout);
		fetch_buffer(tmp, sizeof(tmp), stdin);
		if (tmp[0] == '\0')
			return;
		group = tmp;
	}
	sprintf(dn, "cn=%s, %s", group, group_base);

	/* make sure the group in question exists */
	if ((lm = find(group, FALSE)) == (LDAPMessage *) NULL) {
		printf("  Could not locate group \"%s\"\n", group);
		return;
	}
	parse_answer(lm);
	ldap_msgfree(lm);

	/* none of this stuff changes */
	mods[0] = &mod;
	mods[1] = (LDAPMod *) NULL;

	values[1] = NULL;

	mod.mod_values = values;
	mod.mod_type = "member";
	mod.mod_op = LDAP_MOD_DELETE;

	/*
	 *  Now cycle through all of the names in the "members" part of the
	 *  group (but not the e-mail address part).  Lookup each one, and
	 *  if it isn't found, let the user know so s/he can delete it.
	 */
	vp = Entry.attrs[attr_to_index("member")].values;
	if (vp == NULL) {
		if (verbose)
			printf("  \"%s\" has no LDAP members.  There is nothing to purge.\n", group);
		return;
	}
	for (; *vp != NULL; vp++) {
		char ans[BUFSIZ], *ufn, *label = "Did not find:  ";
		int len = strlen(label);

		if (vrfy(*vp))
			continue;
		isclean = FALSE;
		ufn = my_ldap_dn2ufn(*vp);
		format2(ufn, label, (char *) NULL, 2, 2 + len, col_size);
ask:
		printf("  Purge, Keep, Replace, Abort [Keep]? ");
		fflush(stdout);
		fetch_buffer(ans, sizeof(ans), stdin);
		if ((ans[0] == '\0') || !strncasecmp(ans, "Keep", strlen(ans)))
			continue;
		if (!strncasecmp(ans, "Abort", strlen(ans))) {
			ldap_uncache_entry(ld, dn);
			return;
		}
		if (!strncasecmp(ans, "Purge", strlen(ans)) || !strncasecmp(ans, "Replace", strlen(ans))) {
			values[0] = *vp;
#ifdef DEBUG
			if (debug & D_GROUPS) {
				register LDAPMod **lpp;
				register char **cp;
				register int i, j;
				printf("  About to call ldap_modify_s()\n");
				printf("  ld = 0x%x\n", ld);
				printf("  dn = [%s]\n", Entry.DN);
				for (lpp = mods, i = 1; *lpp != NULL; lpp++, i++) {
					printf("  mods[%1d] code = %1d\n", i, (*lpp)->mod_op);
					printf("  mods[%1d] type = %s\n", i, (*lpp)->mod_type);
					for (cp = (*lpp)->mod_values, j = 1; *cp != NULL; cp++, j++)
						printf("  mods[%1d] v[%1d] = %s\n", i, j, *cp);
						
				}
			}
#endif
			if (ldap_modify_s(ld, Entry.DN, mods))
				mod_perror(ld);

			/* now add the replacement if requested */
			if (!strncasecmp(ans, "Purge", strlen(ans)))
				continue;
			rdns = ldap_explode_dn(*vp, TRUE);
			if ((lm = find(*rdns, FALSE)) == NULL) {
				printf("  Could not find a replacement for %s; purged only.\n", *rdns);
				ldap_msgfree(lm);
				ldap_value_free(rdns);
				break;
			}
			values[0] = ldap_get_dn(ld, ldap_first_entry(ld, lm));
			mod.mod_op = LDAP_MOD_ADD;
#ifdef DEBUG
			if (debug & D_GROUPS) {
				register LDAPMod **lpp;
				register char **cp;
				register int i, j;
				printf("  About to call ldap_modify_s()\n");
				printf("  ld = 0x%x\n", ld);
				printf("  dn = [%s]\n", Entry.DN);
				for (lpp = mods, i = 1; *lpp != NULL; lpp++, i++) {
					printf("  mods[%1d] code = %1d\n", i, (*lpp)->mod_op);
					printf("  mods[%1d] type = %s\n", i, (*lpp)->mod_type);
					for (cp = (*lpp)->mod_values, j = 1; *cp != NULL; cp++, j++)
						printf("  mods[%1d] v[%1d] = %s\n", i, j, *cp);
						
				}
			}
#endif
			if (ldap_modify_s(ld, Entry.DN, mods))
				mod_perror(ld);
			ldap_msgfree(lm);
			ldap_value_free(rdns);
	
			/* set this back to DELETE for other purges */
			mod.mod_op = LDAP_MOD_DELETE;
		}
		else {
			printf("  Did not recognize that answer.\n\n");
			goto ask;
		}
	}
	ldap_uncache_entry(ld, Entry.DN);
	if (isclean)
		printf("  No entries were purged.\n");
	return;
}

void
tidy_up( void )
{
	register int i = 0;
	int found_one = 0;
	register char **vp;
	LDAPMessage *lm;
	static LDAPMod mod;
	static LDAPMod *mods[2] = { &mod, NULL };
	static char *values[MAX_VALUES];

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->tidy()\n");
#endif

	if (bind_status == UD_NOT_BOUND) {
		if (auth((char *) NULL, 1) < 0) {
			return;
		}
	}

	/* lookup the user, and see to which groups he has subscribed */
	vp = ldap_explode_dn(bound_dn, TRUE);
	if ((lm = find(*vp, TRUE)) == (LDAPMessage *) NULL) {
		printf("  Could not locate \"%s\"\n", *vp);
		ldap_value_free(vp);
		return;
	}
	ldap_value_free(vp);
	parse_answer(lm);
	ldap_msgfree(lm);
	vp = Entry.attrs[attr_to_index("memberOfGroup")].values;
	if (vp == NULL) {
		printf("  You have not subscribed to any groups.\n");
		return;
	}

	/* now, loop through these groups, deleting the bogus */
	for ( ; *vp != NULL; vp++) {
		if (vrfy(*vp))
			continue;
		found_one++;
		printf("  \"%s\" is not a valid group name.\n", *vp);
		values[i++] = strdup(*vp);
		if ( i >= MAX_VALUES ) {
			printf( "  At most %d invalid groups can be removed at one time; skipping the rest.\n", MAX_VALUES );
			break;
		}
	}
	if (found_one == 0) {
		if (verbose)
			printf("  You are not a member of any invalid groups.  There is nothing to tidy.\n");
		return;
	}

	/* delete the most heinous entries */
	values[i] = NULL;
	mod.mod_values = values;
	mod.mod_op = LDAP_MOD_DELETE;
	mod.mod_type = "memberOfGroup";
	if (ldap_modify_s(ld, bound_dn, mods))
		mod_perror(ld);
	ldap_uncache_entry(ld, bound_dn);

	/* tidy up before we finish tidy_up */
	for ( ; i >= 1; i--)
		Free(values[i - 1]);
	return;
}

/*
 *  This routine is used to modify lists that can contain either Distinguished
 *  Names or e-mail addresses.  This includes things like group members,
 *  the errors-to field in groups, and so on.
 */
void
mod_addrDN( char *group, int offset )
{
	char s[BUFSIZ], *new_value /* was member */, *values[2];
	char attrtype[ 64 ];
	LDAPMod mod, *mods[2];
	LDAPMessage *mp;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->mod_addrDN(%s)\n", group);
#endif
	/*
	 *  At this point the user can indicate that he wishes to add values
	 *  to the attribute, delete values from the attribute, or replace the 
	 *  current list of values with a new list.  The first two cases
	 *  are very straight-forward, but the last case requires a little
	 *  extra care and work.
	 */
	if (verbose) {
		printf("\n");
		if ( !isatty( 1 ))
			format("There are three options available at this point.  You may:  Add additional values; Delete values; or Replace the entire list of values with a new list entered interactively.\n", 75, 2);
		else
			format("There are four options available at this point.  You may:  Add one or more additional values; Delete one or more existing values; Replace the entire list of values with a new list entered interactively; or Bulk load a new list of values from a file, overwriting the existing list.\n", 75, 2);
	}

	/* initialize the modififier type */
	mod.mod_type = NULL;

	for (;;) {
		if ( !isatty( 1 ))
			printf("  Do you want to Add, Delete, or Replace? ");
		else
			printf("  Do you want to Add, Delete, Replace, or Bulk load? ");
		fflush(stdout);
		fetch_buffer(s, sizeof(s), stdin);
		if (s[0] == '\0') {
			return;
			/*NOTREACHED*/
		}
		if (!strncasecmp(s, "add", strlen(s))) {
			mod.mod_op = LDAP_MOD_ADD;
			break;
		}
		else if (!strncasecmp(s, "delete", strlen(s))) {
			mod.mod_op = LDAP_MOD_DELETE;
			break;
		}
		else if (!strncasecmp(s, "replace", strlen(s))) {
			mod.mod_op = LDAP_MOD_REPLACE;
			break;
		}
		else if(!strncasecmp(s, "bulk", strlen(s))) {
			bulk_load(group);
			return;
		}
		else if (verbose) {
			printf("\n");
			if ( !isatty( 1 ))
				format("Did not recognize that response.  Please use 'A' to add, 'D' to delete, or 'R' to replace the entire list with a new list\n", 75, 2);
			else
				format("Did not recognize that response.  Please use 'A' to add, 'D' to delete, 'R' to replace the entire list with a new list, or 'B' to bulk load a new list from a file\n", 75, 2);
		}
	}
	if (mod.mod_op == LDAP_MOD_REPLACE) {
		if ( verbose && !confirm_action( "The entire existing list will be overwritten with the new values you are about to enter." )) {
			printf("\n  Modification halted.\n");
			return;
		}
	}
	if (verbose) {
		printf("\n");
		format("Values may be specified as a name (which is then looked up in the LDAP Directory) or as a domain-style (i.e., user@domain) e-mail address.  Simply hit the RETURN key at the prompt when finished.\n", 75, 2);
		printf("\n");
	}

	for (;;) {
		printf("%s? ", attrlist[offset].output_string);
		fflush(stdout);
		fetch_buffer(s, sizeof(s), stdin);
		if (s[0] == '\0')
			return;

		/*
	 	 *  If the string the user has just typed has an @-sign in it,
	 	 *  then we assume it is an e-mail address.  In this case, we
	 	 *  just store away whatever it is they have typed.
	 	 *
	 	 *  If the string had no @-sign, then we look in the Directory,
	 	 *  make sure it exists, and if it does, we add that.
		 *
		 *  If the string begins with a comma, then strip off the
		 *  comma, and pass it along to the LDAP server.  This is
		 *  the way one can force ud to accept a name.  Handy for
		 *  debugging purposes.
	 	 */
		if (*s == ',') {
			new_value = s + 1;
			mod.mod_type = attrlist[offset].quipu_name;
		}
		else if (strchr(s, '@') == NULL) {
			if ((mp = find(s, FALSE)) == (LDAPMessage *) NULL) {
				printf("  Could not find \"%s\"\n", s);
				if (verbose && (mod.mod_op == LDAP_MOD_DELETE)){
					printf("\n");
					format("I could not find anything that matched what you typed.  You might try the \"purge\" command instead.  It is used to purge corrupted or unlocatable entries from a group.", 75, 2);
					printf("\n");
				}
				continue;
			}
			parse_answer(mp);
			new_value = Entry.DN;
			mod.mod_type = attrlist[offset].quipu_name;
		}
		else if (mod.mod_op != LDAP_MOD_DELETE) {
			/*
			 * Don't screw around with what the user has typed
			 * if they are simply trying to delete a rfc822mailbox
			 * value.
			 *
			 * spaces on the left hand side of the e-mail
			 * address are bad news - we know that there
			 * must be a @-sign in the string, or else we
			 * would not be here
			 *
			 * note that this means a value like:
			 *
			 *	first m. last@host.domain
			 *
			 * will be turned into:
			 *
			 *	first.m..last@host.domain
			 *
			 * and the mailer will need to do the right thing
			 * with this; alternatively we could add code that
			 * collapsed multiple dots into a single dot
			 *
			 * Don't screw up things like:
			 *
			 *	"Bryan Beecher" <bryan@umich.edu>
			 *	 Bryan Beecher  <bryan@umich.edu>
			 */
			char *cp;
			if (strchr(s, '<') == NULL) {
				for (cp = s; *cp != '@'; cp++)
					if (isspace((unsigned char)*cp))
						*cp = '.';
			}
			new_value = s;
			strcpy(attrtype, "rfc822");
			strcat(attrtype, attrlist[offset].quipu_name);
			mod.mod_type = attrtype;
		}
		else {
			new_value = s;
			strcpy(attrtype, "rfc822");
			strcat(attrtype, attrlist[offset].quipu_name);
			mod.mod_type = attrtype;
		}

		/*  fill in the rest of the ldap_mod() structure */
		mods[0] = &mod;
		mods[1] = (LDAPMod *) NULL;

		values[0] = new_value;
		values[1] = NULL;
		mod.mod_values = values;

#ifdef DEBUG
		if (debug & D_GROUPS) {
			LDAPMod **lpp;
			char **cp;
			int i, j;
			printf("  About to call ldap_modify_s()\n");
			printf("  ld = 0x%x\n", ld);
			printf("  dn = [%s]\n", group);
			for (lpp = mods, i = 1; *lpp != NULL; lpp++, i++) {
				printf("  mods[%1d] code = %1d\n", 
							i, (*lpp)->mod_op);
				printf("  mods[%1d] type = %s\n", 
							i, (*lpp)->mod_type);
				for (cp = (*lpp)->mod_values, j = 1; *cp != NULL; cp++, j++)
					printf("  mods[%1d] v[%1d] = %s\n", 
								i, j, *cp);
			}
		}
#endif

		if (my_ldap_modify_s(ld, group, mods)) {
			int ld_errno = 0;
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
			if (ld_errno == LDAP_NO_SUCH_ATTRIBUTE) {
				printf("  Could not locate value \"%s\"\n", 
								new_value);
				continue;
			}
			else {
				mod_perror(ld);
				return;
			}
		}
		ldap_uncache_entry(ld, group);

		/*
	 	 *  If the operation was REPLACE, we now need to "zero out" the
	 	 *  other "half" of the list (e.g., user specified an e-mail
	 	 *  address; now we need to clear the DN part of the list).
		 *
		 *  NOTE:  WE HAVE ALREADY DONE HALF OF THE REPLACE ABOVE.
	 	 *
	 	 *  Also, change the opcode to LDAP_MOD_ADD and give the user an
	 	 *  opportunity to add additional members to the group.  We
	 	 *  only take this branch the very first time during a REPLACE
	 	 *  operation.
	 	 */
		if (mod.mod_op == LDAP_MOD_REPLACE) {
			if (!strncmp(mod.mod_type, "rfc822", 6))
				mod.mod_type = mod.mod_type + 6;
			else {
				strcpy(attrtype, "rfc822");
				strcat(attrtype, mod.mod_type);
				mod.mod_type = attrtype;
			}
			mods[0] = &mod;
			values[0] = NULL;
			mod.mod_values = values;
			mod.mod_op = LDAP_MOD_DELETE;
#ifdef DEBUG
			if (debug & D_GROUPS) {
				LDAPMod **lpp;
				char **cp;
				int i, j;
				printf("  About to call ldap_modify_s()\n");
				printf("  ld = 0x%x\n", ld);
				printf("  dn = [%s]\n", group);
				for (lpp = mods, i = 1; *lpp != NULL; lpp++, i++) {
					printf("  mods[%1d] code = %1d\n", 
							i, (*lpp)->mod_op);
					printf("  mods[%1d] type = %s\n", 
							i, (*lpp)->mod_type);
					for (cp = (*lpp)->mod_values, j = 1; *cp != NULL; cp++, j++)
						printf("  mods[%1d] v[%1d] = %s\n", i, j, *cp);
				}
			}
#endif
			if (my_ldap_modify_s(ld, group, mods)) {
				/*
			 	*  A "No such attribute" error is no big deal.
			 	*  We only wanted to clear the attribute anyhow.
			 	*/
				int ld_errno = 0;
				ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
				if (ld_errno != LDAP_NO_SUCH_ATTRIBUTE) {
					mod_perror(ld);
					return;
				}
			}
			ldap_uncache_entry(ld, group);
			if (verbose)
				printf("  \"%s\" has been added\n", new_value);
			mod.mod_op = LDAP_MOD_ADD;
		}
		else if (verbose && (mod.mod_op == LDAP_MOD_ADD))
			printf("  \"%s\" has been added\n", new_value);
		else if (verbose && (mod.mod_op == LDAP_MOD_DELETE))
			printf("  \"%s\" has been removed\n", new_value);
	}
}

int
my_ldap_modify_s( LDAP *ldap, char *group, LDAPMod **mods )
{
	int	was_rfc822member, rc;

	was_rfc822member = 0;

	if (!strcasecmp(mods[0]->mod_type, "rfc822member")) {
		mods[0]->mod_type = "mail";
		was_rfc822member = 1;
	}

	rc = ldap_modify_s(ldap, group, mods);

	if (was_rfc822member)
	    mods[0]->mod_type = "rfc822member";

	return(rc);
}

void
list_groups( char *who )
{
	LDAPMessage *mp;
	char name[BUFSIZ], filter[BUFSIZ], *search_attrs[2];
	char *work_area[MAX_NUM_NAMES];
	char *dn, **rdns;
	int i, rc;
	

#ifdef DEBUG
	if (debug & D_TRACE) {
		if (who == NULL)
			printf("->list_groups(NULL)\n");
		else
			printf("->list_groups(%s)\n", who);
	}
#endif
	/*
	 *  First, decide what entry we are going to list.  If the
	 *  user has not included a name on the list command line,
	 *  we will use the person who was last looked up with a find
	 *  command.
	 *
	 *  Once we know who to modify, be sure that they exist, and
	 *  parse out their DN.
	 */
	if (who == NULL) {
		printf("  List groups belonging to whose entry? ");
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
	ldap_msgfree(mp);
	rdns = ldap_explode_dn(dn, TRUE);
	if (verbose)
		printf("\n  Listing groups belonging to \"%s\"\n", *rdns);

	/* lookup the groups belonging to this person */
	sprintf(filter, "owner=%s", dn);
	ldap_memfree(dn);
	search_attrs[0] = "cn";
	search_attrs[1] = NULL;
	if ((rc = ldap_search_s(ld, UD_WHERE_ALL_GROUPS_LIVE, LDAP_SCOPE_SUBTREE, 
		filter, search_attrs, FALSE, &mp)) != LDAP_SUCCESS &&
	    rc != LDAP_SIZELIMIT_EXCEEDED && rc != LDAP_TIMELIMIT_EXCEEDED) {
		ldap_perror(ld, "ldap_search_s");
		ldap_value_free(rdns);
		return;
	}
	if ((rc = ldap_count_entries(ld, mp)) < 0) {
		ldap_perror(ld, "ldap_count_entries");
		ldap_value_free(rdns);
		return;
	}
	if (rc == 0) {
		printf("  %s owns no groups in this portion of the Directory.\n", *rdns);
		ldap_value_free(rdns);
		return;
	}
	if (verbose)
		printf("  %s owns %d groups.\n\n", *rdns, rc);
	print_list(mp, work_area, &rc);
	for (i = 1; work_area[i] != NULL; i++)
		Free(work_area[i]);
	ldap_msgfree(mp);
	ldap_value_free(rdns);
	return;
}

static char *
bind_and_fetch( char *name )
{
	LDAPMessage *lm;
	char tmp[MED_BUF_SIZE];

#ifdef DEBUG
	if (debug & D_TRACE) {
		if (name == NULL)
			printf("->bind_and_fetch(NULL)\n");
		else
			printf("->bind_and_fetch(%s)\n", name);
	}
#endif
	if (bind_status == UD_NOT_BOUND) {
		if (auth((char *) NULL, 1) < 0)
			return(NULL);
	}

	/*
	 *  If the user did not supply us with a name, prompt them for
	 *  a name.
	 */
	if ((name == NULL) || (*name == '\0')) {
		printf("  Group? ");
		fflush(stdout);
		fetch_buffer(tmp, sizeof(tmp), stdin);
		if (tmp[0] == '\0')
			return(NULL);
		name = tmp;
	}
	/* remove quotes, dots, and underscores. */
	name = strip_ignore_chars(name);

#ifdef DEBUG
	if (debug & D_GROUPS)
		printf("Group name = (%s)\n", name);
#endif

	/* make sure the group in question exists and is joinable */
	if ((lm = find(name, TRUE)) == (LDAPMessage *) NULL) {
		printf("  Could not locate group \"%s\"\n", name);
		return(NULL);
	}
	parse_answer(lm);
	ldap_msgfree(lm);

#ifdef DEBUG
	if (debug & D_GROUPS)
		printf("Group DN = (%s)\n", Entry.DN);
#endif
	return(strdup(Entry.DN));
}

void
list_memberships( char *who )
{
	LDAPMessage *mp;
	char name[BUFSIZ], filter[BUFSIZ], *search_attrs[2];
	char *work_area[MAX_NUM_NAMES];
	char *dn, **rdns;
	int i, rc;
	

#ifdef DEBUG
	if (debug & D_TRACE) {
		if (who == NULL)
			printf("->list_memberships(NULL)\n");
		else
			printf("->list_memberships(%s)\n", who);
	}
#endif
	/*
	 *  First, decide what entry we are going to list.  If the
	 *  user has not included a name on the list command line,
	 *  we will use the person who was last looked up with a find
	 *  command.
	 *
	 *  Once we know who to modify, be sure that they exist, and
	 *  parse out their DN.
	 */
	if (who == NULL) {
		printf("  List memberships containing whose entry? ");
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
		ldap_msgfree(mp);
		return;
	}
	dn = ldap_get_dn(ld, ldap_first_entry(ld, mp));
	rdns = ldap_explode_dn(dn, TRUE);
	if (verbose)
		printf("\n  Listing memberships of \"%s\"\n", *rdns);

	/* lookup the groups belonging to this person */
	sprintf(filter, "member=%s", dn);
	ldap_memfree(dn);
	search_attrs[0] = "cn";
	search_attrs[1] = NULL;
	ldap_msgfree(mp);
	if ((rc = ldap_search_s(ld, UD_WHERE_ALL_GROUPS_LIVE, LDAP_SCOPE_SUBTREE, 
		filter, search_attrs, FALSE, &mp)) != LDAP_SUCCESS &&
	    rc != LDAP_SIZELIMIT_EXCEEDED && rc != LDAP_TIMELIMIT_EXCEEDED) {
		ldap_perror(ld, "ldap_search_s");
		ldap_msgfree(mp);
		ldap_value_free(rdns);
		return;
	}
	if ((rc = ldap_count_entries(ld, mp)) < 0) {
		ldap_perror(ld, "ldap_count_entries");
		ldap_msgfree(mp);
		ldap_value_free(rdns);
		return;
	}
	if (rc == 0) {
		printf("  %s is not a member of any groups in this portion of the Directory.\n", *rdns);
		ldap_msgfree(mp);
		ldap_value_free(rdns);
		return;
	}
	if (verbose)
		printf("  %s is a member of %d groups.\n\n", *rdns, rc);

	/*
	 *  print_list fills in the char * array starting at 1, not 0
	 */
	print_list(mp, work_area, &rc);
	for (i = 1; work_area[i] != NULL; i++)
		Free(work_area[i]);
	ldap_msgfree(mp);
	ldap_value_free(rdns);
	return;
}

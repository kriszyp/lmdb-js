/* $OpenLDAP$ */
/*
 * Copyright (c) 1991,1993  Regents of the University of Michigan.
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
#include <ac/string.h>
#include <ac/time.h>

#include <lber.h>
#include <ldap.h>
#include "ud.h"

static char *get_URL( void );
static int  check_URL( char *url );


void
modify( char *who )
{
	LDAPMessage *mp;	/* returned from find() */
	char *dn;		/* distinguished name */
	char **rdns;		/* for fiddling with the DN */
	char name[MED_BUF_SIZE];	/* entry to modify */
	int displayed_choices = 0;
	static char ans[SMALL_BUF_SIZE];	/* for holding user input */
#ifdef UOFM
	static char printed_warning = 0;	/* for use with the */
	struct attribute no_batch_update_attr;
	int ld_errno;
#endif
	int is_a_group;		/* TRUE if it is; FALSE otherwise */

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->modify(%s)\n", who);
#endif
	/*
	 *  Require them to bind first if the are modifying a group.
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
			printf("  group whose entry you want to modify: ");
		}
		else
			printf("  Modify whose entry? ");
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
	if (verbose)
		printf("\n  Modifying Directory entry of \"%s\"\n", *rdns);

#ifdef UOFM
	/*
	 *  If verbose mode is turned on and the user has not set a value
	 *  for noBatchUpdates, warn them that what they are about to do
	 *  may be overwritten automatically by that Stinkbug.
	 */
	no_batch_update_attr.quipu_name = "noBatchUpdates";
	(void) fetch_boolean_value(dn, no_batch_update_attr);

	ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);

	if (verbose && !printed_warning && (ld_errno == LDAP_NO_SUCH_ATTRIBUTE)) {
		printed_warning = 1;
		printf("\n  WARNING!\n");
		printf("  You are about to make a modification to an LDAP entry\n");
		printf("  that has its \"automatic updates\" field set to ON.\n");
		printf("  This means that the entry will be automatically updated\n");
		printf("  each month from official University sources like the\n");
		printf("  Personnel Office.  With \"automatic updates\" set to ON,\n");
		printf("  the following fields will be overwritten each month:\n");
		printf("         Title, home address and phone,\n");
		printf("         business address and phone\n");
		printf("  If you modify any of these fields, you may want to change\n");
		printf("  the \"automatic updates\" field to OFF so that your\n");
		printf("  changes will not be overwritten.  You may change this\n");
		printf("  setting by choosing \"u\" at the \"Modify what?\" prompt\n");
	}
#endif

	/*
	 *  Current values for user 'who' are being held in 'mp'. We
	 *  should parse up that buffer and fill in the Entry structure.
	 *  Once we're done with that, we can find out which fields the
	 *  user would like to modify.
	 */
	parse_answer(mp);
	is_a_group = isgroup();
	(void) ldap_msgfree(mp);
	printf("  You now need to specify what field you'd like to modify.\n");
	for (;;) {
		if ( verbose || !displayed_choices ) {
			printf("\n  Choices are:\n");
			printf("  -----------------------\n");
			print_mod_list(is_a_group);
			printf("\n  Pressing Return will cancel the process.\n");
			displayed_choices = 1;
		}
		printf("\n  Modify what? ");
		fflush(stdout);
		fetch_buffer(ans, sizeof(ans), stdin);
		if (ans[0] == '\0')
			break;
		perform_action(ans, dn, is_a_group);
		if ((mp = find(*rdns, TRUE)) == NULL)
			break;
		parse_answer(mp);
		(void) ldap_msgfree(mp);
	}
	ldap_memfree(dn);
	ldap_value_free(rdns);
	return;
}

/* generic routine for changing any field */
void
change_field(
    char *who,			/* DN of entry we are changing */
    int attr_idx		/* attribute to change */
)
{
	struct attribute attr = Entry.attrs[attr_to_index(attrlist[attr_idx].quipu_name)];

#define	IS_MOD(x)	(!strncasecmp(resp, (x), strlen(resp)))
				
	static char buf[MED_BUF_SIZE];	/* for printing things */
	static char resp[SMALL_BUF_SIZE];	/* for user input */
	char *prompt, *prompt2, *more;
	register int i;				/* for looping thru values */
	static LDAPMod mod;
	static LDAPMod *mods[2] = { &mod };	/* passed to ldap_modify */
	static char *values[MAX_VALUES];	/* passed to ldap_modify */

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->change_field(%x, %s)\n", attr, who);
#endif
	/*
	 *  If there is no current value associated with the attribute,
	 *  then this is the easy case.  Collect one (or more) attributes
	 *  from the user, and then call ldap_modify_s() to write the changes
	 *  to the LDAP server.
	 */
	for (i = 0; i < MAX_VALUES; i++)
		values[i] = NULL;
	if (attr.values == (char **) NULL) {
		printf("\n  No current \"%s\"\n", attr.output_string);
		values[0] = get_value(attr.quipu_name, "Enter a value");
		if ( values[0] == NULL )
			return;
		mod.mod_op = LDAP_MOD_REPLACE;
		mod.mod_type = attr.quipu_name;
		mod.mod_values = values;
		for (i = 1; i < MAX_VALUES; i++) {
			printf("  Do you wish to add an additional value? ");
			fflush(stdout);
			fetch_buffer(resp, sizeof(resp), stdin);
			if ((resp[0] == 'y') || (resp[0] == 'Y'))
				values[i] = get_value(attr.quipu_name, "Enter an additional value");
			else
				break;
		}
#ifdef DEBUG
		if (debug & D_MODIFY) {
			printf("  ld = 0x%x\n", ld);
			printf("  who = [%s]\n", who);
			printf("  mods[0]->mod_op = %1d\n", mods[0]->mod_op);
			printf("  mods[0]->mod_type = %s\n", mods[0]->mod_type);
			for (i = 0; mods[0]->mod_values[i] != NULL; i++)
				printf("  mods[0]->mod_values[%1d] = %s\n", i, mods[0]->mod_values[i]);
		}
#endif
		if (ldap_modify_s(ld, who, mods)) {
			mod_perror(ld);
			return;
		}
		else if (verbose)
			printf("  Modification of '%s' complete.\n", attr.output_string);
		ldap_uncache_entry( ld, who );
		for (i--; i > 0; i--)
			(void) Free(values[i]);
	}
	/*
	 *  There are values for this attribute already.  In this case,
	 *  we want to allow the user to delete all existing values,
	 *  add additional values to the ones there already, or just
	 *  delete some of the values already present.  DIXIE does not
	 *  handle modifications where the attribute occurs on the LHS
	 *  more than once.  So to delete entries and add entries, we
	 *  need to call ldap_modify() twice.
	 */
	else {
		/*
		 *  If the attribute holds values which are DNs, print them
		 *  in a most pleasant way.
		 */
		sprintf(buf, "%s:  ", attr.output_string);
		if (!strcmp(attr.quipu_name, "owner"))
			(void) print_DN(attr);
		else
			(void) print_values(attr);

		if (verbose) {
			printf("  You may now:\n");
			printf("    Add additional values to the existing ones, OR\n");
			printf("    Clear all values listed above, OR\n");
			printf("    Delete one of the values listed above, OR\n");
			printf("    Replace all of the values above with new ones.\n");
		}
		printf("\n  Add, Clear, Delete, or Replace? ");
		fflush(stdout);
		fetch_buffer(resp, sizeof(resp), stdin);

		/*
		 *  Bail if they just hit the RETURN key.
		 */
		if (resp[0] == '\0') {
			if (verbose)
				printf("\n  No changes made.\n");
			return;
		}

		/*
		 *  If the want to clear the values, just do it.
		 */
		mod.mod_type = attr.quipu_name;
		mod.mod_values = values;
		if (IS_MOD("clear")) {
			mod.mod_op = LDAP_MOD_DELETE;
			mod.mod_values = NULL;
			if ( verbose && !confirm_action( "All existing values will be removed." )) {
				printf("  Modification halted.\n");
				return;
			}
#ifdef DEBUG
			if (debug & D_MODIFY) {
				printf("Clearing attribute '%s'\n", attr.quipu_name);
				printf("who = [%s]\n", who);
				printf("mod = [%d] [%s] [%x]\n", mod.mod_op,
					mod.mod_type, mod.mod_values);
			}
#endif
			if (ldap_modify_s(ld, who, mods)) {
				mod_perror(ld);
				return;
			}
			else if (verbose)
				printf("  '%s' has been cleared.\n", attr.output_string);
			ldap_uncache_entry( ld,  who );
			return;
		}

		if (IS_MOD("add")) {
			prompt = "Enter the value you wish to add";
			more = "  Add an additional value? ";
			prompt2 = "Enter another value you wish to add";
			mod.mod_op = LDAP_MOD_ADD;
		}
		else if (IS_MOD("delete")) {
			prompt = "Enter the value you wish to delete";
			more = "  Delete an additional value? ";
			prompt2 = "Enter another value you wish to delete";
			mod.mod_op = LDAP_MOD_DELETE;
		}
		else if (IS_MOD("replace")) {
			prompt = "Enter the new value";
			more = "  Add an additional value? ";
			prompt2 = "Enter another value you wish to add";
			mod.mod_op = LDAP_MOD_REPLACE;
			if ( verbose && !confirm_action( "All existing values will be overwritten with the new values you are about to enter." )) {
				printf("  Modification halted.\n");
				return;
			}

		}
		else {
			printf("  No changes made.\n");
			return;
		}

		values[0] = get_value(attr.quipu_name, prompt);
		for (i = 1; i < MAX_VALUES; i++) {
			printf(more);
			fflush(stdout);
			fetch_buffer(resp, sizeof(resp), stdin);
			if ((resp[0] == 'y') || (resp[0] == 'Y'))
				values[i] = get_value(attr.quipu_name, prompt2);
			else
				break;
		}

		/* if the first value in the value-array is NULL, bail */
		if (values[0] == NULL) {
			if (verbose)
				printf("  No modification made.\n");
			return;
		}
#ifdef DEBUG
		if (debug & D_MODIFY) {
			printf("  ld = 0x%x\n", ld);
			printf("  who = [%s]\n", who);
			printf("  mods[0]->mod_op = %1d\n", mods[0]->mod_op);
			printf("  mods[0]->mod_type = %s\n", mods[0]->mod_type);
			for (i = 0; mods[0]->mod_values[i] != NULL; i++)
				printf("  mods[0]->mod_values[%1d] = %s\n", i, mods[0]->mod_values[i]);
		}
#endif
		if (ldap_modify_s(ld, who, mods)) {
			mod_perror(ld);
			return;
		}
		else if (verbose)
			printf("  Modifications to '%s' complete.\n", attr.output_string);
		ldap_uncache_entry( ld, who );
		for (i--; i > 0; i--)
			(void) Free(values[i]);
	}
	return;
}

/*
 *  These are used to size the buffers we use when collecting values that
 *  can cross more than one line.
 */
#define LINE_SIZE       80
#define MAX_LINES	 6
#define MAX_DESC_LINES  24
#define INTL_ADDR_LIMIT	30

char *
get_value( char *id, char *prompt )
{
	char *cp;		/* for the Malloc() */
	int count;		/* line # of new value -- if multiline */
	int multiline = 0;	/* 1 if this value is multiline */
	static char line[LINE_SIZE];	/* raw line from user */
	static char buffer[MAX_DESC_LINES * (LINE_SIZE+2)]; /* holds ALL of the
							   lines we get */
#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->get_value(%s, %s)\n", id, prompt);
#endif
	/* if this is a URL, have another routine handle this */
	if (!strcmp(id, "labeledURL"))
		return(get_URL());

	/*
	 *  To start with, we have one line of input from the user.
	 *
	 *  Addresses and multiline description can span multiple lines.
	 *  Other attributes may not.
	 */
	count = 1;
	(void) memset(buffer, 0, sizeof(buffer));
#ifdef UOFM
	if (!strcmp(id, "postalAddress") || !strcmp(id, "homePostalAddress") || !strcmp(id, "multiLineDescription") || !strcmp(id, "vacationMessage")) 
#else
	if (!strcmp(id, "postalAddress") || !strcmp(id, "homePostalAddress"))
#endif
		multiline = 1;
	printf("\n  %s:\n", prompt);

	/* fetch lines */
	for (;;) {
		if (multiline)
			printf(" %1d: ", count);
		else
			printf("  > ");
		fflush(stdout);
		fetch_buffer(line, sizeof(line), stdin);

		if (line[0] == '\0')
			break;
#ifdef UOFM
		/*
		 *  Screen out dangerous e-mail addresses of the form:
		 *
		 *		user@umich.edu
		 *
		 * and addresses that have no '@' symbol at all.
		 */
		if (!strcmp(id, "mail")) {
			int i;
			char *tmp, *tmp2;

			/* if this is a group, don't worry */
			if (isgroup())
				goto mail_is_good;

			/* if this address is not @umich.edu, don't worry */
			/* ...unless there is no '@' at all! */
			tmp = strdup(line);
			if ((tmp2 = strrchr(tmp, '@')) == NULL) {
			printf("\n");
			format("The address you entered is not a valid e-mail address.  E-mail addresses should be of the form \"local@domain\", e.g. bjensen@b.imap.itd.umich.edu", 75, 2 );
				goto mail_is_bad;
			}
			
			*tmp2 = '\0';
			tmp2++;
			if (strcasecmp(tmp2, "umich.edu"))
				goto mail_is_good;

			/* if not of the form uid@umich.edu, don't worry */
			if ((i = attr_to_index("uid")) < 0)
				goto mail_is_good;
			if (strcasecmp(tmp, *(Entry.attrs[i].values)))
				goto mail_is_good;
			printf("\n");
			format("An e-mail address of the form uniqname@umich.edu is not the form that you want registered in the Directory.  This form is the one to use on business cards, for example, but the Directory should contain your real e-mail address; that is, the address where you really read your mail.", 75, 2);

mail_is_bad:
			printf("\n");
			printf("  Please enter a legal e-mail address (or press RETURN to stop)\n");
			continue;
		}
mail_is_good:
#endif

		/*
		 *  If the attribute which we are gathering is a "owner"
		 *  then we should lookup the name.  The user is going to
		 *  either have to change the search base before doing the
		 *  modify, or the person is going to have to be within the
		 *  scope of the current search base, or they will need to
		 *  type in a UFN.
		 */
		if (!strcmp(id, "owner")) {
			LDAPMessage *lmp, *elmp;
			char *tmp;
			
			lmp = find(line, FALSE);
			if (lmp == (LDAPMessage *) NULL) {
				printf("  Could not find \"%s\" in the Directory\n", line);
				if (verbose) 
					format("Owners of groups must be valid entries in the LDAP Directory.  The name you have typed above could not be found in the LDAP Directory.", 72, 2);
				return(NULL);
			}
			elmp = ldap_first_entry(ld, lmp);
			if (lmp == (LDAPMessage *) NULL) {
				ldap_perror(ld, "ldap_first_entry");
				return(NULL);
			}
			tmp = ldap_get_dn(ld, elmp);
			strcpy(buffer, tmp);
			ldap_memfree(tmp);
			(void) ldap_msgfree(lmp);
			break;
		}

		if (!strcmp(id, "postalAddress") || !strcmp(id, "homePostalAddress")) {
			if (strlen(line) > INTL_ADDR_LIMIT) {
				printf("  The international standard for addresses only allows for 30-character lines\n");
				printf("  Please re-enter your last line.\n");
				continue;
			}
		}

		/*
		 *  Separate lines of multiline attribute values with
		 *  dollar signs.  Copy this line into the buffer we
		 *  use to collect up all of the user-supplied input
		 *  lines.  If this is not a multiline attribute, we
		 *  are done.
		 */
		if (count++ > 1)
			(void) strcat(buffer, " $ ");
		(void) strcat(buffer, line);
		if (!multiline)
			break;
		if ((count > MAX_LINES) && (!strcmp(id, "postalAddress") || !strcmp(id, "homePostalAddress"))) {
			printf("  The international standard for addresses only allows for six lines\n");
			break;
		}
#ifdef UOFM
		if ((count > MAX_DESC_LINES) && !strcmp(id, "multiLineDescription")) {
			printf("  We only allow %d lines of description\n", MAX_DESC_LINES);
			break;
		}
#endif
	}
	if (buffer[0] == '\0')
		return(NULL);
#ifdef DEBUG
	if (debug & D_MODIFY)
		printf("  Value is [%s]\n", buffer);
#endif
	cp = (char *) Malloc((unsigned) (strlen(buffer) + 1));
	strcpy(cp, buffer);
	return(cp);
}

void
set_boolean(
	char *who,		/* DN of entry we are changing */
	int attr_idx		/* boolean attribute to change */
)
{
	struct attribute attr = Entry.attrs[attr_to_index(attrlist[attr_idx].quipu_name)];

	char *cp, *s;
	static char response[16];
	static char *newsetting[2] = { NULL, NULL };
	LDAPMod mod, *mods[2];

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->set_boolean(%s, %s)\n", who, attr.quipu_name);
#endif
	mods[0] = &mod;
	mods[1] = (LDAPMod *) NULL;
	mod.mod_op = LDAP_MOD_REPLACE;
	mod.mod_type = attr.quipu_name;
	mod.mod_values = newsetting;

	/* fetch the current setting */
	if ((cp = fetch_boolean_value(who, attr)) == NULL)
		return;
	if (!strcmp(cp, "TRUE"))
		newsetting[0] = "FALSE";
	else if (!strcmp(cp, "FALSE"))
		newsetting[0] = "TRUE";
	else {
		printf("  This field needs to be set to either TRUE or to FALSE.\n");
		printf("  \"%s\" is not a legal value.  Please set this field to either TRUE or to FALSE.\n", cp);
		newsetting[0] = "FALSE";
	}

	/* see if they want to change it */
	printf("\n");
	printf("  The current value of this field is %s.\n", cp);
	printf("  Should I change the value of this field to %s?\n", 
							newsetting[0]);
	printf("  Please enter Y for yes, N for no, or RETURN to cancel:  ");
	fflush(stdout);
	(void) fetch_buffer(response, sizeof(response), stdin);
	for (s = response; isspace((unsigned char)*s); s++)
			;
	if ((*s == 'y') || (*s == 'Y')) {
		if (ldap_modify_s(ld, who, mods)) {
			mod_perror(ld);
			return;
		}
		else if (verbose)
			printf("  Setting has been changed\n");
		ldap_uncache_entry(ld, who);
		return;
	}
	if (verbose)
		printf("  Setting has not been changed\n");
}

#ifdef UOFM

void
set_updates( char *who, int dummy )
{
	char *cp, *s;
	static char response[16];
	static char value[6];
	static char *newsetting[2] = { value, NULL };
	LDAPMod mod, *mods[2];
	struct attribute attr;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->set_updates(%s)\n", who);
#endif
	mods[0] = &mod;
	mods[1] = (LDAPMod *) NULL;
	mod.mod_op = LDAP_MOD_REPLACE;
	mod.mod_type = "noBatchUpdates";
	mod.mod_values = newsetting;
	/* explain what the implications are */
	if (verbose) {
		printf("\n  By default, updates that are received from the Personnel\n");
		printf("  Office and the Office of the Registrar are applied to all\n");
		printf("  entries in the LDAP database each month.  Sometimes this\n");
		printf("  feature is undesirable.  For example, if you maintain your\n");
		printf("  entry in the LDAP database manually, you may not want to\n");
		printf("  have these updates applied to your entry, possibly overwriting\n");
		printf("  correct information with out-dated information.\n\n");
	}

	/* fetch the current setting */
	attr.quipu_name = "noBatchUpdates";
	if ((cp = fetch_boolean_value(who, attr)) == NULL)
		return;
	if (!strcmp(cp, "TRUE"))
		printf("  Automatic updates are currently turned OFF\n");
	else if (!strcmp(cp, "FALSE"))
		printf("  Automatic updates are currently turned ON\n");
	else {
		fprintf(stderr, "  Unknown update flag -> [%s]\n", cp);
		return;
	}

	/* see if they want to change it */
	printf("\n  Change this setting [no]? ");
	fflush(stdout);
	(void) fetch_buffer(response, sizeof(response), stdin);
	for (s = response; isspace((unsigned char)*s); s++)
			;
	if ((*s == 'y') || (*s == 'Y')) {
		if (!strcmp(cp, "TRUE"))
			strcpy(value, "FALSE");
		else
			strcpy(value, "TRUE");
		if (ldap_modify_s(ld, who, mods)) {
			mod_perror(ld);
			return;
		}
		else if (verbose)
			printf("  Setting has been changed\n");
		ldap_uncache_entry( ld, who );
		return;
	}
	if (verbose)
		printf("  Setting has not been changed\n");
}

#endif

void
print_mod_list( int group )
{
	register int i, j = 1;

	if (group == TRUE) {
	    for (i = 0; attrlist[i].quipu_name != NULL; i++) {
		if (attrlist[i].flags & ATTR_FLAG_GROUP_MOD) {
			printf("  %2d ->  %s\n", j, attrlist[i].output_string);
			j++;
		}
	    }
	} else {
	    for (i = 0; attrlist[i].quipu_name != NULL; i++) {
		if (attrlist[i].flags & ATTR_FLAG_PERSON_MOD) {
			printf("  %2d ->  %s\n", j, attrlist[i].output_string);
			j++;
		}
	    }
	}
	printf("   ? ->  Print this list\n\n");
	printf("  Press the RETURN key without typing a number to quit.\n");
#ifdef UOFM
	if (group == FALSE)
		printf("  To add nicknames, send mail to x500-nicknames@umich.edu\n");
#endif
}
			
int
perform_action( char *choice, char *dn, int group )
{
	int selection;
	register int i, j = 1;

	selection = atoi(choice);
	if (selection < 1) {
		printf("\n  Choices are:\n");
		printf("  -----------------------\n");
		print_mod_list(group);
		return(1);
		/* NOTREACHED */
	}

	if (group == TRUE) {
	    for (i = 0; attrlist[i].quipu_name != NULL; i++) {
		if (attrlist[i].flags & ATTR_FLAG_GROUP_MOD) {
			if (j == selection)
				break;
			j++;
		}
	    }
	} else {
	    for (i = 0; attrlist[i].quipu_name != NULL; i++) {
		if (attrlist[i].flags & ATTR_FLAG_PERSON_MOD) {
			if (j == selection)
				break;
			j++;
		}
	    }
	}

	if (attrlist[i].quipu_name == NULL) {
		printf("\n  Choices are:\n");
		printf("  -----------------------\n");
		print_mod_list(group);
		return(1);
		/* NOTREACHED */
	}
	(*attrlist[i].mod_func)(dn, i);
	return(0);
}

static char *
get_URL( void )
{
	char *rvalue, label[MED_BUF_SIZE], url[MED_BUF_SIZE];

	if (verbose) {
		printf("  First, enter the URL.  (Example: http://www.us.itd.umich.edu/users/).\n");
		printf("  The URL may be up to %d characters long.\n", MED_BUF_SIZE);
	}
	for (;;) {
		printf("  URL: ");
		fflush(stdout);
		(void) fetch_buffer(url, sizeof(url), stdin);
		if (*url == '\0')
			continue;
		if (check_URL(url) == 0)
			break;
		printf("  A URL may not have any spaces or tabs in it.  Please re-enter your URL.\n\n");
	}
	if (verbose)
		printf("\n  Now please enter a descriptive label for this URL\n");
	do {
		printf("  Label: ");
		fflush(stdout);
		(void) fetch_buffer(label, sizeof(label), stdin);
	} while (label[0] == '\0');
	rvalue = (char *) Malloc((unsigned) (strlen(url) + 2 + strlen(label)));
	sprintf(rvalue, "%s %s", url, label);
	return((char *) rvalue);
}

static int
check_URL( char *url )
{
	register char *cp;

	for (cp = url; *cp != '\n' && *cp != '\0'; cp++) {
		if (isspace((unsigned char)*cp))
			return(-1);
			/*NOTREACHED*/
	}
	*cp = '\0';
	return(0);
}


void
mod_perror( LDAP *ld )
{
	int ld_errno = 0;

	if(ld != NULL) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
	}

	if (( ld == NULL ) || ( ld_errno != LDAP_UNAVAILABLE &&
	    ld_errno != LDAP_UNWILLING_TO_PERFORM ))
	{
		ldap_perror( ld, "modify" );
		return;
	}

	fprintf( stderr, "\n  modify: failed because part of the online directory is not able\n" );
	fprintf( stderr, "  to be modified right now" );
	if ( ld_errno == LDAP_UNAVAILABLE ) {
		fprintf( stderr, " or is temporarily unavailable" );
	}
	fprintf( stderr, ".\n  Please try again later.\n" );
}

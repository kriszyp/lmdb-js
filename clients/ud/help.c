/* $OpenLDAP$ */
/*
 * Copyright (c) 1992, 1993  Regents of the University of Michigan.
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

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>

#include <lber.h>
#include <ldap.h>

#include "ud.h"


void
print_help( char *s )
{
	int len;			/* command length */

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->print_help(%s)\n", s);
#endif
	if (s == NULL)
		len = 0;
	else {
		len = strlen(s);
		if (!strcasecmp(s, "commands"))
			len = 0;
	}

	/* print general help, or just on topic 's' if provided */
	if (len == 0) {
		printf("\n  Here are brief descriptions of available commands:\n\n");
		printf("  ?                    To print this list.\n");
		printf("  bind [who]           To bind (authenticate) to the directory.\n");
		printf("  cb [where]           To change the search base.\n");
		printf("  change [entry]       To change information associated with an entry.\n");
		printf("  create [group]       To create a new group entry.\n");
		printf("  dereference          To toggle dereferencing of aliases.\n");
#ifdef UOFM
		if (isatty( 1 )) {
#endif
			printf("  vedit [entry]        To edit a complete Directory entry using your editor.\n");
#ifdef UOFM
		}
#endif
		printf("  find [entry]         To find an entry in the directory.\n");

		printf("  groupbase [where]    To change the group base.\n");
		printf("  help [command]       To display detailed help for a particular command.\n");
		printf("  join [group]         To subscribe to a group.\n");
		printf("  list [who]           To list the groups owned by someone.\n");
		printf("  memberships [who]    To list out the groups in which someone is a member.\n");
		printf("  purge [group]        To remove obsolete entries from a group.\n");
		printf("  quit                 To terminate the program.\n");
		printf("  remove [group]       To remove a group entry.\n");
		printf("  resign [group]       To unsubscribe from a group.\n");
		printf("  status               To display directory connection status.\n");
		printf("  tidy                 To unsubscribe from groups that no longer exist.\n");
		printf("  verbose              To toggle the verbose switch.\n");

		printf("\n  Type \"help <command-name>\" to get help about a particular command.");
		printf("\n  Type \"help options\" to get help about options in brackets above.\n");
#ifdef UOFM
		printf("\n  Bugs in ud should be reported via e-mail to:  OpenLDAP-its@OpenLDAP.org\n" );
		printf("\n  For more assistance with ud, contact the ITD Consultants by phoning\n" );
		printf("      764-HELP or by sending e-mail to:  consulting.help@umich.edu\n" );
#endif /* UOFM */
	}
	else if (!strncasecmp("options", s, len)) {
		printf("\n");
		format("Most commands need additional information in order to work.  For example, the 'remove' command needs to know the name of the group to remove.  This can be specified along with the 'remove' command, or the program will prompt you for the information.", 75, 2);
		printf("\n");
		printf("  [entry]      An entry needs to be specified.  This may be a person or a\n");
		format("group.  The name can be specified as either a ordinary name (e.g., 'Jane Doe'), or as some other identifying characteristic (e.g., 'uid=babs').", 75, 15);
		printf("\n");
		printf("  [group]      A group in the Directory needs to be specified.  This name\n");
		format("should be specified as a ordinary name (e.g., 'Friends of maX500').", 75, 15);
		printf("\n");
		printf("  [where]      A place in the Directory needs to be specified.  This name\n");
		format("should be specified as an LDAP-style name (e.g., 'ou=people, o=University of Michigan, c=United States of America').  In most cases, it is easier to omit the [where] and allow the program to guide you.", 75, 15);
		printf("\n");
		printf("  [who]        A person in the Directory needs to be specified.  This name\n");
		format("can be specified as either a ordinary name (e.g., 'Jane Doe'), or as some other identifying characteristic (e.g., 'uid=babs').", 75, 15);
	}
	else if (!strncasecmp("list", s, len)) {
		printf("  list [who]\n\n");
		format("Prints out the list of groups owned by the person specified.", 75, 2);
	}
	else if (!strncasecmp("memberships", s, len)) {
		printf("  memberships [who]\n\n");
		format("Prints out the list of groups in which the person specified is a member.", 75, 2);
	}
	else if (!strncasecmp("vedit", s, len)) {
		printf("  vedit [entry]\n\n");
		format("Looks up the specified person in the Directory, and then writes this entry into a file.  It then uses the EDITOR environment variable to select an editor, and then loads this file into the editor.  The entry can now be modified in any way desired, and when the editor is exited, the entry will be written back into the Directory.", 75, 2);
	}
	else if (!strncasecmp("status", s, len)) {
		printf("  status\n\n");
		format("Prints out the current connection status.  Lists the name of the current LDAP server, the current search base, the current group base, and the identity to which you are bound.  If you have not bound as anyone then ud considers you bound as Nobody.  cd is an alias for cb.", 75, 2);
	}
	else if (!strncasecmp("groupbase", s, len)) {
		printf("  groupbase [where]\n\n");
		format("The syntax and use of this command is identical to the more commonly used 'cb' command.  This command sets the base which is used to create groups in the LDAP Directory.  Setting the base to a certain value does not necessarily grant the person write-access to that part of the Directory in order to successfully create a group.", 75, 2);
	}
	else if (!strncasecmp("cd", s, len) || !strncasecmp("cb", s,len)) {
		printf("  cb [where]\n");
		printf("  cd [where]\n\n");
		format("The cb command changes the search base.  By default, this program looks only in the local part of the Directory.  By using the cb command, you can search other parts of the Directory.", 75, 2);
	printf("\n  Examples:\n");
	printf("\n            * cb ..\n\n");
	format("changes the search base so that it is one level higher in the Directory.  Note that if you perform several of these in a row you will move to the root of the Directory tree.", 75, 2);
	printf("\n            * cb ?\n\n");
	format("prints out a list of the possible areas to search below the current search base.  This is useful once you have moved high in the tree and wish to snoop about.", 75, 2);
	printf("\n            * cb default\n\n");
	format("sets the search base to its original default value.", 75, 2);
	printf("\n            * cb o=Merit Computer Network, c=US\n\n");
	format("sets the search base to organization given, the Merit Computer Network in this case.  This comamnd checks the validity of the specified search base, and rejects it if it is not a valid Distinguished Name (DN).  A DN uniquely identifies a portion of the global LDAP namespace.", 75, 2);
	}
	else if (!strncasecmp("quit", s, len) || !strncasecmp("stop",s, len)) {
		printf("  quit\n");
		printf("  stop\n\n");
		printf("  Quits the program.  'stop' is an alias for 'quit'.\n");
	}
	else if (!strncasecmp("find", s, len) || !strncasecmp("display", s, len) || !strncasecmp("show", s, len)) {
		printf("  find [entry]\n");
		printf("  show [entry]\n");
		printf("  display [entry]\n\n");
		format("Displays information about the person specified.  If the name specified matches more than one person, one will be presented a list from which to make a choice.  'show' and 'display' are aliases for 'find.'", 75, 2);
	}
	else if (!strncasecmp("bind", s, len)) {
		printf("  bind [who]\n\n");
		format("Binds (authenticates) to the Directory.  It is generally necessary to bind to the Directory in order to look at privileged entries or to modify an entry.   Allows one to authenticate prior to issuing a 'change' or 'modify' command.  Most often used by administrators to bind to an identity.", 75, 2);
	}
	else if (!strncasecmp("modify", s, len) || !strncasecmp("change", s, len)) {
		printf("  modify [entry]\n");
		printf("  change [entry]\n\n");
		format("Changes information associated with an entry in the LDAP Directory.  'change' is an alias for 'modify'.", 75, 2);
	}
	else if (!strncasecmp("verbose", s, len)) {
		printf("  verbose\n\n");
		format("Turns on long and windy messages which might be useful to new users of this program.  If verbose mode is already on, this turns it off.", 75, 2);
	}
	else if (!strncasecmp("dereference", s, len)) {
		printf("  dereference\n\n");
		format("Turns off following of aliases when searching, etc.  If alias dereferencing has already been turned off, this turns it back on.", 75, 2);
	}
	else if (!strncasecmp("create", s, len)) {
		printf("  create [group]\n\n");
		format("Creates a new group in the Directory.", 75, 2);
	}
	else if (!strncasecmp("join", s, len) || !strncasecmp("subscribe", s, len)) {
		printf("  join [group]\n");
		printf("  subscribe [group]\n\n");
		format("Adds the person as a subscriber to the specified group.", 75, 2);
	}
	else if (!strncasecmp("purge", s, len)) {
		printf("  purge [group]\n\n");
		format("Goes through the specified group looking for Distinguished Names that cannot be found.  As it finds each one, it gives the person an opportunity to delete it.", 75, 2);
	}
	else if (!strncasecmp("resign", s, len) || !strncasecmp("unsubscribe", s, len)) {
		printf("  resign [group]\n");
		printf("  unsubscribe [group]\n\n");
		format("Deletes the person from the specified group.", 75, 2);
	}
	else if (!strncasecmp("remove", s, len)) {
		printf("  remove [group]\n\n");
		format("Removes a group from the Directory.", 75, 2);
	}
	else if (!strncasecmp("help", s, len)) {
		format("Prints out a brief description of each command.", 75, 2);
	}
	else if (!strncasecmp("tidy", s, len)) {
		printf("  tidy\n\n");
		format("Unsubscribes you from non-existent groups.  Useful when you cannot resign from a group because, while your LDAP entry still contains a pointer to it, someone has removed a group of which you were a subscriber.", 75, 2);
	}
	else if (*s == '?') {
		format("Prints out a brief description of each command.  Same as typing 'help help'.", 75, 2);
	}
	else {
		printf("  Don't recognize <%s>\n", s);
	}
}

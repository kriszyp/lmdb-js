/* $OpenLDAP$ */
/*
 * Copyright (c) 1992, 1993, 1994  Regents of the University of Michigan.
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
#include <ac/time.h>		/* ldap.h needs time_t */
#include <ldap.h>
#include "ud.h"

struct attribute attrlist[] = {

	/* 
	 *  Field 1 = Quipu name
	 *  Field 2 = String used when printing the field
	 *  Field 3 = function used to modify this field (if any)
	 *  Field 4 = Flags specifying how this field is displayed
	 */
	{ "memberOfGroup", "Subscriptions", 0, ATTR_FLAG_PERSON | ATTR_FLAG_READ | ATTR_FLAG_IS_A_DN },
	{ "acl", "Access Control", 0, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ },
	{ "cn", "Aliases", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_SEARCH | ATTR_FLAG_GROUP_MOD },
	{ "title", "Title", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_READ | ATTR_FLAG_SEARCH | ATTR_FLAG_PERSON_MOD },
	{ "postalAddress", "Business address", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_GROUP_MOD | ATTR_FLAG_IS_MULTILINE },
	{ "telephoneNumber", "Business phone", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_GROUP_MOD },
	{ "mail", "E-mail address", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_SEARCH | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_MAY_EDIT },
	{ "member", "Members", mod_addrDN, ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_IS_A_DN | ATTR_FLAG_GROUP_MOD },
	{ "homePhone", "Home phone", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_READ  | ATTR_FLAG_PERSON_MOD },
	{ "homePostalAddress", "Home address", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_READ  | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_IS_MULTILINE },
	{ "objectClass", "Object class", 0, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_SEARCH },
#ifdef UOFM
	{ "multiLineDescription", "Description", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ  | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_GROUP_MOD | ATTR_FLAG_IS_MULTILINE },
#endif
#ifdef HAVE_KERBEROS
	{ "krbName", "Kerberos name", 0, ATTR_FLAG_PERSON | ATTR_FLAG_READ },
#endif
	{ "description", "Brief description", 0, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ },
	{ "facsimileTelephoneNumber", "Fax number", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ  | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_GROUP_MOD },
	{ "pager", "Pager number", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_READ  | ATTR_FLAG_PERSON_MOD },
	{ "uid", "Uniqname", 0, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ },
	{ "userPassword", "Password", 0, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ },
#ifdef UOFM
	{ "noBatchUpdates", "No batch updates", set_updates, ATTR_FLAG_PERSON | ATTR_FLAG_READ | ATTR_FLAG_PERSON_MOD },
#endif
	{ "joinable", "Joinable flag", set_boolean, ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_GROUP_MOD },
	{ "associatedDomain", "Associated domain", change_field, ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_GROUP_MOD },
	{ "owner", "Owner", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_IS_A_DN | ATTR_FLAG_GROUP_MOD },
	{ "rfc822ErrorsTo", "Errors to", change_field, ATTR_FLAG_GROUP | ATTR_FLAG_READ },
	{ "ErrorsTo", "Errors to", mod_addrDN, ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_IS_A_DN | ATTR_FLAG_GROUP_MOD },
	{ "rfc822RequestsTo", "Requests to", change_field, ATTR_FLAG_GROUP | ATTR_FLAG_READ },
	{ "RequestsTo", "Requests to", mod_addrDN, ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_IS_A_DN | ATTR_FLAG_GROUP_MOD },
	{ "moderator", "Moderated by", change_field, ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_GROUP_MOD },
	{ "labeledURL", "More Info (URL)", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_GROUP | ATTR_FLAG_READ | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_GROUP_MOD | ATTR_FLAG_IS_A_URL },
	{ "onVacation", "On Vacation", set_boolean, ATTR_FLAG_PERSON | ATTR_FLAG_READ | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_IS_A_BOOL },
	{ "vacationMessage", "Vacation Message", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_READ  | ATTR_FLAG_PERSON_MOD | ATTR_FLAG_IS_MULTILINE },
	{ "drink", "Favorite Beverage", change_field, ATTR_FLAG_PERSON | ATTR_FLAG_READ | ATTR_FLAG_PERSON_MOD },
	{ "lastModifiedBy", "Last modified by", 0, ATTR_FLAG_GROUP | ATTR_FLAG_PERSON | ATTR_FLAG_IS_A_DN | ATTR_FLAG_READ },
	{ "lastModifiedTime", "Last modified at", 0, ATTR_FLAG_GROUP | ATTR_FLAG_PERSON | ATTR_FLAG_READ | ATTR_FLAG_IS_A_DATE },
	{ NULL, NULL, 0, ATTR_FLAG_NONE }
};

/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.  A copy of this license is available at
 * http://www.OpenLDAP.org/license.html or in file LICENSE in the
 * top-level directory of the distribution.
 */
/* Portions
 * Copyright (c) 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

/*
 * This file controls defaults for OpenLDAP package.
 * You probably do not need to edit the defaults provided by this file.
 */

#ifndef _LDAP_DEFAULTS_H
#define _LDAP_DEFAULTS_H


#include <ldap_config.h>

#define LDAP_CONF_FILE	 LDAP_SYSCONFDIR LDAP_DIRSEP "ldap.conf"
#define LDAP_USERRC_FILE "ldaprc"
#define LDAP_ENV_PREFIX "LDAP"

/* default ldapi:// socket */
#define LDAPI_SOCK LDAP_RUNDIR LDAP_DIRSEP "ldapi"

/*
 * SHARED DEFINITIONS - other things you can change
 */
	/* default attribute to use when sorting entries, NULL => sort by DN */
#define SORT_ATTR	NULL
	/* default count of DN components to show in entry displays */
#define DEFAULT_RDNCOUNT	2
	/* default config file locations */
#define FILTERFILE	LDAP_SYSCONFDIR LDAP_DIRSEP "ldapfilter.conf"

/*
 * FINGER DEFINITIONS
 */
	/* banner to print */
#define FINGER_BANNER		"OpenLDAP Finger Service...\r\n"
	/* who to report errors to */
#define FINGER_ERRORS		"System Administrator"
	/* what to say if no matches are found */
#define FINGER_NOMATCH		"Search failed to find anything.\r\n"
	/* what to say if the service may be unavailable */
#define FINGER_UNAVAILABLE	\
"The directory service may be temporarily unavailable.\r\n\
Please try again later.\r\n"
	/* printed if a match has no email address - for disptmp default */
#define FINGER_NOEMAIL1	"None registered in this service."
#define FINGER_NOEMAIL2	NULL
#define FINGER_NOEMAIL	{ FINGER_NOEMAIL1, FINGER_NOEMAIL2, NULL }
	/* maximum number of matches returned */
#define FINGER_SIZELIMIT	50
	/* max number of hits displayed in full before a list is presented */
#define FINGER_LISTLIMIT	1
	/* what to exec for "finger @host" */
#define FINGER_CMD		LDAP_FINGER
	/* how to treat aliases when searching */
#define FINGER_DEREF		LDAP_DEREF_FINDING
	/* attribute to use when sorting results */
#define FINGER_SORT_ATTR	SORT_ATTR
#ifdef LDAP_UFN
	/* enable ufn support */
#define FINGER_UFN
#endif
	/* timeout for searches */
#define FINGER_TIMEOUT		60
	/* number of DN components to show in entry displays */
#define FINGER_RDNCOUNT		DEFAULT_RDNCOUNT

/*
 * MAIL500 MAILER DEFINITIONS
 */
	/* max number of ambiguous matches reported */
#define MAIL500_MAXAMBIGUOUS	10
	/* max subscribers allowed (size limit when searching for them ) */
#define MAIL500_MAXGROUPMEMBERS	LDAP_NO_LIMIT
	/* timeout for all searches */
#define MAIL500_TIMEOUT		180
	/* sendmail location - mail500 needs to exec this */
#define MAIL500_SENDMAIL	LDAP_SENDMAIL

/*
 * UD DEFINITIONS
 */
	/* ud configuration file */
#define UD_CONFIG_FILE		LDAP_SYSCONFDIR LDAP_DIRSEP "ud.conf"
	/* default editor */
#define UD_DEFAULT_EDITOR	LDAP_EDITOR
	/* default bbasename of user config file */
#define UD_USER_CONFIG_FILE	".udrc"
	/* default base where groups are created */
#define UD_WHERE_GROUPS_ARE_CREATED	""
	/* default base below which all groups live */
#define UD_WHERE_ALL_GROUPS_LIVE	""

/*
 * SLAPD DEFINITIONS
 */
	/* location of the default slapd config file */
#define SLAPD_DEFAULT_CONFIGFILE	LDAP_SYSCONFDIR LDAP_DIRSEP "slapd.conf"
#define SLAPD_DEFAULT_UCDATA		LDAP_DATADIR LDAP_DIRSEP "ucdata"
	/* default max deref depth for aliases */
#define SLAPD_DEFAULT_MAXDEREFDEPTH	15
	/* default sizelimit on number of entries from a search */
#define SLAPD_DEFAULT_SIZELIMIT		500
	/* default timelimit to spend on a search */
#define SLAPD_DEFAULT_TIMELIMIT		3600
	/* minimum max ids that a single index entry can map to in ldbm */
#define SLAPD_LDBM_MIN_MAXIDS		(8192-4)

/* the following DNs must be normalized! */
	/* dn of the default subschema subentry */
#define SLAPD_SCHEMA_DN			"cn=Subschema"
	/* dn of the default "monitor" subentry */
#define SLAPD_MONITOR_DN		"cn=Monitor"

#endif /* _LDAP_CONFIG_H */

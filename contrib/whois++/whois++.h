/*
 *			W H O I S + +
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	October 1992
 * Copyright:	(C) 1992, The University of Adelaide
 * Version:	1.7
 * Description:
 *	This is an experimental implementation of the proposed IETF
 *	WNILS WG update to the whois/nicname protocol (whois++).
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of Adelaide. The name of the University may not
 * be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#if defined(INTERNATIONAL)
#include <langinfo.h>
#include <locale.h>
#include <nl_types.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "syslog.h"
#include "lber.h"
#include "ldap.h"

#define	EQ(x,y)		(strcasecmp(x,y) == 0)

#if defined(sun)
extern	int	sys_nerr;
extern	char	*sys_errlist[];
#define strerror(_e)	( ( ( (_e) >= 0 ) && ( (_e) < sys_nerr ) ) ? \
		sys_errlist[(_e)] : "Undocumented error code" )
#endif

#if !defined(TRUE)
#define	TRUE			1
#define	FALSE			0
#endif

#if defined(MAIN)
#define	EXTERN
#else
#define	EXTERN			extern
#endif

#if !defined(ABRIDGED_LIMIT)
#define	ABRIDGED_LIMIT		10
#endif
#if !defined(DEFAULT_LDAPHOST)
#define DEFAULT_LDAPHOST	"localhost"
#endif
#if !defined(DEFAULT_SIZELIMIT)
#define DEFAULT_SIZELIMIT	50
#endif
#if !defined(DEFAULT_TIMELIMIT)
#define DEFAULT_TIMELIMIT	60
#endif
#if !defined(HELP_DIRECTORY)
#define HELP_DIRECTORY		"/usr/local/isode/help/whois++"
#endif
#if !defined(CONFIG_DIRECTORY)
#define	CONFIG_DIRECTORY	"/usr/local/isode/etc/whois++"
#endif
#if !defined(DEFAULT_LANGUAGE)
#define	DEFAULT_LANGUAGE	"english"
#endif

#define	ATTRIBUTE_INCREMENT	10
#define	TABLE_INCREMENT		10
#define	DEFAULT_LINE_LENGTH	80
#define MIN_LINE_LENGTH		40
#define	MAX_LINE_LENGTH		200

/*
 * Tokens
 */
#define	HELP		1
#define	LIST		2
#define	DESCRIBE	3
#define	VERSION		4
#define	SHOW		5
#define	CONSTRAINTS	6
#define	SEARCH		7
#define	TEMPLATE	8
#define	HANDLE		9
#define	ATTRIBUTE	10
#define	VALUE		11
#define	SEARCH_ALL	12
#define	COMMA		13
#define	ERROR		14
#define	EQUALS		15
#define	COLON		16
#define	SEMICOLON	17
#define	FULL		18
#define	ABRIDGED	19
#define	SUMMARY		20
#define	READ		21
#define	LANGUAGE	22
#define	FORMAT		23
#define	HOLD		24
#define	MAXHITS		25
#define	MATCH		26
#define	LINE_LENGTH	27
#define	COMMAND		28
#define TRACE		29

typedef	struct {
	char	*key;
	char	*value;
	} table;

EXTERN int		debug, outputFormat, lineLength, holdConnection, log;
EXTERN int		maxHits, numberOfTemplates, tableSize, maximumSize;
EXTERN char		*program, *ldaphost, *language, *locale, *base;
EXTERN char		*contact, *hostname, *user, *password, *helpDir;
EXTERN char		*configDir, *organisation, *defaultLanguage;
EXTERN char		*banner;
EXTERN char		**category;
EXTERN table		*templateTranslationTable;

extern int		displayDescribe(), parseCommand();
extern void		needHelp();
extern void		showTemplate(), listTemplates();
extern char		**specifyAttributes();
extern char		*lowerCase(), *version(), *attributeLabel();
extern char		*rfc931_name();

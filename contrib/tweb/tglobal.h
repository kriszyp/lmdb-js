/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* tglobal.h..                                                              *
*                                                                          *
* Function:..Global variables for TWEB                                     *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            August 16 1996               Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            September 13 1999          ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: tglobal.h,v 1.8 1999/09/13 13:47:47 zrnsk01 Exp $
 *
 */


#ifndef _TGLOBAL_
#define _TGLOBAL_

#include "lber.h"
#include "ldap.h"


extern int	debug;
extern int	dosyslog;
extern int  ldap_syslog;
extern int  ldap_syslog_level;

extern struct timeval timestore[];
extern int items_displayed;

extern int		searchaliases;

#if OL_LDAPV >= 2

extern LDAPFriendlyMap      *fm;

#else

extern FriendlyMap      *fm;

#endif

extern LDAPFiltDesc	*filtd;

extern char	version[];
extern char	copyright[];

extern int	http;	/* HTTP-header in request -> also in reply */

extern int	request;


#endif /* _TGLOBAL */



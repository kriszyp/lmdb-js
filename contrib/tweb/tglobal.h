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
*            December 29 1998           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: tglobal.h,v 1.6 1999/09/10 15:01:20 zrnsk01 Exp $
 *
 */


#ifndef _TGLOBAL_
#define _TGLOBAL_

#include "lber.h"
#include "ldap.h"


extern int	debug;
extern int	dosyslog;
extern struct timeval timestore[];
extern int items_displayed;

extern int		searchaliases;

#if defined LDAP_VENDOR_NAME && defined LDAP_API_VERSION
#  if LDAP_API_VERSION > 2001 && LDAP_API_VERSION < 2010

extern LDAPFriendlyMap      *fm;

#  else

extern LDAPFriendlyMap      *fm;

#  endif
#else

extern FriendlyMap      *fm;

#endif

extern LDAPFiltDesc	*filtd;

extern char	version[];
extern char	copyright[];

extern int	http;	/* HTTP-header in request -> also in reply */

extern int	request;


#endif /* _TGLOBAL */



/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* tweb.h.....                                                              *
*                                                                          *
* Function:..Header-File for TWEB-SOFTWARE                                 *
*                                                                          *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            August 16 1995               Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            December 31 1998           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: tweb.h,v 1.6 1999/09/10 15:01:20 zrnsk01 Exp $
 *
 */


#ifndef _TWEB_
#define _TWEB_


#include "tgeneral.h"
#include "init_exp.h"
#include "server_exp.h"
#include "support_exp.h"

PRIVATE void do_child();
int	debug;
int	dosyslog = 0;

GLOB_STRUCT *globP;

int		searchaliases = 1;

#if defined LDAP_VENDOR_NAME && defined LDAP_API_VERSION
#  if LDAP_API_VERSION > 2001 && LDAP_API_VERSION < 2010

LDAPFriendlyMap     *fm = NULL;

#  else

LDAPFriendlyMap     *fm = NULL;

#  endif
#else

FriendlyMap     *fm = NULL;

#endif

LDAPFiltDesc	*filtd;

extern char	version[];

int	http = 1;	/* HTTP Version ??? */

int	request = UNKNOWN;



#endif /* _TWEB_ */



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
*            September 13 1999          ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: tweb.h,v 1.8 1999/09/13 13:47:47 zrnsk01 Exp $
 *
 */


#ifndef _TWEB_
#define _TWEB_


#include "tgeneral.h"
#include "init_exp.h"
#include "server_exp.h"
#include "support_exp.h"

PRIVATE void do_child();
int	debug                 = 0;
int ldap_syslog           = 0;
int ldap_syslog_level     = 0;

int	dosyslog = 0;

GLOB_STRUCT *globP;

int		searchaliases = 1;

#if OL_LDAPV >= 2

LDAPFriendlyMap     *fm = NULL;

#else

FriendlyMap     *fm = NULL;

#endif

LDAPFiltDesc	*filtd;

extern char	version[];

int	http = 1;	/* HTTP Version ??? */

int	request = UNKNOWN;



#endif /* _TWEB_ */



/* This file contains definitions for use by the Hesiod name service and
 * applications.
 *
 * For copying and distribution information, see the file <mit-copyright.h>.
 *
 * Original version by Steve Dyer, IBM/Project Athena.
 *
 * Vendor History
 *
 * Revision 1.6  90/07/20  13:09:16  probe
 * Incorrect declaration of hes_getpwnam()
 * 
 * Revision 1.5  90/07/11  16:49:12  probe
 * Patches from <mar>
 * Added missing declarations
 * 
 * Revision 1.5  90/07/09  18:44:30  mar
 * mention hes_getservbyname(), hes_getpwent()
 * 
 * Revision 1.4  88/08/07  23:18:00  treese
 * Second-public-distribution
 * 
 * Revision 1.3  88/08/07  21:52:39  treese
 * First public distribution
 * 
 * Revision 1.2  88/06/05  19:51:32  treese
 * Cleaned up for public distribution
 * 
 */

/* Configuration information. */

#ifndef _HESIOD_
#define _HESIOD_

#ifdef WINDOWS
#include <windows.h>
#endif

#if !defined(WINDOWS) && !defined(_WINDOWS)
#define HESIOD_CONF     "/etc/hesiod.conf"      /* Configuration file. */
#else
#define HESIOD_CONF     "c:\\net\\tcp\\hesiod.cfg"
#endif

#define DEF_RHS         ".Athena.MIT.EDU"       /* Defaults if HESIOD_CONF */
#define DEF_LHS         ".ns"                   /*    file is not present. */

/* Error codes. */

#define HES_ER_UNINIT   -1      /* uninitialized */
#define HES_ER_OK       0       /* no error */
#define HES_ER_NOTFOUND 1       /* Hesiod name not found by server */
#define HES_ER_CONFIG   2       /* local problem (no config file?) */
#define HES_ER_NET      3       /* network problem */

/* Declaration of routines */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(WINDOWS) && !defined(_WINDOWS)
char *hes_to_bind();
char **hes_resolve();
int hes_error();
#else 
#ifndef _WSHELPER_
LPSTR FAR PASCAL hes_to_bind(LPSTR HesiodName, LPSTR HesiodNameType);
LPSTR * FAR PASCAL hes_resolve(LPSTR HesiodName, LPSTR HesiodNameType);
int FAR PASCAL hes_error(void);
#endif
#endif


/* For use in getting post-office information. */

#if !defined(WINDOWS) && !defined(_WINDOWS)
struct hes_postoffice {
	char    *po_type;
	char    *po_host;
	char    *po_name;
};
#else
struct hes_postoffice {
	LPSTR   po_type;
	LPSTR   po_host;
	LPSTR   po_name;
};
#endif

/* Other routines */

#if !defined(WINDOWS) && !defined(_WINDOWS)
struct hes_postoffice *hes_getmailhost();
struct servent *hes_getservbyname();
struct passwd *hes_getpwnam();
struct passwd *hes_getpwuid();
#else
struct hes_postoffice FAR * WINAPI hes_getmailhost(LPSTR user);
struct servent FAR * WINAPI hes_getservbyname(LPSTR name, LPSTR proto);
struct passwd FAR * WINAPI hes_getpwnam(LPSTR nam);
struct passwd FAR * WINAPI hes_getpwuid(int uid);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _HESIOD_ */

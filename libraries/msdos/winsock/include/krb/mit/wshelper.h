/*
	WSHelper DNS/Hesiod Library for WINSOCK
	wshelper.h
*/

#ifndef _WSHELPER_
#define _WSHELPER_

#include <winsock.h>
#include <resolv.h>
#include <hesiod.h>

#ifdef __cplusplus
extern "C" {
#endif

int FAR PASCAL res_mkquery(int op, char FAR *dname, int qclass, int type,
			   char FAR *data, int datalen, struct rrec FAR *newrr,
			   char FAR *buf, int buflen);

int FAR PASCAL res_send(char FAR *msg, int msglen, char FAR *answer, int anslen);

int FAR PASCAL res_init();

int FAR PASCAL dn_comp(char FAR *exp_dn, char FAR *comp_dn, int length,
		       char FAR * FAR *dnptrs, char FAR * FAR *lastdnptr);

int FAR PASCAL dn_expand(char FAR *msg, char FAR *eomorig, char FAR *comp_dn,
			 char FAR *exp_dn, int length);

struct hostent FAR* FAR PASCAL rgethostbyname(char FAR *name);

struct hostent FAR* FAR PASCAL rgethostbyaddr(char FAR *addr, int len, int type);

LPSTR FAR PASCAL hes_to_bind(char FAR *HesiodName, char FAR *HesiodNameType);
     
LPSTR * FAR PASCAL hes_resolve(char FAR *HesiodName, char FAR *HesiodNameType);

int FAR PASCAL hes_error(void);

void FAR PASCAL res_setopts(long opts);

long FAR PASCAL res_getopts(void);

unsigned long FAR PASCAL inet_aton(register const char *cp, struct in_addr *addr);

LPSTR FAR PASCAL gethinfobyname(LPSTR name);

LPSTR FAR PASCAL getmxbyname(LPSTR name);

LPSTR FAR PASCAL getrecordbyname(LPSTR name, int rectype);

DWORD FAR PASCAL rrhost( LPSTR lpHost );

struct servent FAR * FAR PASCAL rgetservbyname(LPSTR name, LPSTR proto);

#ifdef __cplusplus
}
#endif

#endif  /* _WSHELPER_ */


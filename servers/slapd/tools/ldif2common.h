/* ldif2common.h - common definitions for the ldif2* tools */

#ifndef LDIF2COMMON_H_
#define LDIF2COMMON_H_

#include "ldap_defaults.h"
#include "../slap.h"

enum ldiftool {
	LDIF2LDBM = 1, LDIF2INDEX, LDIF2ID2ENTRY, LDIF2ID2CHILDREN
};


extern	char	*progname;
extern	char	*tailorfile;
extern	char	*inputfile;
extern	char	*sbindir;
extern	int     cmdkids;
extern	int 	dbnum;


void slap_ldif_init LDAP_P(( int, char **, int, const char *, int ));

#endif /* LDIF2COMMON_H_ */

/* $OpenLDAP$ */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef LDAPSYNTAX_H
#define LDAPSYNTAX_H 1

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/* XXX: the "master" LINE_WIDTH #define is in ../slap.h */
#define LINE_WIDTH	76	/* for lines in string rep of an entry */

/*
 * function prototypes
 */

int init_syntaxes LDAP_P(( void ));
int av2ldif LDAP_P(( FILE *outfp, AV_Sequence av, DN dn, short syntax,
    char *attrname, PS str_ps ));

LDAP_END_DECL
#endif

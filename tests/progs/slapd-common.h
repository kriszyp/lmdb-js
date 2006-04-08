/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#ifndef SLAPD_COMMON_H
#define SLAPD_COMMON_H

extern void tester_init( const char *pname );
extern char * tester_uri( char *uri, char *host, int port );
extern void tester_error( const char *msg );
extern void tester_perror( const char *fname, const char *msg );
extern void tester_ldap_error( LDAP *ld, const char *fname, const char *msg );

#endif /* SLAPD_COMMON_H */

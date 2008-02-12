/* common.h - common definitions for the ldap client tools */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This file was initially created by Hallvard B. Furuseth based (in
 * part) upon argument parsing code for individual tools located in
 * this directory. 
 */

#ifndef _CLIENT_TOOLS_COMMON_H_
#define _CLIENT_TOOLS_COMMON_H_

LDAP_BEGIN_DECL

/* Defined and set in common.c */
extern int   authmethod;
extern char *binddn;
extern int   contoper;
extern int   debug;
extern char *infile;
extern char *ldapuri;
extern char *ldaphost;
extern int   ldapport;
#ifdef HAVE_CYRUS_SASL
extern unsigned sasl_flags;
extern char	*sasl_realm;
extern char	*sasl_authc_id;
extern char	*sasl_authz_id;
extern char	*sasl_mech;
extern char	*sasl_secprops;
#endif
extern int   use_tls;

extern char *assertion;
extern char *authzid;
extern int   manageDIT;
extern int   manageDSAit;
extern int   noop;
extern int   ppolicy;
extern int	preread, postread;
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
extern int	chaining;
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

extern int   not;
extern int   want_bindpw;
extern struct berval passwd;
extern char *pw_file;
extern int   referrals;
extern int   protocol;
extern int   verbose;
extern int   ldif;
extern int   version;

/* Defined in common.c, set in main() */
extern char *prog;
extern const char __Version[];

/* Defined in main program */
extern const char options[];
void usage LDAP_P(( void )) LDAP_GCCATTR((noreturn));
int handle_private_option LDAP_P(( int i ));

/* Defined in common.c */
void tool_init LDAP_P(( void ));
void tool_common_usage LDAP_P(( void ));
void tool_args LDAP_P(( int, char ** ));
LDAP *tool_conn_setup LDAP_P(( int dont, void (*private_setup)( LDAP * ) ));
void tool_bind LDAP_P(( LDAP * ));
void tool_unbind LDAP_P(( LDAP * ));
void tool_destroy LDAP_P(( void ));
void tool_server_controls LDAP_P(( LDAP *, LDAPControl *, int ));
int tool_check_abandon LDAP_P(( LDAP *ld, int msgid ));
void tool_perror LDAP_P((
	char *func,
	int err,
	char *extra,
	char *matched,
	char *info,
	char **refs ));
void tool_print_ctrls LDAP_P(( LDAP *ld, LDAPControl **ctrls ));
int tool_write_ldif LDAP_P(( int type, char *name, char *value, ber_len_t vallen ));

LDAP_END_DECL

#endif /* _CLIENT_TOOLS_COMMON_H_ */

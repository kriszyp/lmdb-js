/* back-ldap.h - ldap backend header file */
/* $OpenLDAP$ */

/*
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 */

#ifndef SLAPD_LDAP_H
#define SLAPD_LDAP_H

#include "external.h"

LDAP_BEGIN_DECL

struct slap_conn;
struct slap_op;

struct ldapconn {
	struct ldapconn *next;
	struct slap_conn	*conn;
	LDAP		*ld;
	int		bound;
};

struct ldapinfo {
	char *url;
	char *suffix;
	char *binddn;
	char *bindpw;
	ldap_pvt_thread_mutex_t		conn_mutex;
	struct ldapconn *lcs;
};

struct ldapconn *ldap_back_getconn(struct ldapinfo *li, struct slap_conn *conn,
	struct slap_op *op);
void ldap_back_dobind(struct ldapconn *lc, Operation *op);
int ldap_back_op_result(struct ldapconn *lc, Operation *op);
int	back_ldap_LTX_init_module(int argc, char *argv[]);

LDAP_END_DECL

#endif

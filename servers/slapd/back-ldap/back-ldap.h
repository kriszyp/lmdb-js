/* back-ldap.h - ldap backend header file */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* This is an altered version */
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
 *
 *
 *
 * Copyright 2000, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This software is being modified by Pierangelo Masarati.
 * The previously reported conditions apply to the modified code as well.
 * Changes in the original code are highlighted where required.
 * Credits for the original code go to the author, Howard Chu.      
 */

#ifndef SLAPD_LDAP_H
#define SLAPD_LDAP_H

#include "external.h"

LDAP_BEGIN_DECL

struct slap_conn;
struct slap_op;

struct ldapconn {
	struct slap_conn	*conn;
	LDAP		*ld;
	char 		*bound_dn;
	int		bound;
};

struct ldapinfo {
	char *url;
#if 0 /* unused! */
	char *suffix;
#endif /* 0 */
	char **suffix_massage;
	char *binddn;
	char *bindpw;
	ldap_pvt_thread_mutex_t		conn_mutex;
	Avlnode *conntree;
};

struct ldapconn *ldap_back_getconn(struct ldapinfo *li, struct slap_conn *conn,
	struct slap_op *op);
int ldap_back_dobind(struct ldapconn *lc, Operation *op);
int ldap_back_map_result(int err);
int ldap_back_op_result(struct ldapconn *lc, Operation *op);
int	back_ldap_LTX_init_module(int argc, char *argv[]);

char *ldap_back_dn_massage(struct ldapinfo *li, char *dn, int normalized);
char *ldap_back_dn_restore(struct ldapinfo *li, char *dn, int normalized);

int conn_cmp(const void *, const void *);
int conn_dup(void *, void *);
			
LDAP_END_DECL

#endif

/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef _LDAPD_COMMON_H
#define _LDAPD_COMMON_H 1

/*
 * This structure represents an association to a dsa.  There is one of
 * these for each association open (a new association is made for each
 * new dsa, and for each dn).
 */

struct conn {
	int		c_ad;		/* association descriptor */
	char		*c_dn;		/* the dn this asoc is bound as */
	char		*c_cred;	/* corresponding pw */
	long		c_credlen;
	unsigned long	c_method;
	struct PSAPaddr	*c_paddr;	/* the dsa address */
	int		c_time;		/* time this association inited */
	int		c_refcnt;	/* number of ops referencing this ad */
	struct conn	*c_next;
};

/*
 * This structure represents an outstanding request.  There is one of
 * these for each client request for which we have not yet received a
 * response from a dsa.
 */

struct msg {
	int		m_msgid;	/* the message id */
	int		m_uniqid;	/* unique id for this message */
	int		m_msgtype;	/* the ldap operation type */
	LDAPMod		*m_mods;	/* for modify operations only */
	BerElement	*m_ber;		/* the unparsed ber for the op */
	struct conn	*m_conn;	/* connection structure */
#ifdef LDAP_CONNECTIONLESS
	int		m_cldap;	/* connectionless transport? (CLDAP) */
	struct sockaddr	m_clientaddr;	/* client address (if using CLDAP) */
	DN		m_searchbase;	/* base used in search */
#endif /* LDAP_CONNECTIONLESS */
	struct msg	*m_next;
};

#define DEFAULT_TIMEOUT			3600	/* idle client connections */
#define DEFAULT_REFERRAL_TIMEOUT	900	/* DSA connections */

#include "proto-ldapd.h"
#include "ldap_log.h"

#endif

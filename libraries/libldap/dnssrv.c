/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * locate using DNS SRV records. Location code based on
 * MIT Kerberos KDC location code.
 */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/param.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

/* Sometimes this is not defined. */
#ifndef T_SRV
#define T_SRV            33
#endif				/* T_SRV */

int ldap_pvt_domain2dn(LDAP_CONST char *domain_in, char **dnp)
{
    char *domain, *s, *tok_r, *dn;
    size_t loc;

    if (domain_in == NULL || dnp == NULL) {
	return LDAP_NO_MEMORY;
    }
    domain = LDAP_STRDUP(domain_in);
    if (domain == NULL) {
	return LDAP_NO_MEMORY;
    }
    dn = NULL;
    loc = 0;

    for (s = ldap_pvt_strtok(domain, ".", &tok_r);
	 s != NULL;
	 s = ldap_pvt_strtok(NULL, ".", &tok_r)) {
	size_t len = strlen(s);

	dn = (char *) LDAP_REALLOC(dn, loc + len + 4);
	if (dn == NULL) {
	    LDAP_FREE(domain);
	    return LDAP_NO_MEMORY;
	}
	if (loc > 0) {
	    /* not first time. */
	    strcpy(dn + loc, ",");
	    loc++;
	}
	strcpy(dn + loc, "dc=");
	loc += 3;

	strcpy(dn + loc, s);
	loc += len;
    }

    LDAP_FREE(domain);

    *dnp = dn;

    return LDAP_SUCCESS;
}

/*
 * Lookup LDAP servers for domain (using the DNS
 * SRV record _ldap._tcp.domain), set the default
 * base using an algorithmic mapping of the domain,
 * and return a session.
 */
int ldap_dnssrv_init(LDAP ** ldp, LDAP_CONST char *domain)
{
#ifdef HAVE_RES_SEARCH
    char *request;
    char *dn;
    char *hostlist = NULL;
    LDAP *ld = NULL;
    int rc, len, cur = 0;
    unsigned char reply[1024];

    request = LDAP_MALLOC(strlen(domain) + sizeof("_ldap._tcp."));
    if (request == NULL) {
	rc = LDAP_NO_MEMORY;
	goto out;
    }
    sprintf(request, "_ldap._tcp.%s", domain);

#ifdef LDAP_R_COMPILE
    ldap_pvt_thread_mutex_lock(&ldap_int_resolv_mutex);
#endif

    len = res_search(request, C_IN, T_SRV, reply, sizeof(reply));
    if (len >= 0) {
	unsigned char *p;
	char host[1024];
	int status;
	u_short port;
	int priority, weight;

	/* Parse out query */
	p = reply;
	p += sizeof(HEADER);
	status = dn_expand(reply, reply + len, p, host, sizeof(host));
	if (status < 0) {
	    goto out;
	}
	p += status;
	p += 4;

	while (p < reply + len) {
	    int type, class, ttl, size;
	    status = dn_expand(reply, reply + len, p, host, sizeof(host));
	    if (status < 0) {
		goto out;
	    }
	    p += status;
	    type = (p[0] << 8) | p[1];
	    p += 2;
	    class = (p[0] << 8) | p[1];
	    p += 2;
	    ttl = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	    p += 4;
	    size = (p[0] << 8) | p[1];
	    p += 2;
	    if (type == T_SRV) {
		int buflen;
		status = dn_expand(reply, reply + len, p + 6, host, sizeof(host));
		if (status < 0) {
		    goto out;
		}
		priority = (p[0] << 8) | p[1];
		weight = (p[2] << 8) | p[3];
		port = (p[4] << 8) | p[5];

		buflen = strlen(host) + /* :XXXXX\0 */ 7;
		hostlist = (char *) LDAP_REALLOC(hostlist, cur + buflen);
		if (hostlist == NULL) {
		    rc = LDAP_NO_MEMORY;
		    goto out;
		}
		if (cur > 0) {
		    /* not first time around */
		    hostlist[cur++] = ' ';
		}
		cur += sprintf(&hostlist[cur], "%s:%hd", host, port);
	    }
	    p += size;
	}
    }
    if (hostlist == NULL) {
	/* No LDAP servers found in DNS. */
	rc = LDAP_UNAVAILABLE;
	goto out;
    }
    rc = ldap_create(&ld);
    if (rc != LDAP_SUCCESS) {
	goto out;
    }
    rc = ldap_set_option(ld, LDAP_OPT_HOST_NAME, hostlist);
    if (rc != LDAP_SUCCESS) {
	goto out;
    }
    rc = ldap_pvt_domain2dn(domain, &dn);
    if (rc != LDAP_SUCCESS) {
	goto out;
    }
    if (ld->ld_options.ldo_defbase != NULL) {
	LDAP_FREE(ld->ld_options.ldo_defbase);
    }
    ld->ld_options.ldo_defbase = dn;

    *ldp = ld;

    rc = LDAP_SUCCESS;

  out:
#ifdef LDAP_R_COMPILE
    ldap_pvt_thread_mutex_unlock(&ldap_int_resolv_mutex);
#endif

    if (request != NULL) {
	LDAP_FREE(request);
    }
    if (hostlist != NULL) {
	LDAP_FREE(hostlist);
    }
    if (rc != LDAP_SUCCESS && ld != NULL) {
	ldap_ld_free(ld, 1, NULL, NULL);
    }
    return rc;
#else
    return LDAP_NOT_SUPPORTED;
#endif				/* HAVE_RES_SEARCH */
}

/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * locate LDAP servers using DNS SRV records.
 * Location code based on MIT Kerberos KDC location code.
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

int ldap_dn2domain(
	LDAP_CONST char *dn_in,
	char **domainp)
{
	int i;
	char *domain = NULL;
	char **dn;

	if( dn_in == NULL || domainp == NULL ) {
		return -1;
	}

	dn = ldap_explode_dn( dn_in, 0 );

	if( dn == NULL ) {
		return -2;
	}

	for( i=0; dn[i] != NULL; i++ ) {
		char ** rdn = ldap_explode_rdn( dn[i], 0 );

		if( rdn == NULL || *rdn == NULL ) {
			LDAP_FREE( rdn );
			LDAP_FREE( domain );
			LDAP_VFREE( dn );
			return -3;
		}

#define LDAP_DC "dc="
#define LDAP_DCOID "0.9.2342.19200300.100.1.25="

		if( rdn[1] == NULL ) {
			char *dc;
			/* single RDN */

			if( strncasecmp( rdn[0],
				LDAP_DC, sizeof(LDAP_DC)-1 ) == 0 )
			{
				dc = &rdn[0][sizeof(LDAP_DC)-1];

			} else if( strncmp( rdn[0],
				LDAP_DCOID, sizeof(LDAP_DCOID)-1 ) == 0 )
			{
				dc = &rdn[0][sizeof(LDAP_DCOID)-1];

			} else {
				dc = NULL;
			}

			if( dc != NULL ) {
				char *ndomain;

				if( *dc == '\0' ) {
					/* dc value is empty! */
					LDAP_FREE( rdn );
					LDAP_FREE( domain );
					LDAP_VFREE( dn );
					LDAP_VFREE( rdn );
					return -4;
				}

				ndomain = LDAP_REALLOC( domain,
					( domain == NULL ? 0 : strlen(domain) )
					+ strlen(dc) + sizeof(".") );

				if( ndomain == NULL ) {
					LDAP_FREE( rdn );
					LDAP_FREE( domain );
					LDAP_VFREE( dn );
					LDAP_VFREE( rdn );
					return -5;
				}

				strcat( ndomain, dc );
				strcat( ndomain, "." );

				domain = ndomain;
				continue;
			}
		}

		LDAP_VFREE( rdn );
		LDAP_FREE( domain );
		domain = NULL;
	} 

	*domainp = domain;
	return 0;
}

int ldap_domain2dn(
	LDAP_CONST char *domain_in,
	char **dnp)
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

	dn = (char *) LDAP_REALLOC(dn, loc + sizeof(",dc=") + len );
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
	loc += sizeof("dc=")-1;

	strcpy(dn + loc, s);
	loc += len;
    }

    LDAP_FREE(domain);

    *dnp = dn;

    return LDAP_SUCCESS;
}

/*
 * Lookup and return LDAP servers for domain (using the DNS
 * SRV record _ldap._tcp.domain).
 */
int ldap_domain2hostlist(
	LDAP_CONST char *domain,
	char **list )
{
#ifdef HAVE_RES_SEARCH
    char *request;
    char *dn;
    char *hostlist = NULL;
    int rc, len, cur = 0;
    unsigned char reply[1024];

	if( domain == NULL || *domain == '\0' ) {
		return LDAP_PARAM_ERROR;
	}

	if( list == NULL ) {
		return LDAP_PARAM_ERROR;
	}

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
	/* int priority, weight; */

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
		/* ignore priority and weight for now */
		/* priority = (p[0] << 8) | p[1]; */
		/* weight = (p[2] << 8) | p[3]; */
		port = (p[4] << 8) | p[5];

		buflen = strlen(host) + sizeof(":65355");
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

    rc = LDAP_SUCCESS;
	*list = hostlist;

  out:
#ifdef LDAP_R_COMPILE
    ldap_pvt_thread_mutex_unlock(&ldap_int_resolv_mutex);
#endif

    if (request != NULL) {
	LDAP_FREE(request);
    }
    if (rc != LDAP_SUCCESS && hostlist != NULL) {
	LDAP_FREE(hostlist);
    }
    return rc;
#else
    return LDAP_NOT_SUPPORTED;
#endif				/* HAVE_RES_SEARCH */
}

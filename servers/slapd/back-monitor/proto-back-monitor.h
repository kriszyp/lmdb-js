/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
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
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#ifndef _PROTO_BACK_MONITOR
#define _PROTO_BACK_MONITOR

#include <ldap_cdefs.h>

#include "external.h"

LDAP_BEGIN_DECL

/*
 * backends
 */
int monitor_subsys_backend_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));

/*
 * cache
 */
extern int monitor_cache_cmp LDAP_P(( const void *c1, const void *c2 ));
extern int monitor_cache_dup LDAP_P(( void *c1, void *c2 ));
extern int monitor_cache_add LDAP_P(( struct monitorinfo *mi, Entry *e ));
extern int monitor_cache_get LDAP_P(( struct monitorinfo *mi, struct berval *ndn, Entry **ep ));
extern int monitor_cache_dn2entry LDAP_P(( Operation *op, struct berval *ndn, Entry **ep, Entry **matched ));
extern int monitor_cache_lock LDAP_P(( Entry *e ));
extern int monitor_cache_release LDAP_P(( struct monitorinfo *mi, Entry *e ));

/*
 * connections
 */
int monitor_subsys_conn_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));
int monitor_subsys_conn_update LDAP_P(( Operation *op, Entry *e ));
int monitor_subsys_conn_create LDAP_P(( Operation *op, struct berval *ndn,
			Entry *e_parent, Entry **ep ));

/*
 * databases 
 */
int monitor_subsys_database_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));
int monitor_subsys_database_modify LDAP_P(( Operation *op, Entry *e ));

/*
 * entry
 */
extern int monitor_entry_update LDAP_P(( Operation *op, Entry *e ));
extern int monitor_entry_create LDAP_P(( Operation *op, struct berval *ndn,
		Entry *e_parent, Entry **ep ));
extern int monitor_entry_modify LDAP_P(( Operation *op, Entry *e ));
int monitor_entry_test_flags LDAP_P(( struct monitorentrypriv *mp, int cond ));
extern struct monitorentrypriv * monitor_entrypriv_create LDAP_P(( void ));

/*
 * init
 */
extern int monitor_back_register_subsys LDAP_P(( monitorsubsys *ms ));
extern monitorsubsys * monitor_back_get_subsys LDAP_P(( const char *name ));
extern monitorsubsys * monitor_back_get_subsys_by_dn LDAP_P(( struct berval *ndn, int sub ));

/*
 * listener
 */
int monitor_subsys_listener_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));

/*
 * log
 */
int monitor_subsys_log_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));
int monitor_subsys_log_modify LDAP_P(( Operation *op, Entry *e ));

/*
 * operations
 */
int monitor_subsys_ops_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));
int monitor_subsys_ops_update LDAP_P(( Operation *op, Entry *e ));

/*
 * overlay
 */
int monitor_subsys_overlay_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));

/*
 * sent
 */
int monitor_subsys_sent_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));
int monitor_subsys_sent_update LDAP_P(( Operation *op, Entry *e ));

/*
 * threads
 */
int monitor_subsys_thread_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));
int monitor_subsys_thread_update LDAP_P(( Operation *op, Entry *e ));

/*
 * time
 */
int monitor_subsys_time_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));
int monitor_subsys_time_update LDAP_P(( Operation *op, Entry *e ));

/*
 * waiters
 */
int monitor_subsys_rww_init LDAP_P(( BackendDB *be, monitorsubsys *ms ));
int monitor_subsys_rww_update LDAP_P(( Operation *op, Entry *e ));

/* NOTE: this macro assumes that bv has been allocated
 * by ber_* malloc functions or is { 0L, NULL } */
#if defined(HAVE_BIGNUM)
#define UI2BV(bv,ui) \
	do { \
		char		*val; \
		ber_len_t	len; \
		val = BN_bn2dec(ui); \
		if (val) { \
			len = strlen(val); \
			if ( len > (bv)->bv_len ) { \
				(bv)->bv_val = ber_memrealloc( (bv)->bv_val, len + 1 ); \
			} \
			AC_MEMCPY((bv)->bv_val, val, len + 1); \
			(bv)->bv_len = len; \
			OPENSSL_free(val); \
		} else { \
			ber_memfree( (bv)->bv_val ); \
			BER_BVZERO( (bv) ); \
		} \
	} while ( 0 )
#elif defined(HAVE_GMP)
/* NOTE: according to the documentation, the result 
 * of mpz_sizeinbase() can exceed the length of the
 * string representation of the number by 1
 */
#define UI2BV(bv,ui) \
	do { \
		ber_len_t	len = mpz_sizeinbase( (ui), 10 ); \
		if ( len > (bv)->bv_len ) { \
			(bv)->bv_val = ber_memrealloc( (bv)->bv_val, len + 1 ); \
		} \
		(void)mpz_get_str( (bv)->bv_val, 10, (ui) ); \
		if ( (bv)->bv_val[ len - 1 ] == '\0' ) { \
			len--; \
		} \
		(bv)->bv_len = len; \
	} while ( 0 )
#else /* ! HAVE_BIGNUM && ! HAVE_GMP */
#define UI2BV(bv,ui) \
	do { \
		char		buf[] = "+9223372036854775807L"; \
		ber_len_t	len; \
		snprintf( buf, sizeof( buf ), "%lu", (ui) ); \
		len = strlen( buf ); \
		if ( len > (bv)->bv_len ) { \
			(bv)->bv_val = ber_memrealloc( (bv)->bv_val, len + 1 ); \
		} \
		AC_MEMCPY( (bv)->bv_val, buf, len + 1 ); \
	} while ( 0 )
#endif /* ! HAVE_GMP */

LDAP_END_DECL

#endif /* _PROTO_BACK_MONITOR */


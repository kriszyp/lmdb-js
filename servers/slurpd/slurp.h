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
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP).
 */

/* slurp.h - Standalone Ldap Update Replication Daemon (slurpd) */

#ifndef _SLURPD_H_
#define _SLURPD_H_

#if !defined(HAVE_WINSOCK) && !defined(LDAP_SYSLOG)
#define LDAP_SYSLOG 1
#endif

#include <ac/errno.h>
#include <ac/param.h>
#include <ac/signal.h>
#include <ac/syslog.h>
#include <ac/time.h>

#include <sys/types.h>

#include <ldap.h>

#undef  ldap_debug
#define ldap_debug slurp_debug
#include "ldap_log.h"

#include "ldap_pvt_thread.h"
#include "ldap_defaults.h"
#include "ldif.h"

#ifdef HAVE_WINSOCK
	/* should be moved to portable.h.nt */
#define ftruncate(a,b) _chsize(a,b)
#define truncate(a,b) _lclose( _lcreat(a, 0))
#define mkdir(a,b)	mkdir(a)
#define S_IRGRP 0
#define S_IWGRP 0
#endif

#undef SERVICE_NAME
#define SERVICE_NAME	OPENLDAP_PACKAGE "-slurpd"

/* Default directory for slurpd's private copy of replication logs */
#define	DEFAULT_SLURPD_REPLICA_DIR	LDAP_RUNDIR LDAP_DIRSEP "openldap-slurp"

/* Default name for slurpd's private copy of the replication log */
#define	DEFAULT_SLURPD_REPLOGFILE	"slurpd.replog"

/* Name of file which stores saved slurpd state info, for restarting */
#define	DEFAULT_SLURPD_STATUS_FILE	"slurpd.status"

/* slurpd dump file - contents of rq struct are written here (debugging) */
#define	SLURPD_DUMPFILE			LDAP_TMPDIR LDAP_DIRSEP "slurpd.dump"

/* Amount of time to sleep if no more work to do */
#define	DEFAULT_NO_WORK_INTERVAL	3

/* The time we wait between checks to see if the replog file needs trimming */
#define	TRIMCHECK_INTERVAL		( 60 * 5 )

/* Only try to trim slurpd replica files larger than this size */
#define	MIN_TRIM_FILESIZE		( 10L * 1024L )

/* Maximum line length we can read from replication log */
#define	REPLBUFLEN			256

/* TLS flags */
#define TLS_OFF			0
#define TLS_ON			1
#define TLS_CRITICAL	2

/* Rejection records are prefaced with this string */
#define	ERROR_STR	"ERROR"

/* Strings found in replication entries */
#define	T_CHANGETYPESTR		"changetype"
#define	T_CHANGETYPE		1
#define	T_TIMESTR		"time"
#define	T_TIME			2
#define	T_DNSTR			"dn"
#define	T_DN			3

#define	T_ADDCTSTR		"add"
#define	T_ADDCT			4
#define	T_MODIFYCTSTR		"modify"
#define	T_MODIFYCT		5
#define	T_DELETECTSTR		"delete"
#define	T_DELETECT		6
#define	T_MODRDNCTSTR		"modrdn"
#define	T_MODDNCTSTR		"moddn"
#define	T_RENAMECTSTR		"rename"
#define	T_MODRDNCT		7

#define	T_MODOPADDSTR		"add"
#define	T_MODOPADD		8
#define	T_MODOPREPLACESTR	"replace"
#define	T_MODOPREPLACE		9
#define	T_MODOPDELETESTR	"delete"
#define	T_MODOPDELETE		10
#define	T_MODOPINCREMENTSTR	"increment"
#define	T_MODOPINCREMENT	11
#define	T_MODSEPSTR		"-"
#define	T_MODSEP		12

#define	T_NEWRDNSTR		"newrdn"
#define	T_DELOLDRDNSTR	"deleteoldrdn"
#define T_NEWSUPSTR		"newsuperior"

#define	T_ERR			-1

/* Config file keywords */
#define	HOSTSTR			"host"
#define	URISTR			"uri"
#define	ATTRSTR			"attr"
#define	SUFFIXSTR		"suffix"
#define	BINDDNSTR		"binddn"
#define	BINDMETHSTR		"bindmethod"
#define	KERBEROSSTR		"kerberos"
#define	SIMPLESTR		"simple"
#define	SASLSTR			"sasl"
#define	CREDSTR			"credentials"
#define	OLDAUTHCSTR		"bindprincipal"
#define	AUTHCSTR		"authcID"
#define	AUTHZSTR		"authzID"
#define	SRVTABSTR		"srvtab"
#define	SASLMECHSTR		"saslmech"
#define	REALMSTR		"realm"
#define	SECPROPSSTR		"secprops"
#define STARTTLSSTR		"starttls"
#define TLSSTR			"tls"
#define CRITICALSTR		"critical"

#define	REPLICA_SLEEP_TIME	( 10 )

/* Enumeration of various types of bind failures */
#define BIND_OK 					0
#define BIND_ERR_BADLDP				1
#define	BIND_ERR_OPEN				2
#define	BIND_ERR_BAD_ATYPE			3
#define	BIND_ERR_SIMPLE_FAILED		4
#define	BIND_ERR_KERBEROS_FAILED	5
#define	BIND_ERR_BADRI				6
#define	BIND_ERR_VERSION			7
#define	BIND_ERR_REFERRALS			8
#define	BIND_ERR_MANAGEDSAIT		9
#define	BIND_ERR_SASL_FAILED		10
#define	BIND_ERR_TLS_FAILED			11

/* Return codes for do_ldap() */
#define	DO_LDAP_OK			0
#define	DO_LDAP_ERR_RETRYABLE		1
#define	DO_LDAP_ERR_FATAL		2

/*
 * Types of counts one can request from the Rq rq_getcount()
 * member function
 */
/* all elements */
#define	RQ_COUNT_ALL			1
/* all elements with nonzero refcnt */
#define	RQ_COUNT_NZRC			2

/* Amount of time, in seconds, for a thread to sleep when it encounters
 * a retryable error in do_ldap().
 */
#define	RETRY_SLEEP_TIME		60


LDAP_BEGIN_DECL

/*
 * ****************************************************************************
 * Data types for replication queue and queue elements.
 * ****************************************************************************
 */


/*
 * Replica host information.  An Ri struct will contain an array of these,
 * with one entry for each replica.  The end of the array is signaled
 * by a NULL value in the rh_hostname field.
 */
typedef struct rh {
    char 	*rh_hostname;		/* replica hostname  */
    int		rh_port;		/* replica port */
} Rh;


/*
 * Per-replica information.
 *
 * Notes:
 *  - Private data should not be manipulated expect by Ri member functions.
 */
typedef struct ri Ri;
struct ri {
    /* Private data */
    char	*ri_hostname;		/* canonical hostname of replica */
    int		ri_port;		/* port where slave slapd running */
    char	*ri_uri;		/* e.g. "ldaps://ldap-1.example.com:636" */
    LDAP	*ri_ldp;		/* LDAP struct for this replica */
    int		ri_tls;			/* TLS: 0=no, 1=yes, 2=critical */
    int		ri_bind_method;		/* AUTH_SIMPLE or AUTH_KERBEROS */
    char	*ri_bind_dn;		/* DN to bind as when replicating */
    char	*ri_password;		/* Password for any method */
    char	*ri_secprops;		/* SASL security properties */
    char	*ri_realm;			/* realm for any mechanism */
    char	*ri_authcId;		/* authentication ID for any mechanism */
    char	*ri_authzId;		/* authorization ID for any mechanism */
    char	*ri_srvtab;		/* srvtab file for kerberos bind */
    char	*ri_saslmech;		/* SASL mechanism to use */
    struct re	*ri_curr;		/* current repl entry being processed */
    struct stel	*ri_stel;		/* pointer to Stel for this replica */
    unsigned long
		ri_seq;			/* seq number of last repl */
    ldap_pvt_thread_t	ri_tid;			/* ID of thread for this replica */

    /* Member functions */
    int (*ri_process) LDAP_P(( Ri * ));	/* process the next repl entry */
    void (*ri_wake)   LDAP_P(( Ri * ));	/* wake up a sleeping thread */
};



/*
 * Information about one particular modification to make.  This data should
 * be considered private to routines in re.c, and to routines in ri.c.
 */
typedef struct mi {
    /* Private data */
    char	*mi_type;		/* attr or type */
    char	*mi_val;		/* value */
    int		mi_len;			/* length of mi_val */
} Mi;



/* 
 * Information about one particular replication entry.  Only routines in
 * re.c  and rq.c should touch the private data.  Other routines should
 * only use member functions.
 */
typedef struct re Re;
struct re {
    /* Private data */
    ldap_pvt_thread_mutex_t
		re_mutex;		/* mutex for this Re */
    int		re_refcnt;		/* ref count, 0 = done */
    time_t	re_timestamp;		/* timestamp of this re */
    int		re_seq;			/* sequence number */
    Rh    	*re_replicas;		/* array of replica info */
    char	*re_dn;			/* dn of entry being modified */
    int		re_changetype;		/* type of modification */
    Mi		*re_mods;		/* array of modifications to make */
    struct re	*re_next;		/* pointer to next element */

    /* Public functions */
    int	(*re_free)    LDAP_P(( Re * ));	/* free an re struct */
    Re *(*re_getnext) LDAP_P(( Re * ));	/* return next Re in linked list */
    int (*re_parse) LDAP_P(( Re *, char * )); /* parse replication log entry */
    int (*re_write) LDAP_P(( Ri *, Re *, FILE * )); /* write repl. log entry */
    void (*re_dump)  LDAP_P(( Re *, FILE * )); /* debugging - print contents */
    int (*re_lock)   LDAP_P(( Re * ));	  /* lock this re */
    int (*re_unlock) LDAP_P(( Re * ));	  /* unlock this re */
    int (*re_decrefcnt) LDAP_P(( Re * )); /* decrement the refcnt */
    int (*re_getrefcnt) LDAP_P(( Re * )); /* get the refcnt */
};




/* 
 * Definition for the queue of replica information.  Private data is
 * private to rq.c.  Other routines should only touch public data or
 * use member functions.  Note that although we have a member function
 * for locking the queue's mutex, we need to expose the rq_mutex
 * variable so routines in ri.c can use it as a mutex for the
 * rq_more condition variable.
 */
typedef struct rq Rq;
struct rq {

    /* Private data */
    Re		*rq_head;		/* pointer to head */
    Re		*rq_tail;		/* pointer to tail */
    int		rq_nre;			/* total number of Re's in queue */
    int		rq_ndel;		/* number of deleted Re's in queue */
    time_t	rq_lasttrim;		/* Last time we trimmed file */
    
    /* Public data */
    ldap_pvt_thread_mutex_t
		rq_mutex;		/* mutex for whole queue */
    ldap_pvt_thread_cond_t
		rq_more;		/* condition var - more work added */

    /* Member functions */
    Re * (*rq_gethead)	LDAP_P(( Rq * )); /* get the element at head */
    Re * (*rq_getnext)	LDAP_P(( Re * )); /* get the next element */
    int	 (*rq_delhead)	LDAP_P(( Rq * )); /* delete the element at head */
    int	 (*rq_add)	LDAP_P(( Rq *, char * )); /* add at tail */
    void (*rq_gc)	LDAP_P(( Rq * )); /* garbage-collect queue */
    int	 (*rq_lock)	LDAP_P(( Rq * )); /* lock the queue */
    int	 (*rq_unlock)	LDAP_P(( Rq * )); /* unlock the queue */
    int	 (*rq_needtrim)	LDAP_P(( Rq * )); /* see if queue needs trimming */
    int	 (*rq_write)	LDAP_P(( Rq *, FILE * )); /*write Rq contents to file*/
    int	 (*rq_getcount)	LDAP_P(( Rq *, int )); /* return queue counts */
    void (*rq_dump)	LDAP_P(( Rq * )); /* debugging - print contents */
};


/*
 * An Stel (status element) contains information about one replica.
 * Stel structs are associated with the St (status) struct, defined 
 * below.
 */
typedef struct stel {
    char	*hostname;		/* host name of replica */
    int		port;			/* port number of replica */
    time_t	last;			/* timestamp of last successful repl */
    int		seq;			/* Sequence number of last repl */
} Stel;


/*
 * An St struct in an in-core structure which contains the current
 * slurpd state.  Most importantly, it contains an array of Stel
 * structs which contain the timestamp and sequence number of the last
 * successful replication for each replica.  The st_write() member
 * function is called periodically to flush status information to
 * disk.  At startup time, slurpd checks for the status file, and
 * if present, uses the timestamps to avoid "replaying" replications
 * which have already been sent to a given replica.
 */
typedef struct st St;
struct st {
    /* Private data */
    ldap_pvt_thread_mutex_t
		st_mutex;		/* mutex to serialize access */
    Stel	**st_data;		/* array of pointers to Stel structs */
    int		st_nreplicas;		/* number of repl hosts */
    int		st_err_logged;		/* 1 if fopen err logged */
    FILE	*st_fp;			/* st file kept open */
    FILE	*st_lfp;		/* lockfile fp */

    /* Public member functions */
    int  (*st_update) LDAP_P(( St *, Stel*, Re* ));/*update entry for a host*/
    Stel*(*st_add)    LDAP_P(( St *, Ri * ));	   /*add a new repl host*/
    int  (*st_write)  LDAP_P(( St * ));	/* write status to disk */
    int  (*st_read)   LDAP_P(( St * ));	/* read status info from disk */
    int  (*st_lock)   LDAP_P(( St * ));	/* read status info from disk */
    int  (*st_unlock) LDAP_P(( St * ));	/* read status info from disk */
};

#if defined( HAVE_LWP )
typedef struct tl {
    thread_t	tl_tid; 	/* thread being managed */
    time_t	tl_wake;	/* time thread should be resumed */
    struct tl	*tl_next;	/* next node in list */
} tl_t;

typedef struct tsl {
    tl_t	*tsl_list;
    mon_t	tsl_mon;
} tsl_t;
#endif /* HAVE_LWP */

/* 
 * Public functions used to instantiate and initialize queue objects.
 */
extern int Ri_init LDAP_P(( Ri **ri ));
extern int Rq_init LDAP_P(( Rq **rq ));
extern int Re_init LDAP_P(( Re **re ));

#include "proto-slurp.h"

LDAP_END_DECL

#endif /* _SLURPD_H_ */

/*
 * Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef SLURPD_GLOBALS_H
#define SLURPD_GLOBALS_H 1

/*
 * globals.h - definition of structure holding global data.
 */

#include "slurp.h"

LDAP_BEGIN_DECL

typedef struct globals {
    /* Thread ID for file manager thread */
    ldap_pvt_thread_t fm_tid;
    /* The name of the slapd config file (which is also our config file) */
    char *slapd_configfile;
    /* How long the master slurpd sleeps when there's no work to do */
    int	no_work_interval;
    /* We keep running until slurpd_shutdown is nonzero.  HUP signal set this */
    sig_atomic_t slurpd_shutdown;
    /* Number of replicas we're servicing */
    int num_replicas;
    /* Array of pointers to replica info */
    Ri **replicas;
    /* Directory where our replica files are written/read */
    char *slurpd_rdir;
    /* Name of slurpd status file (timestamp of last replog */
    char slurpd_status_file[ MAXPATHLEN ];
    /* Name of the replication log slapd is writing (and we are reading) */
    char slapd_replogfile[ MAXPATHLEN ];
    /* Name of local copy of replogfile we maintain */
    char slurpd_replogfile[ MAXPATHLEN ];
    /* Non-zero if we were given a replog file to process on command-line */
    int	one_shot_mode;
    /* Non-zero if we should not detach the process */
    int no_detach;
    /* Name of program */
    char *myname;
    /* Current offset into slurpd replica logfile */
    off_t srpos;
    /* mutex to serialize access to reject file */
    ldap_pvt_thread_mutex_t rej_mutex;
    /* pointer to status struct */
    St	*st;
    /* Pointer to replication queue */
    Rq *rq;
#ifdef HAVE_KERBEROS
    /* Default name of kerberos srvtab file */
    char *default_srvtab;
#endif /* HAVE_KERBEROS */
} Globals;


extern Globals *sglob;

LDAP_END_DECL

#endif /* SLURPD_GLOBALS_H */

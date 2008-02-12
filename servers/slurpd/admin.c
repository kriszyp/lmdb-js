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

/*
 * admin.c - routines for performing administrative tasks, e.g. on-the-fly
 * reconfiguration of slurpd.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/signal.h>

#include "slurp.h"
#include "globals.h"


/*
 * Eventually, do_admin will be the entry point for performing
 * administrative tasks.  General idea: put commands in a file
 * somewhere, send slurpd a USR2 signal.  The handler for
 * USR2 (this routine) reads the file and takes some action.
 *
 * For right now, this routine has been hijacked for debugging.  When
 * slurpd receives a USR2 signal, it will dump its replication 
 * queue to the disk file given by SLURPD_DUMPFILE.
 */
RETSIGTYPE
do_admin( int sig )
{
    sglob->rq->rq_dump( sglob->rq );
    (void) SIGNAL_REINSTALL( sig, do_admin );
}

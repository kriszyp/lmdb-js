/* txn.h - Header for TP support functions of the bdb2 backend */

#ifndef _BDB2_TXN_H_
#define _BDB2_TXN_H_

#include "portable.h"

#include <stdio.h>
#include <sys/stat.h>

#include <ac/dirent.h>
#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "slap.h"
#include "back-bdb2.h"



/*  the DB environment for the backend  */
DB_ENV                    bdb2i_dbEnv;


/*  variables for transaction support  */
DB_TXN                    *txnid       = NULL;
int                       txn_do_abort = 0;

u_int32_t                 txn_max_pending_log;
u_int32_t                 txn_max_pending_time;
int                       txn_dirty = 0;
ldap_pvt_thread_mutex_t   txn_dirty_mutex;

/*  defaults for checkpointing  */
#define  BDB2_TXN_CHKP_MAX_LOG     2000    /*  checkpoint every 2MB lock file
                                               (approx. 20 ADD TXNs)  */
#define  BDB2_TXN_CHKP_MAX_TIME       5    /*  checkpoint after 5 minutes */


/*  the name of the file and the record number of the NEXTID datum  */
#define NEXTID_NAME    "NEXTID"
#define NEXTID_RECNO   (db_recno_t) 1



#endif  /*  _BDB2_TXN_H_  */


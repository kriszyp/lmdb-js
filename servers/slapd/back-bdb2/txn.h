/* txn.h - Header for TP support functions of the bdb2 backend */

#ifndef _BDB2_TXN_H_
#define _BDB2_TXN_H_

#include "portable.h"

#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>

#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldapconfig.h"
#include "slap.h"
#include "back-bdb2.h"



#define  BDB2_TXN_CHKP_MAX_CNT     20                   /*  checkpoint every
                                                            20 transactions */
#define  BDB2_TXN_CHKP_MAX_TIME    600                  /*  checkpoint after
                                                            600 seconds     */


char  *bdb2i_fixed_filenames[] = {

		"dn", "dn2id", "id2entry", "id2children", "objectclass"

	};


#endif  /*  _BDB2_TXN_H_  */


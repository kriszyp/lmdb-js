/* init.c - initialize passwd backend */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "external.h"

#ifdef SLAPD_PASSWD_DYNAMIC

int back_passwd_LTX_init_module(int argc, char *argv[]) {
    BackendInfo bi;

    memset( &bi, '\0', sizeof(bi) );
    bi.bi_type = "passwd";
    bi.bi_init = passwd_back_initialize;

    backend_add(&bi);
    return 0;
}

#endif /* SLAPD_PASSWD_DYNAMIC */

int
passwd_back_initialize(
    BackendInfo	*bi
)
{
	bi->bi_open = 0;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = 0;
	bi->bi_db_config = 0;
	bi->bi_db_open = 0;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = 0;

	bi->bi_op_bind = 0;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = passwd_back_search;
	bi->bi_op_compare = 0;
	bi->bi_op_modify = 0;
	bi->bi_op_modrdn = 0;
	bi->bi_op_add = 0;
	bi->bi_op_delete = 0;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_acl_group = 0;
	bi->bi_chk_referrals = 0;

#ifdef HAVE_CYRUS_SASL
	bi->bi_sasl_authorize = 0;
	bi->bi_sasl_getsecret = 0;
	bi->bi_sasl_putsecret = 0;
#endif /* HAVE_CYRUS_SASL */

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

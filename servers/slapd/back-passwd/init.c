/* init.c - initialize passwd backend */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "external.h"

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

#ifdef SLAPD_ACLGROUPS
	bi->bi_acl_group = 0;
#endif

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

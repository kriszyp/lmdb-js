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
	bi->bi_open = NULL;
	bi->bi_config = NULL;
	bi->bi_close = NULL;
	bi->bi_destroy = NULL;

	bi->bi_db_init = NULL;
	bi->bi_db_config = NULL;
	bi->bi_db_open = NULL;
	bi->bi_db_close = NULL;
	bi->bi_db_destroy = NULL;

	bi->bi_op_bind = NULL;
	bi->bi_op_unbind = NULL;
	bi->bi_op_search = passwd_back_search;
	bi->bi_op_compare = NULL;
	bi->bi_op_modify = NULL;
	bi->bi_op_modrdn = NULL;
	bi->bi_op_add = NULL;
	bi->bi_op_delete = NULL;
	bi->bi_op_abandon = NULL;

	bi->bi_acl_group = NULL;

	return 0;
}

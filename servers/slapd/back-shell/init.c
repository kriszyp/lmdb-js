/* init.c - initialize shell backend */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "shell.h"

#ifdef SLAPD_SHELL_DYNAMIC

int back_shell_LTX_init_module(int argc, char *argv[]) {
    BackendInfo bi;

    memset( &bi, 0, sizeof(bi) );
    bi.bi_type = "shell";
    bi.bi_init = shell_back_initialize;

    backend_add(&bi);
    return 0;
}

#endif /* SLAPD_SHELL_DYNAMIC */

int
shell_back_initialize(
    BackendInfo	*bi
)
{
	bi->bi_open = 0;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = shell_back_db_init;
	bi->bi_db_config = shell_back_db_config;
	bi->bi_db_open = 0;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = shell_back_db_destroy;

	bi->bi_op_bind = shell_back_bind;
	bi->bi_op_unbind = shell_back_unbind;
	bi->bi_op_search = shell_back_search;
	bi->bi_op_compare = shell_back_compare;
	bi->bi_op_modify = shell_back_modify;
	bi->bi_op_modrdn = shell_back_modrdn;
	bi->bi_op_add = shell_back_add;
	bi->bi_op_delete = shell_back_delete;
	bi->bi_op_abandon = shell_back_abandon;

	bi->bi_acl_group = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

int
shell_back_db_init(
    Backend	*be
)
{
	struct shellinfo	*si;

	si = (struct shellinfo *) ch_calloc( 1, sizeof(struct shellinfo) );

	be->be_private = si;

	return si == NULL;
}

int
shell_back_db_destroy(
    Backend	*be
)
{
	free( be->be_private );
	return 0;
}

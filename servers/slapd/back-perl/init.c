/* $OpenLDAP$ */
/*
 *	 Copyright 1999, John C. Quillan, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"
 /* init.c - initialize shell backend */
	
#include <stdio.h>
/* #include <ac/types.h>
	#include <ac/socket.h>
*/



#include <EXTERN.h>
#include <perl.h>

#include "slap.h"
#include "perl_back.h"


LDAP_F( void )
perl_back_xs_init LDAP_P((void));
LDAP_F( void )
boot_DynaLoader LDAP_P((CV* cv));

PerlInterpreter *perl_interpreter = NULL;
ldap_pvt_thread_mutex_t	perl_interpreter_mutex;

#ifdef SLAPD_PERL_DYNAMIC

int back_perl_LTX_init_module(int argc, char *argv[]) {
    BackendInfo bi;

    memset( &bi, 0, sizeof(bi) );
    bi.bi_type = "perl";
    bi.bi_init = perl_back_initialize;

    backend_add(&bi);
    return 0;
}

#endif /* SLAPD_PERL_DYNAMIC */


/**********************************************************
 *
 * Init
 *
 **********************************************************/

int
perl_back_initialize(
	BackendInfo	*bi
)
{
	char *embedding[] = { "", "-e", "0" };

	Debug( LDAP_DEBUG_TRACE, "perl backend open\n", 0, 0, 0 );

	if( perl_interpreter != NULL ) {
		Debug( LDAP_DEBUG_ANY, "perl backend open: already opened\n",
			0, 0, 0 );
		return 1;
	}
	
	perl_interpreter = perl_alloc();
	perl_construct(perl_interpreter);
	perl_parse(perl_interpreter, perl_back_xs_init, 3, embedding, (char **)NULL);
	perl_run(perl_interpreter);

	bi->bi_open = perl_back_open;
	bi->bi_config = 0;
	bi->bi_close = perl_back_close;
	bi->bi_destroy = perl_back_destroy;

	bi->bi_db_init = perl_back_db_init;
	bi->bi_db_config = perl_back_db_config;
	bi->bi_db_open = 0;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = perl_back_db_destroy;

	bi->bi_op_bind = perl_back_bind;
	bi->bi_op_unbind = perl_back_unbind;
	bi->bi_op_search = perl_back_search;
	bi->bi_op_compare = perl_back_compare;
	bi->bi_op_modify = perl_back_modify;
	bi->bi_op_modrdn = perl_back_modrdn;
	bi->bi_op_add = perl_back_add;
	bi->bi_op_delete = perl_back_delete;
	bi->bi_op_abandon = 0;

	bi->bi_acl_group = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}
		
int
perl_back_open(
	BackendInfo	*bi
)
{
	ldap_pvt_thread_mutex_init( &perl_interpreter_mutex );
	return 0;
}

int
perl_back_db_init(
	Backend	*be
)
{
	be->be_private = (PerlBackend *) ch_malloc( sizeof(PerlBackend) );
	memset( be->be_private, 0, sizeof(PerlBackend));

	Debug( LDAP_DEBUG_TRACE, "perl backend db init\n", 0, 0, 0 );

	return 0;
}


static void
perl_back_xs_init()
{
    char *file = __FILE__;
    dXSUB_SYS;
        newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

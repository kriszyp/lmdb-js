/* $OpenLDAP$ */
#ifndef PERL_BACK_H
#define PERL_BACK_H 1

LDAP_BEGIN_DECL

/*
 * From Apache mod_perl: test for Perl version.[ja
 */
#ifdef pTHX_
#define PERL_IS_5_6
#endif

#define EVAL_BUF_SIZE 500

#ifdef pTHX_
#define PERL_IS_5_6
#endif

extern PerlInterpreter *perl_interpreter;
extern ldap_pvt_thread_mutex_t  perl_interpreter_mutex;

typedef struct perl_backend_instance {
	char	*pb_module_name;
	SV	*pb_obj_ref;
	int	pb_filter_search_results;
} PerlBackend;

LDAP_END_DECL

#include "external.h"

#endif

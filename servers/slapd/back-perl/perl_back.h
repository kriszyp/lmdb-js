/* $OpenLDAP$ */
#ifndef PERL_BACK_H
#define PERL_BACK_H 1

LDAP_BEGIN_DECL

/*
 */
#define EVAL_BUF_SIZE 500

extern PerlInterpreter *perl_interpreter;
extern ldap_pvt_thread_mutex_t  perl_interpreter_mutex;

typedef struct perl_backend_instance {
  char *pb_module_name;
  SV   *pb_obj_ref;
} PerlBackend;

LDAP_END_DECL

#include "external.h"

#endif

#ifndef _PASSWD_EXTERNAL_H
#define _PASSWD_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	passwd_back_initialize LDAP_P(( BackendInfo *bi ));

extern int  passwd_back_search LDAP_P(( BackendDB *be,
	Connection *c, Operation *o,
	char *base, int scope, int deref, int slimit, int tlimit,
	Filter *f, char *filterstr, char **attrs, int attrsonly));

extern int passwd_back_db_config LDAP_P((BackendDB *bd,
	const char *fname, int lineno, int argc, char **argv ));

LDAP_END_DECL

#endif /* _PASSWD_EXTERNAL_H */


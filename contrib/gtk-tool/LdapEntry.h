#ifdef MY_LDAP_ENTRY_H
#define MY_LDAP_ENTRY_H
#include "common.h"
#include "gtk.h"
#include <lber.h>
#include <ldap.h>

class LdapEntry {
public:
	char *dn;
	LdapEntry **children;
	LdapEntry* get_entries(LDAP *ld, char *base_dn, int level, char *filter);
	Gtk_Tree* make_tree(LdapEntry *thing);
}
#endif

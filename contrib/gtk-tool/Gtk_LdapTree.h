#ifndef GTK_LDAP_TREE_H
#define GTK_LDAP_TREE_H
#include <gtk--/tree.h>
#include "utils.h"
#include <Gtk_LdapTreeItem.h>

class Gtk_LdapTree : public Gtk_Tree {
	void show_impl();
};
#endif

#ifndef GTK_LDAPITEM_H
#define GTK_LDAPITEM_H
#include "cpluscommon.h"
#include "gtk.h"
#include <Gtk_LdapTreeItem.h>
class Gtk_LdapTreeItem;

class Gtk_LdapItem {
public:
	Gtk_Tree *tree;
	Gtk_LdapTreeItem *treeitem;
};
#endif

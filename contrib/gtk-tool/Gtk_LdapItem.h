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
	G_List<gchar> *value_list;
	char *attribute_name;
	G_List<Gtk_LdapItem> *attribute_list;
	char *entry_name;
};
#endif

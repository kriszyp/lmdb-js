#ifndef GTK_LDAPTREEITEM_H
#define GTK_LDAPTREEITEM_H
#include "gtk.h"
#include <My_Window.h>
#include <lber.h>
#include <ldap.h>
/*#include "XPMLabelBox.h"*/
#include "icons/root_node.h"
#include "icons/branch_node.h"
#include "icons/leaf_node.h"
#include "icons/general_node.h"

#define ROOT_NODE 1
#define BRANCH_NODE 2
#define LEAF_NODE 3

class My_Window;

class Gtk_LdapTreeItem : public Gtk_TreeItem {
public:
	char *dn;
	char *rdn;
	char *objectClass;
	LDAP *ld;
	LDAPMessage *result_identifier;
	My_Window *par;
	Gtk_Notebook *notebook;
	Gtk_HBox *xpm_label;
	Gtk_LdapTreeItem();
	Gtk_LdapTreeItem(char *c, My_Window *w);
	Gtk_LdapTreeItem(GtkTreeItem *t);
	~Gtk_LdapTreeItem();
	void setType(int t);
	int getDetails();
	int showDetails();
	void select_impl();
	void collapse_impl();
	void expand_impl();
};
#endif

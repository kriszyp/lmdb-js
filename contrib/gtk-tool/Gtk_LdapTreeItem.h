#ifndef GTK_LDAPTREEITEM_H
#define GTK_LDAPTREEITEM_H
#include "gtk.h"
#include <My_Window.h>
#include <lber.h>
#include <ldap.h>

class My_Window;

class Gtk_LdapTreeItem : public Gtk_TreeItem {
public:
	char *dn;
	char *rdn;
	LDAP *ld;
	LDAPMessage *result_identifier;
	My_Window *par;
	Gtk_Notebook *notebook;
	Gtk_LdapTreeItem();
	Gtk_LdapTreeItem(char *c, My_Window *w);
	Gtk_LdapTreeItem(GtkTreeItem *t);
	int search();
	void select_impl();
	void collapse_impl();
	void expand_impl();
};
#endif

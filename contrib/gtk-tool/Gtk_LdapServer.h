#ifndef GTK_LDAPSERVER_H
#define GTK_LDAPSERVER_H
#include "gtk.h"
#include <My_Window.h>
/*#include <LdapOpts.h>*/
#include <Gtk_LdapItem.h>
#include <Gtk_LdapTreeItem.h>
#include <lber.h>
#include <ldap.h>
#include "icons/local_server.h"
#include "icons/remote_server.h"

#define LOCAL_SERVER 1
#define REMOTE_SERVER 2

class My_Window;

class Gtk_LdapServer : public Gtk_TreeItem {
public:
	char *dn;
	char *hostname;
	LDAPMessage **thing;
	LDAP *ld;
	char *host;
	char *base_dn;
	int c, port;
	My_Window *par;
//	Gtk_Notebook *notebook;
	Gtk_Viewport *notebook;
	Gtk_HBox *xpm_label;
//	Gtk_Tree *subtree;
	G_List<char> *databases;
	Gtk_LdapServer();
	Gtk_LdapServer(My_Window *w, char *c, int p);
	Gtk_LdapServer(GtkTreeItem *t);
	~Gtk_LdapServer();
	void setType(int t);
	int getConfig();
	int getSubtree();
	int getDetails();
	int showDetails();
	void select_impl();
	void collapse_impl();
	void expand_impl();
};
#endif

#ifndef GTK_LDAPSERVER_H
#define GTK_LDAPSERVER_H
#include "gtk.h"
#include "utils.h"
#include <My_Window.h>
#include <Gtk_LdapTree.h>
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
	Gtk_Frame *notebook;
	Gtk_HBox *xpm_label;
//	Gtk_Tree *subtree;
	Gtk_Menu *popup;
	GList *databases;
	Gtk_LdapServer();
	Gtk_LdapServer(My_Window *w, char *c, int p);
	Gtk_LdapServer(GtkTreeItem *t);
	~Gtk_LdapServer();
	void setType(int t);
	int getMonitor();
	int getConfig();
	Gtk_Tree* getSubtree();
#ifndef LDAP_GET_OPT
	char* getOptDescription(int option);
	int getOptType(int option);
#endif
	int getOptions();
	int showDetails();
//	void show_impl();
	void select_impl();
	void collapse_impl();
	void expand_impl();
};
#endif

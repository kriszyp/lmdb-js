#ifndef GTK_LDAPTREEITEM_H
#define GTK_LDAPTREEITEM_H
#include "gtk.h"
#include "utils.h"
#include <My_Window.h>
#include <Gtk_LdapTree.h>
#include <lber.h>
#include <ldap.h>
#include "icons/root_node.h"
#include "icons/branch_node.h"
#include "icons/leaf_node.h"
#include "icons/alias_node.h"
#include "icons/rfc822mailgroup_node.h"
#include "icons/general_node.h"
#include "icons/monitor.h"

#define ROOT_NODE 1
#define BRANCH_NODE 2
#define LEAF_NODE 3

class My_Window;
class Gtk_LdapTree;

class Gtk_LdapTreeItem : public Gtk_TreeItem {
public:
	char *dn;
	char *rdn;
	char *objectClass;
	char *aliasedObjectName;
	LDAP *ld;
	LDAPMessage *result_identifier;
	My_Window *par;
	Gtk_Notebook *notebook;
	Gtk_HBox *xpm_label;
	Gtk_Menu *menu;
	enum
	{
		TARGET_STRING,
		TARGET_ROOTWIN,
		TARGET_URL
	};
	bool have_drag;

	//Functions
	Gtk_LdapTreeItem();
	Gtk_LdapTreeItem(char *c, My_Window *w, LDAP *ld);
	Gtk_LdapTreeItem(GtkTreeItem *t);
	~Gtk_LdapTreeItem();
	void setDnd();
	gchar* getAttribute(char *c);
	Gtk_LdapTree* getSubtree(LDAP *ld, int i);
	void setType(int t);
	int getDetails();
	void createPopupMenu();
	int showDetails();
//	void show_impl();
//	void select_impl();
	void collapse_impl();
	void expand_impl();
	void click();
//	gint button_press_event_impl(GdkEventButton *p0);
	void item_drag_data_received (GdkDragContext *context,
				gint x, gint y, GtkSelectionData *data,
				guint info, guint32 time);
	gboolean target_drag_drop ( GdkDragContext *context,
				gint x, gint y, guint time);

	void source_drag_data_get(GdkDragContext *context,
                               GtkSelectionData *selection_data,
                               guint info, guint32 time);
	void source_drag_data_delete(GdkDragContext *context);
	void target_drag_leave(GdkDragContext *context, guint time);
};

static GtkTargetEntry target_table[] = {
	{ "STRING",     0, Gtk_LdapTreeItem::TARGET_STRING },
	{ "text/plain", 0, Gtk_LdapTreeItem::TARGET_STRING },
	{ "text/uri-list", 0, Gtk_LdapTreeItem::TARGET_URL },
	{ "application/x-rootwin-drop", 0, Gtk_LdapTreeItem::TARGET_ROOTWIN }
};

static guint n_targets = sizeof(target_table) / sizeof(target_table[0]);
#endif

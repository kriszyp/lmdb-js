#ifndef MY_WINDOW_H
#define MY_WINDOW_H
#include "cpluscommon.h"
#include "gtk.h"
#include <lber.h>
#include <ldap.h>
/*#include "My_Scroller.h"*/
#include "Gtk_LdapItem.h"
#include "Gtk_LdapTreeItem.h"
class Gtk_LdapTreeItem;
class Gtk_LdapItem;
class My_Scroller;

class My_Window : public Gtk_Window {
public:
	Gtk_ScrolledWindow *scroller, *scroller2;
	Gtk_Viewport *viewport;
//	My_Scroller *scroller2;
	Gtk_Entry *urlfield;
	Gtk_Button *display_button;
	Gtk_Paned *pane;
	Gtk_MenuBar *menubar;
	My_Window(GtkWindowType t);
	~My_Window();
	void do_display();
	void expand(Gtk_TreeItem *t);
	gint delete_event_impl(GdkEventAny *);
	Gtk_LdapItem* make_tree(My_Window *p, LDAP* l_i, char* b_d);
};
#endif

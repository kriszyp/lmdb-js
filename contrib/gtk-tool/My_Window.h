#ifndef MY_WINDOW_H
#define MY_WINDOW_H
#include "cpluscommon.h"
#include "gtk.h"
#include "Gtk_LdapServer.h"
#include "Gtk_LdapTreeItem.h"

extern int debug_level;

class My_Window : public Gtk_Window {
public:
	Gtk_ScrolledWindow *scroller, *scroller2;
	Gtk_Viewport *viewport, *viewport2;
	Gtk_Entry *urlfield;
	Gtk_Button *display_button;
	Gtk_InputDialog *dialog;
	Gtk_Paned *pane;
	Gtk_MenuBar *menubar;
//	Gtk_ProgressBar *progress;
	Gtk_Statusbar *status;
	My_Window(GtkWindowType t);
	~My_Window();
	int debug(const char *c,...);
	void do_display();
	void addServer();
	void getHost();
	void setDebug();
	gint delete_event_impl(GdkEventAny *);
};
#endif

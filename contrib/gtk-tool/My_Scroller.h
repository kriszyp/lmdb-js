#ifndef MY_SCROLLER_H
#define MY_SCROLLER_H
#include <gtk--/container.h>
#include "gtk.h"

class My_Scroller : public Gtk_ScrolledWindow {
public:
	Gtk_Widget *children[2];
	void add_child(Gtk_Widget *w);
	void remove_child(int i);
};
#endif

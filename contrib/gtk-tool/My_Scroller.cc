#include "My_Scroller.h"

#include <gtk--/container.h>

void My_Scroller::remove_child(int i) {
//	cout << "Unparenting child[" << i << "]" << endl;
//	this->children[i]->unparent();
	cout << "Deleting child[" << i << "] from children" << endl;
//	this->remove(children()->first());
//	delete this->children[i];
	this->remove_c(this->children[i]->gtkobj());
	gtk_widget_destroy(this->children[i]->gtkobj());
	cout << "done" << endl;
}
void My_Scroller::add_child(Gtk_Widget *w) {
	cout << "My_Scroller::add_child()" << endl;
//	w->reparent(this);
	this->add(w);
	cout << "done" << endl;
	this->children[0] = w;
}

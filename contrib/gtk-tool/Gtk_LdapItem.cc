#include "Gtk_LdapItem.h"

Gtk_LdapItem::Gtk_LdapItem() : Gtk_TreeItem() {
	cout << "Gtk_LdapItem()" << endl;
}

Gtk_LdapItem::Gtk_LdapItem(char *c) : Gtk_TreeItem() {
	cout << "Gtk_LdapItem(" << c << ")" << endl;
	this->dn = c;
}

Gtk_LdapItem::Gtk_LdapItem(Gtk_TreeItem *item) : Gtk_TreeItem(*item) {
	cout << "Gtk_LdapItem(*item)" << endl;	
}

Gtk_LdapItem::Gtk_LdapItem(Gtk_TreeItem &item) : Gtk_TreeItem(item) {
	cout << "Gtk_LdapItem(&item)" << endl;	
}

void Gtk_LdapItem::expand_impl() {
	cout << this->dn << " expanded" << endl;
}

void Gtk_LdapItem::collapse_impl() {
	cout << this->dn << " collapsed" << endl;
}

void Gtk_LdapItem::select_impl() {
	cout << this->dn << " selected" << endl;
}

void Gtk_LdapItem::deselect_impl() {
	cout << this->dn << " deselected" << endl;
}

void Gtk_LdapItem::toggle_impl() {
	cout << this->dn << " toggled" << endl;
}

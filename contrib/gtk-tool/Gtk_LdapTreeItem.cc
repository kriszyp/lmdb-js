#include "Gtk_LdapTreeItem.h"

Gtk_LdapTreeItem::Gtk_LdapTreeItem() : Gtk_TreeItem() {
}
Gtk_LdapTreeItem::Gtk_LdapTreeItem(char *c, My_Window *w) : Gtk_TreeItem(c) {
	this->rdn = c;
	this->par = w;
}
Gtk_LdapTreeItem::Gtk_LdapTreeItem(GtkTreeItem *t) : Gtk_TreeItem(t) {
}
int Gtk_LdapTreeItem::search() {
	int error, entriesCount;
	BerElement *ber;
	LDAPMessage *entry;
	char *attribute, **values;
	Gtk_CList *table;
	Gtk_Label *label;
	GList *child_list;
	Gtk_Notebook *g;
	if (this->notebook != NULL) {
		if (par->scroller2->children != NULL) {
			par->scroller2->remove_child(0);
		}
		par->scroller2->add_child(this->notebook);	
	//	par->scroller2->remove((Gtk_Object)par->scroller2->children()->first());
		this->notebook->reparent(*par->scroller2);
		this->notebook->show();
		par->scroller2->show();
		return 0;
	}
	error = ldap_search_s(this->ld, this->dn, LDAP_SCOPE_BASE, "objectclass=*", NULL, 0, &result_identifier);
	entriesCount = ldap_count_entries(ld, result_identifier);
	if (entriesCount == 0) return 0;
	notebook = new Gtk_Notebook();
	notebook->set_tab_pos(GTK_POS_LEFT);
	gchar *titles[] = { "values" };
	
	for (entry = ldap_first_entry(ld, result_identifier); entry != NULL; entry = ldap_next_entry(ld, result_identifier)) {
		for (attribute = ldap_first_attribute(ld, entry, &ber); attribute != NULL; attribute = ldap_next_attribute(ld, entry, ber)) {
			table = new Gtk_CList(1, titles);
			values = ldap_get_values(ld, entry, attribute);
			for (int i=0; i<ldap_count_values(values); i++) {
				gchar *t[] = { values[i] };
				table->append(t);
			}
			ldap_value_free(values);
			label = new Gtk_Label(attribute);
			notebook->append_page(*table, *label);
			table->show();
			label->show();
		}
	}
	if (par->scroller2 != NULL) {
		cout << "Scroller2 exists" << endl;
		if (par->scroller2->children[0] != NULL) {
			cout << "There are children in scroller2" << endl;
			par->scroller2->remove_child(0);
		}
		par->scroller2->add_child(this->notebook);
		this->notebook->show();
		par->scroller2->show();
	}
	return 0;
}
void Gtk_LdapTreeItem::select_impl() {
//	cout << this->dn << " selected" << endl;
//	gtk_item_select(GTK_ITEM(GTK_TREE_ITEM(this->gtkobj())));
	Gtk_c_signals_Item *sig=(Gtk_c_signals_Item *)internal_getsignalbase();
	if (!sig->select) return;
	sig->select(GTK_ITEM(gtkobj()));
	this->search();
}
void Gtk_LdapTreeItem::collapse_impl() {
	cout << this->dn << " collapsed" << endl;
	Gtk_c_signals_TreeItem *sig=(Gtk_c_signals_TreeItem *)internal_getsignalbase();
	if (!sig->collapse) return;
	sig->collapse(GTK_TREE_ITEM(gtkobj()));
//	gtk_widget_hide(GTK_WIDGET(GTK_TREE(GTK_TREE_ITEM (this->gtkobj())->subtree)));
}
void Gtk_LdapTreeItem::expand_impl() {
	Gtk_c_signals_TreeItem *sig=(Gtk_c_signals_TreeItem *)internal_getsignalbase();
	if (!sig->expand) return;
	sig->expand(GTK_TREE_ITEM(gtkobj()));
//	Gtk_Tree *t;
//	t = new Gtk_Tree(GTK_TREE(GTK_TREE_ITEM(this->gtkobj())->subtree));
//	bool vis = t->visible();
//	if (vis == false) {
//		gtk_widget_show(GTK_WIDGET(GTK_TREE(GTK_TREE_ITEM (this->gtkobj())->subtree)));
//		cout << this->dn << " expanded" << endl;
//	}
//	else {
//		gtk_widget_hide(GTK_WIDGET(GTK_TREE(GTK_TREE_ITEM (this->gtkobj())->subtree)));
//		cout << this->dn << " collapsed" << endl;
//	}
}

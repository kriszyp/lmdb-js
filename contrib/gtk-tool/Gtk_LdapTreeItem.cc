#include "Gtk_LdapTreeItem.h"
#include <gtk--/base.h>

Gtk_LdapTreeItem::Gtk_LdapTreeItem() : Gtk_TreeItem() {
}

Gtk_LdapTreeItem::Gtk_LdapTreeItem(char *c, My_Window *w) : Gtk_TreeItem() {
	this->rdn = c;
	this->par = w;
}

Gtk_LdapTreeItem::Gtk_LdapTreeItem(GtkTreeItem *t) : Gtk_TreeItem(t) {
}

void Gtk_LdapTreeItem::setType(int t) {
//	printf("Gtk_LdapTreeItem::setType(%d)\n", t);
	Gtk_Pixmap *xpm_icon;
	Gtk_Label *label;
	if (this->getchild() != NULL) {
	//	printf("There's a label in here - removing");
		xpm_label = new Gtk_HBox(GTK_HBOX(this->getchild()->gtkobj()));
		xpm_label->remove_c(xpm_label->children()->nth_data(0));
		xpm_label->remove_c(xpm_label->children()->nth_data(0));
	//	xpm_label->remove_c(GTK_WIDGET(xpm_icon->gtkobj()));
	//	printf("done\n");
	}
	else xpm_label = new Gtk_HBox();
	switch (t) {
		case 1: xpm_icon = new Gtk_Pixmap(*xpm_label, "root_node.xpm"); break;
		case 2: xpm_icon = new Gtk_Pixmap(*xpm_label, "branch_node.xpm"); break;
		default: xpm_icon = new Gtk_Pixmap(*xpm_label, "leaf_node.xpm"); break;
	}
	label = new Gtk_Label(this->rdn);
	xpm_label->pack_start(*xpm_icon, false, false, 1);
	xpm_label->pack_start(*label, false, false, 1);
	xpm_icon->show();
	label->show();
	xpm_label->show();
	if (this->getchild() == NULL) this->add(xpm_label);
	else printf("There's still a child here!\n");
}

int Gtk_LdapTreeItem::getDetails() {
	int error, entriesCount;
	BerElement *ber;
	LDAPMessage *entry;
	char *attribute, **values;
	Gtk_CList *table;
	Gtk_Label *label;
	GList *child_list;
	Gtk_Notebook *g;
	Gtk_Viewport *viewport;
	viewport = new Gtk_Viewport();
	if (this->notebook != NULL) {
		printf("Data on %s available\n", this->rdn);
		if (par->viewport->getchild() != NULL) {
			par->viewport->remove_c(par->viewport->getchild()->gtkobj());
		}
		par->viewport->add(this->notebook);
		this->notebook->show();
		par->viewport->show();
	//	par->scroller2->show();
		return 0;
	}
	error = ldap_search_s(this->ld, this->dn, LDAP_SCOPE_BASE, "objectclass=*", NULL, 0, &result_identifier);
	entriesCount = ldap_count_entries(ld, result_identifier);
	if (entriesCount == 0) return 0;
	notebook = new Gtk_Notebook();
	notebook->set_tab_pos(GTK_POS_LEFT);
	const gchar *titles[] = { "values" };
	
	for (entry = ldap_first_entry(ld, result_identifier); entry != NULL; entry = ldap_next_entry(ld, result_identifier)) {
		for (attribute = ldap_first_attribute(ld, entry, &ber); attribute != NULL; attribute = ldap_next_attribute(ld, entry, ber)) {
			table = new Gtk_CList(1, titles);
			values = ldap_get_values(ld, entry, attribute);
			for (int i=0; i<ldap_count_values(values); i++) {
				const gchar *t[] = { values[i] };
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
		if (par->viewport->getchild() != NULL) {
			par->viewport->remove_c(par->viewport->getchild()->gtkobj());
		}
		par->viewport->add(this->notebook);
		this->notebook->show();
		par->viewport->show();
	//	par->scroller2->show();
		cout << "Added details for " << this->rdn << endl;
	}
	return 0;
}
void Gtk_LdapTreeItem::select_impl() {
//	cout << this->dn << " selected" << endl;
//	gtk_item_select(GTK_ITEM(GTK_TREE_ITEM(this->gtkobj())));
	Gtk_c_signals_Item *sig=(Gtk_c_signals_Item *)internal_getsignalbase();
	if (!sig->select) return;
	sig->select(GTK_ITEM(gtkobj()));
	this->getDetails();
}

void Gtk_LdapTreeItem::collapse_impl() {
//	cout << this->dn << " collapsed" << endl;
	Gtk_c_signals_TreeItem *sig=(Gtk_c_signals_TreeItem *)internal_getsignalbase();
	if (!sig->collapse) return;
	sig->collapse(GTK_TREE_ITEM(gtkobj()));
//	gtk_widget_hide(GTK_WIDGET(GTK_TREE(GTK_TREE_ITEM (this->gtkobj())->subtree)));
}

void Gtk_LdapTreeItem::expand_impl() {
//	cout << this->dn << " expanded" << endl;
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

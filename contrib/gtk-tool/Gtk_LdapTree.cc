#include <Gtk_LdapTree.h>

void Gtk_LdapTree::show_impl() {
	cout << "tree show" << endl;
	Gtk_LdapTree *tree;
	Gtk_LdapTreeItem *item;
	Gtk_LdapTree::selectioniterator i;
	debug("iterator\n");
	for (i=this->begin(); i!=this->end();i++) {
		item = (Gtk_LdapTreeItem *)GTK_TREE_ITEM((*i));
		debug("#%s#\n", item->dn);
		tree = item->getSubtree(item->ld, 1);
		if (tree != NULL) item->set_subtree(*tree);
	}
	debug("done\n");
	Gtk_c_signals_Tree *sig=(Gtk_c_signals_Tree *)internal_getsignalbase();	
	sig->show(GTK_WIDGET(gtkobj()));
}

#include <Gtk_LdapTree.h>

void Gtk_LdapTree::show_impl() {
	debug("tree show\n");
	Gtk_LdapTree *tree = NULL;
	Gtk_LdapTreeItem *item = NULL;
	Gtk_LdapTree::iterator i;
	debug("iterator\n");
	for (i=this->begin(); i!=this->end();i++) {
	//	item = (Gtk_LdapTreeItem *)GTK_TREE_ITEM((*i));
		item = (Gtk_LdapTreeItem *)(*i);
		debug("#%s#\n", item->dn);
		if (item->get_subtree() == NULL) {
			debug("ding!\n");
			tree = item->getSubtree(item->ld, 1);
			if (tree != NULL) item->set_subtree(*tree);
		}
	}
	debug("done\n");
	Gtk_Tree::show_impl();
}

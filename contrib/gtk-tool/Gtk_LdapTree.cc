#include <Gtk_LdapTree.h>

void Gtk_LdapTree::show_impl() {
	debug("Gtk_LdapTree::show_impl()\n");
	Gtk_LdapTree *tree;
	Gtk_LdapTreeItem *item = NULL;
	Gtk_LdapTree::ItemList &items = this->tree();
	Gtk_LdapTree::ItemList::iterator i = items.begin();
	debug("iterator\n");
	for (i=items.begin(); i!=items.end();i++) {
		item = (Gtk_LdapTreeItem *)(*i);
		debug("new item\n");
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

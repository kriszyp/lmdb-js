#include "cpluscommon.h"
#include "gtk.h"
#include <lber.h>
#include <ldap.h>
#include <My_Window.h>
#include <Gtk_LdapItem.h>
#include <Gtk_LdapTreeItem.h>

int main(int argc, char **argv) {
	My_Window *window;
	Gtk_LdapItem *treeresult;
	Gtk_Tree *tree, *subtree;
	Gtk_LdapTreeItem *treeitem;
	LDAPMessage **thing;
	LDAP *ld;
	char *base_dn;

	Gtk_Main m(&argc, &argv);

	window = new My_Window(GTK_WINDOW_TOPLEVEL);

	if ((ld = ldap_open("localhost", LDAP_PORT))==NULL) {
		perror("connection");
	}

	tree = new Gtk_Tree();
	base_dn = "o=University of Michigan, c=US";
	treeresult = window->make_tree(window, ld, base_dn);
	treeitem = new Gtk_LdapTreeItem(*treeresult->treeitem);
	tree->append(treeitem);
	if (treeresult->tree != NULL) {
		subtree = new Gtk_Tree(*treeresult->tree);
		printf("inserting %s into root\n", base_dn);
		treeitem->set_subtree(subtree);
	}
	treeitem->show();
	window->scroller->add(tree);
	tree->show();
	window->scroller->show();
	treeitem->search();
	window->set_title("Hello");
	window->activate();

	window->set_usize(450, 450);

	window->show();

	m.run();
	return 0;
}

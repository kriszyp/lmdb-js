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
	char *host = NULL;
	char *base_dn = NULL;
	int c, port = 0;

	while ((c = getopt(argc, argv, "b:s:p:h")) != -1) {
		switch (c) {
			case 'b':
				base_dn = optarg; break;
			case 's':
				host = strdup(optarg); break;
			case 'p':
				port = atoi(optarg); break;
			case 'h':
	                default:
				fprintf(stderr, "Usage: %s [-s server] [-p port] [-b base_dn]\n", argv[0]);
				exit(-1);
		}
	}

	if (base_dn == NULL) base_dn = "o=University of Michigan, c=US";
	if (host == NULL) host = "localhost";
	if (port == 0) port = LDAP_PORT;

	Gtk_Main m(&argc, &argv);

	window = new My_Window(GTK_WINDOW_TOPLEVEL);

	if ((ld = ldap_open(host, port)) == NULL) {
		perror("connection");
	}

	tree = new Gtk_Tree();
	treeresult = window->make_tree(window, ld, base_dn);
	treeitem = new Gtk_LdapTreeItem(*treeresult->treeitem);
	tree->append(treeitem);
	if (treeresult->tree != NULL) {
		subtree = new Gtk_Tree(*treeresult->tree);
		printf("inserting %s into root\n", base_dn);
		treeitem->set_subtree(*subtree);
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

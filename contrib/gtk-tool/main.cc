#include "cpluscommon.h"
#include "gtk.h"
#include <lber.h>
#include <ldap.h>
#include <My_Window.h>
#include <Gtk_LdapItem.h>
#include <Gtk_LdapServer.h>

int main(int argc, char **argv) {
	My_Window *window;
	Gtk_LdapItem *treeresult;
	Gtk_Tree *tree, *subtree;
	Gtk_Tree *machine, *machinetree;
	Gtk_LdapServer *treeitem;
	Gtk_Viewport *viewport;
	char *host = NULL, *prt = NULL;
	char *base_dn = NULL;
	int c, port = 0;
	G_List<char> *hosts;
	int host_count = 0;
	char *pair[2];

	hosts = new G_List<char>();
	while ((c = getopt(argc, argv, "s:p:h")) != -1) {
		switch (c) {
			case 's':
			cout << "host" << endl;
				hosts = hosts->append(strdup(optarg));
				break;
			case 'p':
				port = atoi(optarg); break;
			case 'h':
	                default:
				fprintf(stderr, "Usage: %s ([-s server[:port]])*\n", argv[0]);
				exit(-1);
		}
	}
	cout << hosts->length() << "hosts" << endl;
	for (int f=0; f<hosts->length(); f++) {
		debug("%s\n", hosts->nth_data(f));
	}
	if (hosts->length() == 0) {
		ldap_get_option(NULL, LDAP_OPT_HOST_NAME, host);
		hosts = hosts->append(host);
	}	
	if (port == 0) port = LDAP_PORT;

	Gtk_Main m(&argc, &argv);

	window = new My_Window(GTK_WINDOW_TOPLEVEL);

	tree = new Gtk_Tree();
	for (int f=0; f<hosts->length(); f++) {
		host = strtok(hosts->nth_data(f), ":");
		prt = strtok(NULL, "\0");
		if (prt != NULL) port = atoi(prt);
		else port = LDAP_PORT;
		treeitem = new Gtk_LdapServer(window, host, port);
		subtree = treeitem->getSubtree();
		tree->append(*treeitem);
		treeitem->set_subtree(*subtree);
		treeitem->show();
	}
	viewport = new Gtk_Viewport();
	viewport->add(tree);
	window->scroller->add(viewport);
	tree->show();
	viewport->show();
	window->scroller->show();
//	treeitem->showDetails();
//	treeitem->select();
	window->set_title("gtk-tool");
	window->activate();
	window->set_usize(600, 500);
	window->show();

	m.run();
	return 0;
}

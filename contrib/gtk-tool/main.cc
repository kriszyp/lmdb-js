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
			debug("host\n");
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
	debug("%i hosts\n", hosts->length());
	for (int f=0; f<hosts->length(); f++) {
		debug("%s\n", hosts->nth_data(f));
	}
	if (hosts->length() == 0) {
#ifdef LDAP_GET_OPT
		printf("Supply me with a host please (hint: use -s\n");
		exit(0);
#else
		ldap_get_option(NULL, LDAP_OPT_HOST_NAME, host);
		hosts = hosts->append(host);
#endif /* LDAP_GET_OPT */
	}	
	if (port == 0) port = LDAP_PORT;

	Gtk_Main m(&argc, &argv);

	window = new My_Window(GTK_WINDOW_TOPLEVEL);

//	viewport = new Gtk_Viewport();
	if (hosts!=NULL) {
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
		window->viewport->add(tree);
		tree->show();
	}

//	window->scroller->add(viewport);
	window->viewport->show();
	window->scroller->show();

	window->set_title("gtk-tool");
	window->activate();
	window->set_usize(600, 500);
	window->show();

	m.run();
	return 0;
}

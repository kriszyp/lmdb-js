#include <My_Window.h>

My_Window::My_Window(GtkWindowType t) : Gtk_Window(t) {
	cout << "My_Window(t)" << endl;
	Gtk_VBox *main_hbox;
	Gtk_HBox *top_hbox;
	Gtk_Menu *menu;
	Gtk_MenuItem *file_menu, *menuitem;

	pane = new Gtk_HPaned();
	this->scroller = new Gtk_ScrolledWindow();
	this->scroller->set_policy(GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
//	this->scroller->set_usize(this->height(), 400);
	pane->add1(*this->scroller);
	this->scroller->show();

//	this->scroller2 = new My_Scroller();
	this->scroller2 = new Gtk_ScrolledWindow();
	this->viewport = new Gtk_Viewport();
	this->scroller2->set_policy(GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	this->scroller2->add(*this->viewport);
	pane->add2(*this->scroller2);	
	this->scroller2->show();

	top_hbox = new Gtk_HBox();
	menu = new Gtk_Menu();
	menuitem = new Gtk_MenuItem("Quit");
	menu->append(*menuitem);
	this->menubar = new Gtk_MenuBar();
	file_menu = new Gtk_MenuItem("File");
	file_menu->set_submenu(menu);
	this->menubar->append(*file_menu);
	menuitem->show();
	menu->show();
	file_menu->show();
//	top_hbox->pack_start(*this->menubar, TRUE, TRUE, 1);
	this->menubar->show();
	this->urlfield = new Gtk_Entry();
	top_hbox->pack_start(*this->urlfield, TRUE, TRUE, 1);
	this->urlfield->show();
	this->display_button = new Gtk_Button("Display");
	connect_to_method(this->display_button->clicked, this, &do_display);
	top_hbox->pack_end(*this->display_button, FALSE, FALSE, 1);
	this->display_button->show();

	main_hbox = new Gtk_VBox();
	main_hbox->pack_start(*this->menubar, FALSE, FALSE, 1);
	main_hbox->pack_start(*top_hbox, FALSE, TRUE, 1);
	main_hbox->pack_end(*pane, TRUE, TRUE, 1);
	top_hbox->show();
	pane->show();
	this->add(main_hbox);
	main_hbox->show();
}

My_Window::~My_Window() {
	cout << "~My_Window()" << endl;
	delete this;
}

void My_Window::do_display() {
	cout << this->urlfield->get_text() << endl;
}
void My_Window::expand(Gtk_TreeItem *t) {
	gchar *name;
	GtkLabel *label;
	label = GTK_LABEL (GTK_BIN (t->gtkobj())->child);
	gtk_label_get (label, &name);
	g_print("%s selected\n", name);
}

gint My_Window::delete_event_impl(GdkEventAny*) {
	Gtk_Main::instance()->quit();
	return 0;
}

Gtk_LdapItem* My_Window::make_tree(My_Window *p, LDAP* l_i, char* b_d) {
//	printf("make_tree(%s)\n", b_d);
	Gtk_LdapItem *treeresult, *subtreeresult;
	Gtk_Tree *tree, *subtree, *subsubtree;
	Gtk_LdapTreeItem *treeitem, *subtreeitem;
	LDAPMessage *r_i, *entry;
	gchar *c;
	char **s;
	char *c_num;
	int entriesCount = 0;
	int error;
	int r_e_i;

	error = ldap_search_s(l_i, b_d, LDAP_SCOPE_ONELEVEL, "objectclass=*", NULL, 0, &r_i);
//	printf("%s\n", ldap_err2string(error));
	entriesCount = ldap_count_entries(l_i, r_i);
//	printf("%i results\n", entriesCount);
	s = ldap_explode_dn(b_d, 1);
	c = g_strdup_printf("%s", s[0]);
	treeitem = new Gtk_LdapTreeItem(c, p);
	treeitem->dn = b_d; treeitem->ld = l_i;
	treeresult = new Gtk_LdapItem();
	treeitem->getDetails();
	if (entriesCount == 0) { 
	//	treeitem->setType(LEAF_NODE);
		treeresult->treeitem = new Gtk_LdapTreeItem(*treeitem);
		treeresult->tree = NULL;
		return treeresult;
	}
	subtree = new Gtk_Tree();
	subtree->set_selection_mode(GTK_SELECTION_BROWSE);
	subtree->set_view_mode(GTK_TREE_VIEW_ITEM);
	subtree->set_view_lines(false);
	entry = ldap_first_entry(l_i, r_i);
	while (entry != NULL) {
		s = ldap_explode_dn(ldap_get_dn(l_i, entry), 1);
		subtreeresult = make_tree(p, l_i, ldap_get_dn(l_i, entry));
		subtreeitem = new Gtk_LdapTreeItem(*subtreeresult->treeitem);
	//	printf("inserting %s into %s", s[0], c);
		subtree->append(*subtreeitem);
		if (subtreeresult->tree != NULL) {
	//		printf(".");
			subsubtree = new Gtk_Tree(*subtreeresult->tree);
	//		printf(".");
			subtreeitem->set_subtree(*subsubtree);
	//		printf(".");
		}
		subtreeitem->show();
	//	printf("\n");
		entry = ldap_next_entry(l_i, entry);
	}
//	treeitem->setType(BRANCH_NODE);
	treeresult->treeitem = new Gtk_LdapTreeItem(*treeitem);
	treeresult->tree = new Gtk_Tree(*subtree);
	return treeresult;
}

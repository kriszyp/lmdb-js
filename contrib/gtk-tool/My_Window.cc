#include <My_Window.h>

My_Window::My_Window(GtkWindowType t) : Gtk_Window(t) {
	debug("My_Window(t)\n");
	Gtk_VBox *main_hbox;
	Gtk_HBox *top_hbox;
	Gtk_VBox *bottom_hbox;
	Gtk_Menu *menu;
	Gtk_MenuItem *file_menu, *menuitem;

	pane = new Gtk_HPaned();
	this->scroller = new Gtk_ScrolledWindow();
	this->viewport = new Gtk_Viewport();
	this->scroller->set_policy(GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	this->scroller->add(*this->viewport);
	pane->add1(*this->scroller);
	this->scroller->show();
	this->viewport->show();

	this->scroller2 = new Gtk_ScrolledWindow();
	this->viewport2 = new Gtk_Viewport();
	this->scroller2->set_policy(GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	this->scroller2->add(*this->viewport2);
	pane->add2(*this->scroller2);	
	this->scroller2->show();
	this->viewport2->show();

	top_hbox = new Gtk_HBox();
	menu = new Gtk_Menu();
	menuitem = new Gtk_MenuItem("Quit");
	menu->append(*menuitem);
	this->menubar = new Gtk_MenuBar();
	file_menu = new Gtk_MenuItem("File");
	file_menu->set_submenu(*menu);
	this->menubar->append(*file_menu);
	menuitem->show();
	menu->show();
	file_menu->show();
//	top_hbox->pack_start(*this->menubar, TRUE, TRUE, 1);
	this->menubar->show();
	this->urlfield = new Gtk_Entry();
	top_hbox->pack_start(*this->urlfield, TRUE, TRUE, 1);
	this->urlfield->show();
	this->display_button = new Gtk_Button("Query Server");
	connect_to_method(this->display_button->clicked, this, &getHost);
	top_hbox->pack_end(*this->display_button, FALSE, FALSE, 1);
	this->display_button->show();

	this->status = new Gtk_Statusbar();

	bottom_hbox = new Gtk_VBox();
	bottom_hbox->pack_start(*pane, TRUE, TRUE, 1);
	bottom_hbox->pack_end(*status, FALSE, TRUE, 1);
	pane->show();
	status->show();

	main_hbox = new Gtk_VBox();
	main_hbox->pack_start(*this->menubar, FALSE, FALSE, 1);
	main_hbox->pack_start(*top_hbox, FALSE, TRUE, 1);
	main_hbox->pack_end(*bottom_hbox, TRUE, TRUE, 1);
	top_hbox->show();
	bottom_hbox->show();
	this->add(main_hbox);
	main_hbox->show();
}

My_Window::~My_Window() {
	cout << "~My_Window()" << endl;
	delete this;
}

int My_Window::debug(const char *format,...) {
#ifdef DEBUG
	va_list args;
	int ret;
	char *c;
	char buff[50];
	unsigned int m_context_id;
	va_start(args, format);
	ret = vprintf(format, args);
/*	if (this->status != NULL) {
		m_context_id = this->status->get_context_id("gtk-tool");
		ret = vsprintf(c, format, args);
		g_snprintf(buff, 50, "Action: %s", c);
		this->status->push(m_context_id, buff);
	}
*/	va_end(args);
	return ret;
#endif
}

void My_Window::do_display() {
	cout << this->urlfield->get_text() << endl;
}

void My_Window::getHost() {
	debug("My_Window::getHost()\n");
	Gtk_Tree *tree, *subtree;
	Gtk_LdapServer *treeitem;
	char *host, *prt;
	int port;

//	viewport = (Gtk_Viewport *) GTK_VIEWPORT(this->scroller->children()->nth_data(1));
//	viewport = (Gtk_Viewport *)this->scroller->children()->nth_data(1);
	if (this->viewport->get_child()!=NULL) {
		tree = (Gtk_Tree *)(this->viewport->get_child());
	}
	else {
		tree = new Gtk_Tree();
	}
	string thing;
	thing = this->urlfield->get_text();
	gchar **c;
	c = g_strsplit(thing.c_str(), ":", 2);
	host = c[0];
	prt = c[1]; //strtok(NULL, "\0");
	if (prt != NULL) port = atoi(prt);
	else port = LDAP_PORT;
	treeitem = new Gtk_LdapServer(this, host, port);
	subtree = treeitem->getSubtree();
	tree->append(*treeitem);
	treeitem->set_subtree(*subtree);
	treeitem->show();
	this->viewport->add(tree);
	tree->show();
	this->viewport->show();
	this->scroller->show();
}

gint My_Window::delete_event_impl(GdkEventAny*) {
	Gtk_Main::instance()->quit();
	return 0;
}

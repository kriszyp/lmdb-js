#include "Gtk_LdapTreeItem.h"

Gtk_LdapTreeItem::Gtk_LdapTreeItem() : Gtk_TreeItem() {
	this->objectClass = NULL;
}

Gtk_LdapTreeItem::Gtk_LdapTreeItem(char *c, My_Window *w, LDAP *ld) : Gtk_TreeItem() {
	debug("Gtk_LdapTreeItem::Gtk_LdapTreeItem(%s)\n", c);
	char **s;
	this->dn = c;
	s = ldap_explode_dn(this->dn, 1);
	this->rdn = g_strdup_printf("%s", s[0]);
	this->par = w;
	this->ld = ld;
	this->objectClass = NULL;
	this->getDetails();
	this->createPopupMenu();
}

void Gtk_LdapTreeItem::setDnd() {
	debug("Gtk_LdapTreeItem::setDnd()\n");
	this->set_events(get_events()|GDK_ALL_EVENTS_MASK);
	this->drag_dest_set(GTK_DEST_DEFAULT_ALL, target_table, n_targets, static_cast <GdkDragAction> (GDK_ACTION_COPY|GDK_ACTION_MOVE));
	this->drag_data_received.connect(slot(this, &(Gtk_LdapTreeItem::item_drag_data_received)));
	this->drag_drop.connect(slot(this,&Gtk_LdapTreeItem::target_drag_drop));
	this->drag_source_set(static_cast<GdkModifierType>(GDK_BUTTON1_MASK|GDK_BUTTON3_MASK), target_table, n_targets, static_cast<GdkDragAction>(GDK_ACTION_COPY|GDK_ACTION_MOVE));
	gtk_drag_source_set(GTK_WIDGET(this->gtkobj()), static_cast<GdkModifierType>(GDK_BUTTON1_MASK|GDK_BUTTON3_MASK), target_table, n_targets, static_cast<GdkDragAction>(GDK_ACTION_COPY|GDK_ACTION_MOVE));
	this->drag_data_get.connect(slot(this, &Gtk_LdapTreeItem::source_drag_data_get));
	this->drag_data_delete.connect(slot(this,&Gtk_LdapTreeItem::source_drag_data_delete));
	this->drag_leave.connect(slot(this,&Gtk_LdapTreeItem::target_drag_leave));

}

Gtk_LdapTreeItem::Gtk_LdapTreeItem(GtkTreeItem *t) : Gtk_TreeItem(t) {
}

Gtk_LdapTreeItem::~Gtk_LdapTreeItem() {
	cout << "Bye" << endl;
	delete this;
}

Gtk_LdapTree* Gtk_LdapTreeItem::getSubtree(LDAP *ld, int counter) {
	debug("Gtk_LdapTreeItem::getSubtree(%s)\n", this->dn);
	if (counter <= 0) return NULL;
	if (this->gtkobj()->subtree != NULL) {
		//return (Gtk_LdapTree *)GTK_TREE(this->gtkobj()->subtree);
		debug("This item has a subtree\n");
		return (Gtk_LdapTree *)this->get_subtree(); //gtkobj()->subtree);
	}
	counter--;
	Gtk_LdapTree *subtree = NULL, *tree = NULL;
	Gtk_LdapTreeItem *subtreeitem = NULL;
	LDAPMessage *r_i = NULL, *entry = NULL;
	gchar *c;
	char **s;
	int entriesCount = 0, error;

	this->ld = ld;
	if (this->dn == "cn=config" || this->dn == "cn=monitor" || this->dn == "cn=schema") error = ldap_search_s(this->ld, this->dn, LDAP_SCOPE_BASE, "objectclass=*", NULL, 0, &r_i);
	else {
		if (strcasecmp(this->objectClass,"alias") == 0) error = ldap_search_s(this->ld, this->getAttribute("aliasedobjectname"), LDAP_SCOPE_ONELEVEL, "objectclass=*", NULL, 0, &r_i);
		else error = ldap_search_s(this->ld, this->dn, LDAP_SCOPE_ONELEVEL, "objectclass=*", NULL, 0, &r_i);
	}
//	printf("%s\n", ldap_err2string(error));
	entriesCount = ldap_count_entries(this->ld, r_i);
	debug("%i results\n", entriesCount);
	if (entriesCount != 0) { 
		tree = new Gtk_LdapTree();
	//	this->set_subtree(*tree);
		tree->set_selection_mode(GTK_SELECTION_BROWSE);
		tree->set_view_mode(GTK_TREE_VIEW_ITEM);
		tree->set_view_lines(false);
		entry = ldap_first_entry(this->ld, r_i);
	//	float i = 1;
		gfloat percent = 100/entriesCount;
		debug("percent is %f\n", percent);
	//	this->par->progress.set_percentage(percent/100);
	//	this->par->progress.show();
		while (entry != NULL) {
			subtreeitem = new Gtk_LdapTreeItem(ldap_get_dn(this->ld, entry), this->par, this->ld);
			debug("inserting %s into %s\n",subtreeitem->rdn,this->rdn);
			tree->append(*subtreeitem);
			subtree = subtreeitem->getSubtree(this->ld, counter);
			subtreeitem->show();
			if (subtree != NULL) subtreeitem->set_subtree(*subtree);
		//	subtreeitem->setDnd();
			debug("done\n");
			entry = ldap_next_entry(this->ld, entry);
		//	gfloat pvalue = (i*percent)/100;
		//	cout << pvalue << " %" << endl;
		//	this->par->progress.update(pvalue);
		//	this->par->progress.show();
		//	i++;
		}
	//	this->set_subtree(*tree);
	//	this->par->progress.update(0);
	//	this->par->progress->show();
	}
//	this->getDetails();
	debug("done\n");
	return tree;
}

void Gtk_LdapTreeItem::setType(int t) {
	debug("Gtk_LdapTreeItem::setType(%s)\n", this->objectClass);
	Gtk_Pixmap *xpm_icon;
	Gtk_Label *label;
	if (this->get_child() != NULL) {
		debug("got a child here");
		//xpm_label = new Gtk_HBox(this->get_child());
		this->remove();
		/*
		//xpm_label = new Gtk_HBox(*GTK_HBOX(this->get_child()->gtkobj()));
		xpm_label = new Gtk_HBox(this->get_child()); //->gtkobj());
		//xpm_label->remove_c(xpm_label->children().nth_data(0));
		Gtk_HBox::BoxList &list = xpm_label->children();
		Gtk_HBox::BoxList::iterator i = list.begin();
		xpm_label->remove(*i);
		//xpm_label->remove_c(xpm_label->children().nth_data(0));
		xpm_label->remove(*xpm_label->children().begin());
		*/
	}
	xpm_label = new Gtk_HBox();
	if (strcasecmp(this->objectClass,"organization") == 0)
		//xpm_icon=new Gtk_Pixmap(*xpm_label, root_node);
		xpm_icon=new Gtk_Pixmap(root_node);
	else if (strcasecmp(this->objectClass,"organizationalunit") == 0)
		//xpm_icon=new Gtk_Pixmap(*xpm_label, branch_node);
		xpm_icon=new Gtk_Pixmap(branch_node);
	else if (strcasecmp(this->objectClass,"person") == 0)
		//xpm_icon=new Gtk_Pixmap(*xpm_label, leaf_node);
		xpm_icon=new Gtk_Pixmap(leaf_node);
	else if (strcasecmp(this->objectClass,"alias") == 0)
		//xpm_icon=new Gtk_Pixmap(*xpm_label, alias_node);
		xpm_icon=new Gtk_Pixmap(alias_node);
	else if (strcasecmp(this->objectClass,"rfc822mailgroup") == 0)
		//xpm_icon=new Gtk_Pixmap(*xpm_label, rfc822mailgroup_node);
		xpm_icon=new Gtk_Pixmap(rfc822mailgroup_node);
	else if (strcasecmp(this->objectClass,"LDAPsubentry") == 0)
		xpm_icon=new Gtk_Pixmap(monitor);
	else //xpm_icon=new Gtk_Pixmap(*xpm_label, general_node);
		xpm_icon=new Gtk_Pixmap(general_node);
	label = new Gtk_Label(this->rdn);
	xpm_label->pack_start(*xpm_icon, false, false, 1);
	xpm_label->pack_start(*label, false, false, 1);
	if (this->get_child() == NULL) {
		debug("no children - GREAT!!");
		this->add(*xpm_label);
	}
	//label->show();
	//xpm_icon->show();
	//xpm_label->show();
	show_all();
}

int Gtk_LdapTreeItem::showDetails() {
	debug("Gtk_LdapTreeItem::showDetails()\n");
	if (this->notebook == NULL) this->getDetails();
	if (this->notebook != NULL) {
		debug("Have a notebook here");
		if (par->viewport2->get_child() != NULL) {
			debug(" and the viewport has children");
			//par->viewport2->remove(par->viewport2->get_child());
			par->viewport2->remove();
			debug(" which have been removed");
		}
		else debug(" and viewport has no children");
		par->viewport2->add(*this->notebook);
		this->notebook->show();
		par->viewport2->show();
		return 0;
	}
	else debug("No notebook and no details");
	return 0;
}

char* Gtk_LdapTreeItem::getAttribute(char *c) {
	int entriesCount, error;
	BerElement *ber;
	LDAPMessage *entry;
	char *attribute, **values;
	error = ldap_search_s(this->ld, this->dn, LDAP_SCOPE_BASE, "objectclass=*", NULL, 0, &this->result_identifier);
	entriesCount = ldap_count_entries(this->ld, this->result_identifier);
	if (entriesCount == 0) return 0;
	for (entry = ldap_first_entry(ld, result_identifier); entry != NULL; entry = ldap_next_entry(ld, result_identifier)) {
		for (attribute = ldap_first_attribute(ld, entry, &ber); attribute != NULL; attribute = ldap_next_attribute(ld, entry, ber)) {
			values = ldap_get_values(ld, entry, attribute);
			if (strcasecmp(attribute, "aliasedobjectname") == 0) {
				this->aliasedObjectName = strdup(values[0]);
			}
		}
	}
	return this->aliasedObjectName;
}

int Gtk_LdapTreeItem::getDetails() {
	debug("Gtk_LdapTreeItem::getDetails()\n");
	int error, entriesCount;
	BerElement *ber;
	LDAPMessage *entry;
	char *attribute, **values;
	char attrib[32];
	Gtk_CList *table;
	Gtk_Label *label;
	GList *child_list;
	Gtk_Viewport *viewport;
	error = ldap_search_s(this->ld, this->dn, LDAP_SCOPE_BASE, "objectclass=*", NULL, 0, &this->result_identifier);
	entriesCount = ldap_count_entries(this->ld, this->result_identifier);
	if (entriesCount == 0) return 0;
	this->notebook = new Gtk_Notebook();
	this->notebook->set_tab_pos(GTK_POS_LEFT);
	const gchar *titles[] = { "values" };
	
	for (entry = ldap_first_entry(ld, result_identifier); entry != NULL; entry = ldap_next_entry(ld, result_identifier)) {
		for (attribute = ldap_first_attribute(ld, entry, &ber); attribute != NULL; attribute = ldap_next_attribute(ld, entry, ber)) {
			values = ldap_get_values(ld, entry, attribute);
			if (strcasecmp(attribute, "objectclass") == 0) {
			//	debug("processing objectclass\n");
				if (strcasecmp(values[0],"top") == 0)
					this->objectClass = strdup(values[1]);
				else this->objectClass = strdup(values[0]);
			}
			table = new Gtk_CList(1, titles);
			for (int i=0; i<ldap_count_values(values); i++) {
			//	debug("%i:%s\n",i, values[i]);
				const gchar *t[] = { values[i] };
				table->append(t);
			}
			ldap_value_free(values);
			sprintf(attrib, "%s", attribute);
			label = new Gtk_Label(attrib);
			label->set_alignment(0, 0);
			label->set_justify(GTK_JUSTIFY_LEFT);
			this->notebook->pages().push_back(Gtk_Notebook_Helpers::TabElem(*table, *label));
			table->show();
			label->show();
		}
	}
	this->setType(1);
	debug("done\n");
	return 0;
}

void Gtk_LdapTreeItem::createPopupMenu() {
	debug("Gtk_LdapTreeItem::createPopupMenu()\n");
	Gtk_MenuItem *item;

	this->menu = new Gtk_Menu();
	
	item = new Gtk_MenuItem("Add");
	this->menu->add(*item);
	item = new Gtk_MenuItem("Delete");
	this->menu->add(*item);
	item = new Gtk_MenuItem();
	this->menu->add(*item);
	item = new Gtk_MenuItem("Cut");
	this->menu->add(*item);
	item = new Gtk_MenuItem("Copy");
	this->menu->add(*item);
	item = new Gtk_MenuItem("Paste");
	this->menu->add(*item);
	this->menu->show_all();
	this->menu->activate();
}
/*
void Gtk_LdapTreeItem::show_impl() {
	debug("%s showed\n", this->dn);
//	Gtk_c_signals_Base *sig=(Gtk_c_signals_Base *)internal_getsignalbase();
//	sig->show(GTK_WIDGET(gtkobj()));
}
*/
/*
void Gtk_LdapTreeItem::select_impl() {
	debug("%s selected\n", this->dn);
	this->showDetails();
	Gtk_TreeItem::select_impl();
}
*/

void Gtk_LdapTreeItem::collapse_impl() {
	debug("%s collapsed\n", this->dn);
	Gtk_TreeItem::collapse_impl();
}

void Gtk_LdapTreeItem::expand_impl() {
	debug("%s expanded\n",this->dn);
	Gtk_LdapTreeItem *item;
	G_List<GtkWidget> *list;
	Gtk_Tree *tree;
	Gtk_TreeItem::expand_impl();
}

void Gtk_LdapTreeItem::click() {
	debug("%s clicked\n", this->dn);
}

/*
gint Gtk_LdapTreeItem::button_press_event_impl(GdkEventButton *p0) {
	debug("Gtk_LdapTreeItem::button_press_event_impl(%i)\n", p0->button);
	GdkEventButton *bevent = (GdkEventButton *) p0;
	if (p0->button == 3) gtk_menu_popup(this->menu->gtkobj(), NULL, NULL, NULL, NULL, bevent->button, bevent->time);
	Gtk_TreeItem::button_press_event_impl(p0);
//	Gtk_TreeItem::select_impl();
}
*/

void Gtk_LdapTreeItem::item_drag_data_received(GdkDragContext *context,
                                    gint                x,
                                    gint                y,
                                    GtkSelectionData   *data,
                                    guint               info,
                                    guint               time) {
	debug("Gtk_LdapTreeItem::item_drag_data_received\n");
	Gdk_DragContext gdc(context);
	if ((data->length >= 0) && (data->format == 8)) {
		cout << "Received \"" << (gchar *)data->data << "\" in label" << endl;
		Gtk_Widget::drag_finish(gdc, true, false, time);
		return;
	}

	Gtk_Widget::drag_finish(gdc , false, false, time);
}

gboolean Gtk_LdapTreeItem::target_drag_drop(GdkDragContext *context,
                            gint x, gint y, guint theTime) {
	debug("Gtk_LdapTreeItem::target_drag_drop\n");
	cout << "drop" << endl;
	have_drag = false;

//	pixmap.set(trashcan_closed, trashcan_closed_mask);

	Gdk_DragContext gdc(context);
	Gdk_Atom *ga = static_cast <GdkAtom *>(context->targets->data);
	if (context->targets) {
		this->drag_get_data(gdc, *ga, theTime);
		return true;
	}

	return false;
}


void Gtk_LdapTreeItem::source_drag_data_get(GdkDragContext	*context,
                                 GtkSelectionData *selection_data,
                                 guint info, guint32 time) {
	debug("Gtk_LdapTreeItem::source_drag_data_get\n");
	if (info == TARGET_ROOTWIN) {
		cout << "I was dropped on the rootwin" << endl;
	}
	else {
		if ( info == TARGET_URL ) {
			gtk_selection_data_set(selection_data,
				selection_data->target, 8,
				reinterpret_cast < const unsigned char * >
				("file:///home/otaylor/images/weave.png"), 37);
		}
		else {
			gtk_selection_data_set(selection_data,
				selection_data->target, 8,
				reinterpret_cast <const unsigned char *>
				("I'm Data!"), 9);
		}
	}
}

void Gtk_LdapTreeItem::source_drag_data_delete(GdkDragContext *context) {
	debug("Gtk_LdapTreeItem::source_drag_data_delete\n");
	debug("Delete the data!\n");
}

void Gtk_LdapTreeItem::target_drag_leave(GdkDragContext *context, guint time) {
  debug("Gtk_LdapTreeItem::target_drag_leave\n");
  this->have_drag = false;
//  pixmap.set(trashcan_closed, trashcan_closed_mask);
}


#include "Gtk_LdapServer.h"
#include <gtk--/base.h>

Gtk_LdapServer::Gtk_LdapServer() : Gtk_TreeItem() {
	this->hostname = NULL;
	this->par = NULL;
	this->base_dn = NULL;
	this->port = 0;
}

Gtk_LdapServer::Gtk_LdapServer(My_Window *w, char *h, int p) : Gtk_TreeItem() {
	this->par = w;
	this->hostname = h;
	this->port = p;
	debug("%s %i\n", this->hostname, this->port);
	this->getConfig();
}

Gtk_LdapServer::Gtk_LdapServer(GtkTreeItem *t) : Gtk_TreeItem(t) {
}

Gtk_LdapServer::~Gtk_LdapServer() {
	debug("Bye\n");
	delete this;
}

void Gtk_LdapServer::setType(int t) {
	debug("Gtk_LdapServer::setType(%i)\n", t);
	Gtk_Pixmap *xpm_icon;
	Gtk_Label *label;
	if (this->getchild() != NULL) {
		xpm_label = new Gtk_HBox(GTK_HBOX(this->getchild()->gtkobj()));
		xpm_label->remove_c(xpm_label->children()->nth_data(0));
		xpm_label->remove_c(xpm_label->children()->nth_data(0));
	}
	else xpm_label = new Gtk_HBox();
	debug(this->hostname);
	if (strcasecmp(this->hostname,"localhost") == 0)
		xpm_icon=new Gtk_Pixmap(*xpm_label, local_server);
	else xpm_icon=new Gtk_Pixmap(*xpm_label, remote_server);
	label = new Gtk_Label(this->hostname);
	xpm_label->pack_start(*xpm_icon, false, false, 1);
	xpm_label->pack_start(*label, false, false, 1);
	if (this->getchild() == NULL) this->add(xpm_label);
	label->show();
	xpm_label->show();
	xpm_icon->show();
}

int Gtk_LdapServer::showDetails() {
	debug("Gtk_LdapServer::showDetails()\n");
	this->getDetails();
	/*
	if (this->notebook != NULL) {
		if (par->viewport->getchild() != NULL) {
			par->viewport->remove_c(par->viewport->getchild()->gtkobj());
		}
		par->viewport->add(this->notebook);
		this->notebook->show();
		par->viewport->show();
		return 0;
	}
	else this->getDetails();
	this->showDetails();
	*/
	return 0;
}

int Gtk_LdapServer::getConfig() {
	debug("Gtk_LdapServer::getConfig()\n");
	int error, entriesCount;
	LDAPMessage *entry, *result_identifier;
	BerElement *ber;
	char *attribute, **t;

	if ((this->ld = ldap_open(this->hostname, this->port)) == NULL) {
		perror("connection");
	}

	error = ldap_search_s(this->ld, "cn=config", LDAP_SCOPE_BASE, "objectclass=*", NULL, 0, &result_identifier);	
	entriesCount = ldap_count_entries(this->ld, result_identifier);
	if (entriesCount == 0) {
		return 0;
	}

	debug("%i entry\n", entriesCount);
	for (entry = ldap_first_entry(this->ld, result_identifier); entry != NULL; entry = ldap_next_entry(this->ld, result_identifier)) {
		for (attribute = ldap_first_attribute(this->ld, entry, &ber); attribute != NULL; attribute = ldap_next_attribute(this->ld, entry, ber)) {
			debug("Attrib: %s\n", attribute);
			if (strcasecmp(attribute, "database") == 0) {
				debug("have database here\n");
				this->databases = new G_List<char>;
				t = ldap_get_values(this->ld, entry, attribute);
				for (int i=0; i<ldap_count_values(t); i++) {
					this->databases->append(strdup(t[i]));
				}
				ldap_value_free(t);
				debug("databases loaded\n");
				for (int i=0; i<this->databases->length(); i++) {
					debug("database(%i) %s\n", i, this->databases->nth_data(i));
				}	
			}
		}
		debug("entry done\n");
	}
//	debug("got %i entries\n", entriesCount);
	return entriesCount;
}

int Gtk_LdapServer::getDetails() {
	debug("Gtk_LdapServer::getDetails()\n");
	Gtk_HBox *hbox;
	Gtk_VBox *vbox;
	Gtk_Label *label;	
	Gtk_RadioButton *radio1, *radio2;
	char *val;
	int ival;

	if (GTK_TREE_ITEM(this->gtkobj())->subtree == NULL) {
		this->getSubtree();
	}

/*
	cout << "getting ldap options";
	vbox = new Gtk_VBox();
	opt_util = new LdapOpts();

	for (int i=0; i<sizeof(things); i++) {
		cout << i << endl;
		hbox = new Gtk_HBox();
		label = new Gtk_Label(LdapOpts->getOption(things[i]);
		hbox->pack_start(*label);
		label->show();
		int tipus = opt_util->getType(things[i]);
		switch (tipus) {
			case 0:
				ldap_get_option(NULL, things[i], &val);
				label = new Gtk_Label(val);
				break;
			case 1:
				ldap_get_option(NULL, numerals[i], &ival);
				sprintf(val, "%i", ival);
				label = new Gtk_Label(val);
				break;
			case 2:
				ldap_get_option(NULL, booleans[i], &ival);
				sprintf(val, "%s", ival == (int) LDAP_OPT_ON ? "on" : "off");
				label = new Gtk_Label(val);
				break;
			default:
				break;
		}

		hbox->pack_start(*label);
		label->show();
		vbox->pack_start(*hbox);
		hbox->show();
		
	}

	vbox->border_width(2);
	this->notebook = new Gtk_Viewport();
	this->notebook->add(*vbox);
	vbox->show();
*/
	this->setType(1);
	return 0;
}

Gtk_Tree* Gtk_LdapServer::getSubtree() {
	debug("Gtk_LdapServer::getSubtree()\n");
	Gtk_LdapItem *treeresult;
	Gtk_LdapTree *tree, *subtree;
	Gtk_LdapTreeItem *treeitem;
	int entries;

	debug("this->hostname=%s\n", this->hostname);
	debug("this->port=%i", this->port);
/*	if ((this->ld = ldap_open(this->hostname, this->port)) == NULL) {
		perror("connection");
	}
*/

	char *c;
	char *tok;

	int len = this->databases->length();
	debug("this->databases->length()=%i\n", len);

	tree = new Gtk_LdapTree();
	for (int i=0; i<len; i++) {
		tok = strdup(this->databases->nth_data(i));
		tok = strtok(tok, ":");
	//	c = strtok(NULL, " ");
		c = strtok(NULL, "\0");
		debug("database %i %s\n", i, c);
		treeitem = new Gtk_LdapTreeItem(c, this->par, this->ld);
		subtree = treeitem->getSubtree(this->ld, 1);
		debug("inserting %s into %s\n", treeitem->rdn, this->hostname);
		tree->append(*treeitem);
		treeitem->set_subtree(*subtree);
		treeitem->show();
	//	tree->show();
	}
//	this->set_subtree(*tree);
	debug("getTree() done\n");
	return tree;
}

void Gtk_LdapServer::select_impl() {
	debug("%s selected\n", this->hostname);
//	gtk_item_select(GTK_ITEM(GTK_TREE_ITEM(this->gtkobj())));
	Gtk_c_signals_Item *sig=(Gtk_c_signals_Item *)internal_getsignalbase();
	if (!sig->select) return;
	sig->select(GTK_ITEM(gtkobj()));
	this->showDetails();
}

void Gtk_LdapServer::collapse_impl() {
	debug("%s collapsed\n", this->hostname);
	Gtk_c_signals_TreeItem *sig=(Gtk_c_signals_TreeItem *)internal_getsignalbase();
	if (!sig->collapse) return;
	sig->collapse(GTK_TREE_ITEM(gtkobj()));
//	gtk_widget_hide(GTK_WIDGET(GTK_TREE(GTK_TREE_ITEM (this->gtkobj())->subtree)));
}

void Gtk_LdapServer::expand_impl() {
	debug("%s expanded\n", this->hostname);
	Gtk_c_signals_TreeItem *sig=(Gtk_c_signals_TreeItem *)internal_getsignalbase();
	if (!sig->expand) return;
	sig->expand(GTK_TREE_ITEM(gtkobj()));
//	Gtk_Tree *t;
//	t = new Gtk_Tree(GTK_TREE(GTK_TREE_ITEM(this->gtkobj())->subtree));
//	bool vis = t->visible();
//	if (vis == false) {
//		gtk_widget_show(GTK_WIDGET(GTK_TREE(GTK_TREE_ITEM (this->gtkobj())->subtree)));
//		cout << this->dn << " expanded" << endl;
//	}
//	else {
//		gtk_widget_hide(GTK_WIDGET(GTK_TREE(GTK_TREE_ITEM (this->gtkobj())->subtree)));
//		cout << this->dn << " collapsed" << endl;
//	}
}

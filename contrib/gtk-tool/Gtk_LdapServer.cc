#include "Gtk_LdapServer.h"
#include <gtk--/base.h>

Gtk_LdapServer::Gtk_LdapServer() : Gtk_TreeItem() {
	this->hostname = NULL;
	this->par = NULL;
	this->base_dn = NULL;
	this->port = 0;
}

Gtk_LdapServer::Gtk_LdapServer(My_Window *w, char *h, int p) : Gtk_TreeItem() {
	char *s, *s2;
	this->par = w;
	this->hostname = h;
	this->port = p;
	this->notebook = NULL;
	debug("%s %i\n", this->hostname, this->port);
	this->setType(1);
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
	char *c = NULL;
	if (this->get_child() != NULL) this->remove();
	xpm_label = new Gtk_HBox();
	debug(this->hostname);
	if (strcasecmp(this->hostname,"localhost") == 0)
		xpm_icon=new Gtk_Pixmap(local_server);
	else xpm_icon=new Gtk_Pixmap(remote_server);
//	sprintf(c, "%s:%i", this->hostname, this->port);
//	printf("%s\n", c);
	label = new Gtk_Label(this->hostname);
	xpm_label->pack_start(*xpm_icon, false, false, 1);
	xpm_label->pack_start(*label, false, false, 1);
	if (this->get_child() == NULL) this->add(*xpm_label);
	this->show_all();
}

int Gtk_LdapServer::showDetails() {
	debug("Gtk_LdapServer::showDetails()\n");
	if (this->notebook == NULL) this->getOptions();
	if (this->notebook != NULL) {
		debug("Have a notebook here");
		if (par->viewport2->get_child() != NULL) {
			debug(" and viewport has children");
			par->viewport2->remove();
			debug(" which have been removed\n");
		}
		else debug(" and viewport without children\n");
		par->viewport2->add(*this->notebook);
	}
	this->show_all();
	debug("done\n");
	return 0;
}

int Gtk_LdapServer::getMonitor() {
	debug("Gtk_LdapServer::getMonitor()\n");
	int error, entriesCount;
	LDAPMessage *entry, *result_identifier;
	BerElement *ber;
	char *attribute, **t;

	if ((this->ld = ldap_open(this->hostname, this->port)) == NULL) {
		perror("connection");
	}

	error = ldap_search_s(this->ld, "cn=monitor", LDAP_SCOPE_BASE, "objectclass=*", NULL, 0, &result_identifier);	
	entriesCount = ldap_count_entries(this->ld, result_identifier);
	if (entriesCount == 0) {
		return 0;
	}

	debug("%i tree(s)\n", entriesCount);
	for (entry = ldap_first_entry(this->ld, result_identifier); entry != NULL; entry = ldap_next_entry(this->ld, result_identifier)) {
		for (attribute = ldap_first_attribute(this->ld, entry, &ber); attribute != NULL; attribute = ldap_next_attribute(this->ld, entry, ber)) {
			debug("Attrib: %s\n", attribute);
			if (strcasecmp(attribute, "database") == 0) {
				debug("have database here\n");
				this->databases = NULL;
				t = ldap_get_values(this->ld, entry, attribute);
				for (int i=0; i<ldap_count_values(t); i++) {
					this->databases = g_list_append(this->databases, strdup(t[i]));
				}
				ldap_value_free(t);
				debug("databases loaded\n");
				GList *t;
				for (int i=0;i>g_list_length(this->databases);i++) {
					t = g_list_nth(this->databases, i);
					debug("database(%i) %s\n", i, (char*) t->data);
				}	
			}
		}
		debug("entry done\n");
	}
	return entriesCount;
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

//	debug("%i tree(s)\n", entriesCount);
	for (entry = ldap_first_entry(this->ld, result_identifier); entry != NULL; entry = ldap_next_entry(this->ld, result_identifier)) {
		for (attribute = ldap_first_attribute(this->ld, entry, &ber); attribute != NULL; attribute = ldap_next_attribute(this->ld, entry, ber)) {
			debug("Attrib: %s\n", attribute);
			if (strcasecmp(attribute, "database") == 0) {
				debug("have database here\n");
				this->databases = NULL;
				t = ldap_get_values(this->ld, entry, attribute);
				for (int i=0; i<ldap_count_values(t); i++) {
					this->databases = g_list_append(this->databases, strdup(t[i]));
				}
			this->databases = g_list_append(this->databases, "ldbm : cn=config");
			this->databases = g_list_append(this->databases, "ldbm : cn=monitor");
				ldap_value_free(t);
				debug("databases loaded\n");
				GList *t;
				for (int i=0;i<g_list_length(this->databases);i++) {
					t = g_list_nth(this->databases, i);
					debug("database(%i) %s\n", i, (char*) t->data);
				}	
			}
		}
		debug("entry done\n");
	}
	return entriesCount;
}

#ifndef LDAP_GET_OPT /* a temporary fix for usability with (old) U-MICH api */
char* Gtk_LdapServer::getOptDescription(int option) {
	debug("Gtk_LdapServer::getOptDescription(%i) ", option);
	char *c;
	switch (option) {
		case LDAP_OPT_API_INFO: c = "API info"; break;
		case LDAP_OPT_CLIENT_CONTROLS: c = "Client controls"; break;
		case LDAP_OPT_DEREF: c = "Dereference"; break;
		case LDAP_OPT_DESC: c = "Description"; break;
		case LDAP_OPT_DNS: c = "DNS Lookup"; break;
		case LDAP_OPT_ERROR_NUMBER: c = "Error number"; break;
		case LDAP_OPT_ERROR_STRING: c = "Error string"; break;
		case LDAP_OPT_SIZELIMIT: c = "Size limit"; break;
		case LDAP_OPT_TIMELIMIT: c = "Time limit"; break;
		case LDAP_OPT_REFERRALS: c = "Referrals"; break;
		case LDAP_OPT_RESTART: c = "Started"; break;
		case LDAP_OPT_PROTOCOL_VERSION: c = "Protocol version"; break;
		case LDAP_OPT_HOST_NAME: c = "Host name"; break;
		case LDAP_OPT_SERVER_CONTROLS: c = "Server controls"; break;
		default: c = "No description"; break;
	}
	debug("%s\n", c);
	return c;
}

int Gtk_LdapServer::getOptType(int option) {
	debug("Gtk_LdapServer::getOptType(%i) ", option);
	/* types:
	 * 0 = int, 1 = string, 2 = boolean,
	 * 3 = range, 4 = LDAPAPIInfo, 5 = unknown
	 */
	int type;
	switch(option) {
		/* ints */
		case LDAP_OPT_DEREF:
		case LDAP_OPT_DESC:
		case LDAP_OPT_ERROR_NUMBER:
		case LDAP_OPT_PROTOCOL_VERSION: type = 0; break;
		/* strings */
		case LDAP_OPT_ERROR_STRING:
		case LDAP_OPT_HOST_NAME: type = 1; break;
		/* bools */
		case LDAP_OPT_REFERRALS:
		case LDAP_OPT_DNS:
		case LDAP_OPT_RESTART: type = 2; break;
		/* range */
		case LDAP_OPT_SIZELIMIT:	
		case LDAP_OPT_TIMELIMIT: type = 3; break;
		/* api */
		case LDAP_OPT_API_INFO: type = 4; break;
		/* unknowns */
		case LDAP_OPT_SERVER_CONTROLS:
		case LDAP_OPT_CLIENT_CONTROLS:
		default: type = 5; break;
	}
	debug("%i\n", type);
	return type;
}
#endif /* LDAP_GET_OPT */

int Gtk_LdapServer::getOptions() {
	debug("Gtk_LdapServer::getOptions()\n");
	if (this->notebook != NULL) return 0;
#ifdef LDAP_GET_OPT /* a temporary fix for usability with (old) U-MICH api */
	Gtk_Label *label;
	label = new Gtk_Label("This tool has been compiled with (old) U-MICH API (no LDAP_GET_OPT)\nCompile with the latest -devel (from OpenLDAP cvs tree)\nto get some nice options here");
	this->notebook = new Gtk_Frame("LDAP Options");
	this->notebook->add(*label);
	//label->show();
	//this->notebook->show();
	this->notebook->show_all();
	return 0;
#else
	LDAPAPIInfo api;
	Gtk_HBox *hbox, *mini_hbox;
	Gtk_VBox *vbox, *mini_vbox;
	Gtk_Table *table;
	Gtk_Label *label;	
	Gtk_RadioButton *radio1, *radio2;
	Gtk_HScale *scale;
	Gtk_Adjustment *adjustment;
	char *description = NULL, *s_value = NULL;
//	int i_value;
	string label_string;

	int things[10] = {
		LDAP_OPT_API_INFO,
		LDAP_OPT_CLIENT_CONTROLS,
	//	LDAP_OPT_DESC,
	//	LDAP_OPT_DEREF,
		LDAP_OPT_DNS,
	//	LDAP_OPT_ERROR_NUMBER,
	//	LDAP_OPT_ERROR_STRING,
		LDAP_OPT_HOST_NAME,
		LDAP_OPT_PROTOCOL_VERSION,
		LDAP_OPT_REFERRALS,
		LDAP_OPT_RESTART,
		LDAP_OPT_SERVER_CONTROLS,
		LDAP_OPT_SIZELIMIT,
		LDAP_OPT_TIMELIMIT
	};

/*	if (GTK_TREE_ITEM(this->gtkobj())->subtree == NULL) {
		this->getSubtree();
	} */

//	vbox = new Gtk_VBox();
	table = new Gtk_Table(10, 1, TRUE);

	for (int i=0; i<10; i++) {
		int i_value;
	//	debug("%i\n", i);
		hbox = new Gtk_HBox(TRUE, 2);
		hbox->set_border_width(2);
		description = this->getOptDescription(things[i]);
		label = new Gtk_Label(description);
		label->set_justify(GTK_JUSTIFY_LEFT);
		label->set_alignment(0, 0);
		hbox->pack_start(*label);
		label->show();
		switch (this->getOptType(things[i])) {
			case 0:
				ldap_get_option(this->ld, things[i], &i_value);
				debug("%s value %d\n", description, i_value);
				sprintf(s_value, "%d", i_value);
				label = new Gtk_Label(s_value);
				label->set_justify(GTK_JUSTIFY_LEFT);
				label->set_alignment(0, 0);
				hbox->pack_end(*label);
				label->show();
				break;
			case 1:
				ldap_get_option(this->ld, things[i], &s_value);
				label = new Gtk_Label(s_value);
				label->set_justify(GTK_JUSTIFY_LEFT);
				label->set_alignment(0, 0);
				hbox->pack_end(*label);
				label->show();
				break;
			case 2:
				ldap_get_option(this->ld, things[i], &i_value);
				radio1 = new Gtk_RadioButton("Enabled");
				radio2 = new Gtk_RadioButton("Disabled");
				radio2->set_group(radio1->group());
				if (i_value == 1) radio1->set_active(true);
				else radio2->set_active(true);
				mini_hbox = new Gtk_HBox(FALSE, 2);
				mini_hbox->set_border_width(2);
				mini_hbox->pack_start(*radio1);
				//radio1->show();
				mini_hbox->pack_end(*radio2);
				//radio2->show();
				hbox->pack_end(*mini_hbox);
				//mini_hbox->show();
				break;
			case 3:
				ldap_get_option(this->ld, things[i], &i_value);
				debug("i_value: %s\n", i_value);
				adjustment = new Gtk_Adjustment(i_value, 0.0, 20.0, 1.0, 1.0, 0.0);
				scale = new Gtk_HScale(*adjustment);
				scale->set_update_policy(GTK_UPDATE_CONTINUOUS);
				scale->set_value_pos(GTK_POS_TOP);
				scale->set_digits(0);
				scale->set_draw_value(true);
				hbox->pack_end(*scale);
				//scale->show();
				break;
			case 4:
#ifdef LDAP_API_INFO_VERSION
	api.ldapai_info_version = LDAP_API_INFO_VERSION;
#else
	api.ldapai_info_version = 1;
#endif
				if (ldap_get_option(this->ld, things[i], &api) != LDAP_SUCCESS) {
					perror(this->getOptDescription(things[i]));
					break;
				}
				s_value = api.ldapai_vendor_name;
				label = new Gtk_Label(s_value);
				label->set_justify(GTK_JUSTIFY_LEFT);
				label->set_alignment(0, 0);
				hbox->pack_end(*label);
				//label->show();
				break;
			default:
				label = new Gtk_Label("Not implemented (yet)");
				label->set_justify(GTK_JUSTIFY_LEFT);
				label->set_alignment(0, 0);
				hbox->pack_end(*label);
				//label->show();
				break;
		}
	//	hbox->pack_end(*label);
	//	label->show();
		table->attach(*hbox, 0, 1, i, i+1);
		hbox->show();
	}
	table->set_border_width(2);
	this->notebook = new Gtk_Frame("LDAP Options");
	this->notebook->add(*table);
	//table->show();
	this->notebook->show_all();
	return 0;
#endif /* LDAP_GET_OPT */
}

Gtk_Tree* Gtk_LdapServer::getSubtree() {
	debug("Gtk_LdapServer::getSubtree()\n");
	Gtk_LdapTree *tree, *subtree;
	Gtk_LdapTreeItem *treeitem;
	int entries;

	debug("this->hostname=%s\n", this->hostname);
	debug("this->port=%i", this->port);

	char *c;
	char *tok;

	int len = g_list_length(this->databases);
	debug("this->databases->length()=%i\n", len);

	tree = new Gtk_LdapTree();
	for (int i=0; i<len; i++) {
		GList *t = g_list_nth(this->databases, i);
		tok = strdup((char*)t->data);
		tok = strtok(tok, ":");
	//	c = strtok(NULL, " ");
		c = strtok(NULL, "\0");
		debug("database %i %s\n", i, c);
		treeitem = new Gtk_LdapTreeItem(c, this->par, this->ld);
		subtree = treeitem->getSubtree(this->ld, 1);
		debug("inserting %s into %s\n", treeitem->rdn, this->hostname);
		tree->append(*treeitem);
		if (subtree != NULL) treeitem->set_subtree(*subtree);
		treeitem->show();
	//	tree->show();
	}
//	this->set_subtree(*tree);
	debug("getSubtree() done\n");
	return tree;
}
/*
void Gtk_LdapServer::show_impl() {
	debug("%s showed\n", this->hostname);
	BaseClassType *sig=static_cast<BaseClassType *>(get_parent_class());
	if (!sig->show) return;
	sig->show(gtkobj());
//	Gtk_c_signals_Item *sig=(Gtk_c_signals_Item *)internal_getsignalbase();
//	sig->show(GTK_WIDGET(gtkobj()));
}
*/
void Gtk_LdapServer::select_impl() {
	debug("%s selected\n", this->hostname);
//	Gtk_c_signals_Item *sig=(Gtk_c_signals_Item *)internal_getsignalbase();
//	if (!sig->select) return;
	this->showDetails();
//	sig->select(GTK_ITEM(gtkobj()));
	Gtk_TreeItem::select_impl();
}

void Gtk_LdapServer::collapse_impl() {
	debug("%s collapsed\n", this->hostname);
//	Gtk_c_signals_TreeItem *sig=(Gtk_c_signals_TreeItem *)internal_getsignalbase();
//	if (!sig->collapse) return;
//	sig->collapse(GTK_TREE_ITEM(gtkobj()));
//	gtk_widget_hide(GTK_WIDGET(GTK_TREE(GTK_TREE_ITEM (this->gtkobj())->subtree)));
	Gtk_TreeItem::collapse_impl();
}

void Gtk_LdapServer::expand_impl() {
	debug("%s expanded\n", this->hostname);
	Gtk_TreeItem::expand_impl();
//	BaseClassType *sig=static_cast<BaseClassType *>(get_parent_class());
//	if (!sig->expand)
//		{ return; }
//	sig->expand(gtkobj());
//	Gtk_c_signals_TreeItem *sig=(Gtk_c_signals_TreeItem *)internal_getsignalbase();
//	if (!sig->expand) return;
//	sig->expand(GTK_TREE_ITEM(gtkobj()));
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

#include "LdapEntry.h"

LdapEntry* LdapEntry::get_entries(LDAP *ld, char *base_dn, int level,char *filter) {
	printf("get_entries(%s)\n", base_dn);
	LDAPMessage **result, *entry;
	Entry *thing;
	char *pele;
	int res;
	res = ldap_search(ld, base_dn, level, filter, NULL, 0);
	res = ldap_result(ld, res, 1, NULL, result);
	printf("%s\n", ldap_err2string(ldap_result2error(ld, *result, 1)));
	int num_entries = ldap_count_entries(ld, *result);
	printf("%i results\n", num_entries);
	int i=0;
	entry = ldap_first_entry(ld, *result);
	thing->dn = ldap_get_dn(ld, entry);
	pele = ldap_get_dn(ld, entry);
	printf("%s\n", thing->dn);
	while (entry) {
		printf("Child %i\n", i);
		thing->child[i] = get_entries(ld, pele, LDAP_SCOPE_ONELEVEL, filter);
		i++;
		entry = ldap_next_entry(ld, entry);
	}
	return thing;
}

Gtk_Tree *LdapEntry::make_tree(Entry *thing) {
	Gtk_Tree *tree, **subtree;
	Gtk_TreeItem *treeitem;
	gchar *c;
	tree = new Gtk_Tree();
	tree->set_selection_mode(GTK_SELECTION_BROWSE);
	tree->set_view_mode(GTK_TREE_VIEW_ITEM);
	tree->set_view_lines(false);
	c = g_strdup_printf("%s", thing->dn);
	printf("%s\n", c);
	treeitem = new Gtk_TreeItem(c);
	tree->append(treeitem);
	treeitem->show();
	int i=0;
	while (thing->child[i]) {
		subtree[i] = make_tree(thing->child[i]);
		treeitem->set_subtree(subtree[i]);
		i++;
	}
	tree->show();
	return tree;
}

/* shell.h - shell backend header file */

struct shellinfo {
	char	**si_bind;	/* cmd + args to exec for bind	  */
	char	**si_unbind;	/* cmd + args to exec for unbind  */
	char	**si_search;	/* cmd + args to exec for search  */
	char	**si_compare;	/* cmd + args to exec for compare */
	char	**si_modify;	/* cmd + args to exec for modify  */
	char	**si_modrdn;	/* cmd + args to exec for modrdn  */
	char	**si_add;	/* cmd + args to exec for add	  */
	char	**si_delete;	/* cmd + args to exec for delete  */
	char	**si_abandon;	/* cmd + args to exec for abandon */
};

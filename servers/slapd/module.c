/* $OpenLDAP$ */
#include "portable.h"
#include <stdio.h>
#include "slap.h"

#ifdef SLAPD_MODULES

#include <ltdl.h>

int load_null (const void *module, const char *file_name);
int load_extension (const void *module, const char *file_name);

struct module_regtable_t {
	char *type;
	int (*proc)(const void *module, const char *file_name);
} module_regtable[] = {
		{ "null", load_null },
#ifdef SLAPD_EXTERNAL_EXTENSIONS
		{ "extension", load_extension },
#endif
		{ NULL, NULL }
};

typedef struct module_loaded_t {
	struct module_loaded_t *next;
	lt_dlhandle *lib;
} module_loaded_t;

module_loaded_t *module_list = NULL;

int module_unload (module_loaded_t *module);

int module_init (void)
{
	if (lt_dlinit()) {
		const char *error = lt_dlerror();
		Debug(LDAP_DEBUG_ANY, "lt_dlinit failed: %s\n", error, 0, 0);
		return -1;
	}
	return 0;
}

int module_kill (void)
{
	/* unload all modules before shutdown */
	while (module_list != NULL) {
		module_unload(module_list);
	}

	if (lt_dlexit()) {
		const char *error = lt_dlerror();
		Debug(LDAP_DEBUG_ANY, "lt_dlexit failed: %s\n", error, 0, 0);
		return -1;
	}
	return 0;
}

int module_load(const char* file_name, int argc, char *argv[])
{
	module_loaded_t *module = NULL;
	const char *error;
	int rc;
	int (*initialize) LDAP_P((int argc, char *argv[]));

	module = (module_loaded_t *)ch_calloc(1, sizeof(module_loaded_t));
	if (module == NULL) {
		Debug(LDAP_DEBUG_ANY, "module_load failed: (%s) out of memory\n", file_name,
			0, 0);
		return -1;
	}

	/*
	 * The result of lt_dlerror(), when called, must be cached prior
	 * to calling Debug. This is because Debug is a macro that expands
	 * into multiple function calls.
	 */
	if ((module->lib = lt_dlopen(file_name)) == NULL) {
		error = lt_dlerror();
		Debug(LDAP_DEBUG_ANY, "lt_dlopen failed: (%s) %s\n", file_name,
			error, 0);
		ch_free(module);
		return -1;
	}

	Debug(LDAP_DEBUG_CONFIG, "loaded module %s\n", file_name, 0, 0);
   
	if ((initialize = lt_dlsym(module->lib, "init_module")) == NULL) {
		Debug(LDAP_DEBUG_CONFIG, "module %s: no init_module() function found\n",
			file_name, 0, 0);
		lt_dlclose(module->lib);
		ch_free(module);
		return -1;
	}

	/* The imported init_module() routine passes back the type of
	 * module (i.e., which part of slapd it should be hooked into)
	 * or -1 for error.  If it passes back 0, then you get the 
	 * old behavior (i.e., the library is loaded and not hooked
	 * into anything).
	 *
	 * It might be better if the conf file could specify the type
	 * of module.  That way, a single module could support multiple
	 * type of hooks. This could be done by using something like:
	 *
	 *    moduleload extension /usr/local/openldap/whatever.so
	 *
	 * then we'd search through module_regtable for a matching
	 * module type, and hook in there.
	 */
	rc = initialize(argc, argv);
	if (rc == -1) {
		Debug(LDAP_DEBUG_CONFIG, "module %s: init_module() failed\n",
			file_name, 0, 0);
		lt_dlclose(module->lib);
		ch_free(module);
		return rc;
	}

	if (rc >= (sizeof(module_regtable) / sizeof(struct module_regtable_t))
		|| module_regtable[rc].proc == NULL)
	{
		Debug(LDAP_DEBUG_CONFIG, "module %s: unknown registration type (%d)\n",
			file_name, rc, 0);
		module_unload(module);
		return -1;
	}

	rc = (module_regtable[rc].proc)(module, file_name);
	if (rc != 0) {
		Debug(LDAP_DEBUG_CONFIG, "module %s: %s module could not be registered\n",
			file_name, module_regtable[rc].type, 0);
		module_unload(module);
		return rc;
	}

	module->next = module_list;
	module_list = module;

	Debug(LDAP_DEBUG_CONFIG, "module %s: %s module registered\n",
		file_name, module_regtable[rc].type, 0);
	return 0;
}

int module_path(const char *path)
{
	return lt_dlsetsearchpath( path );
}

void *module_resolve (const void *module, const char *name)
{
	if (module == NULL || name == NULL)
		return(NULL);
	return(lt_dlsym(((module_loaded_t *)module)->lib, name));
}

int module_unload (module_loaded_t *module)
{
	module_loaded_t *mod;
	int (*terminate) LDAP_P((void));

	if (module != NULL) {
		/* remove module from tracking list */
		if (module_list == module) {
			module_list = module->next;
		} else {
			for (mod = module_list; mod; mod = mod->next) {
				if (mod->next == module) {
					mod->next = module->next;
					break;
				}
			}
		}

		/* call module's terminate routine, if present */
		if (terminate = lt_dlsym(module->lib, "term_module")) {
			terminate();
		}

		/* close the library and free the memory */
		lt_dlclose(module->lib);
		ch_free(module);
	}
	return 0;
}

int load_null (const void *module, const char *file_name)
{
	return 0;
}

#endif /* SLAPD_MODULES */


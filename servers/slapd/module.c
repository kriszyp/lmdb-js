/* $OpenLDAP$ */
#include "portable.h"
#include <stdio.h>
#include "slap.h"

#ifdef SLAPD_MODULES

#include <ltdl.h>

int module_load(const char* file_name, int argc, char *argv[])
{
    lt_dlhandle* module = NULL;
    const char *error;

    /*
     * The result of lt_dlerror(), when called, must be cached prior
     * to calling Debug. This is because Debug is a macro that expands
     * into multiple function calls.
     */

    int (*initialize) LDAP_P((int argc, char *argv[]));

    if (lt_dlinit()) {
	error = lt_dlerror();
	Debug(LDAP_DEBUG_ANY, "lt_dlinit failed: %s\n", error, 0, 0);
	return -1;
    }

    if ((module = lt_dlopen(file_name)) == NULL) {
	error = lt_dlerror();
	Debug(LDAP_DEBUG_ANY, "lt_dlopen failed: (%s) %s\n", file_name,
	    error, 0);
	return -1;
    }

    Debug(LDAP_DEBUG_CONFIG, "loaded module %s\n", file_name, 0, 0);
   
    if ((initialize = lt_dlsym(module, "init_module")))
	return initialize(argc, argv);

    Debug(LDAP_DEBUG_CONFIG, "module %s: no init_module() function found\n",
	file_name, 0, 0);
    return -1;
}

int module_path(const char *path)
{
    const char *error;

    /*
     * The result of lt_dlerror(), when called, must be cached prior
     * to calling Debug. This is because Debug is a macro that expands
     * into multiple function calls.
     */

    if (lt_dlinit()) {
	error = lt_dlerror();
	Debug(LDAP_DEBUG_ANY, "lt_dlinit failed: %s\n", error, 0, 0);
	return -1;
    }

    return lt_dlsetsearchpath( path );
}
#endif /* SLAPD_MODULES */


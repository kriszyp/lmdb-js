#include "portable.h"
#include <stdio.h>
#include "slap.h"

#ifdef SLAPD_MODULES

#include <ltdl.h>

int load_module(const char* file_name, int argc, char *argv[]) {
   lt_dlhandle* module = NULL;
   void (*initialize) LDAP_P((int argc, char *argv[]));

   if (lt_dlinit()) {
      Debug(LDAP_DEBUG_ANY, "lt_dlinit failed: %s\n", lt_dlerror(), 0, 0);
      return -1;
   }
   
   if ((module = lt_dlopen(file_name)) == NULL) {
      Debug(LDAP_DEBUG_ANY, "lt_dlopen failed: (%s) %s\n", file_name, lt_dlerror(), 0);
      return -1;
   }

   Debug(LDAP_DEBUG_CONFIG, "loaded module %s\n", file_name, 0, 0);
   
   if ((initialize = lt_dlsym(module, "init_module"))) {
      initialize(argc, argv);
   } else {
      Debug(LDAP_DEBUG_CONFIG, "module %s: no init_module() function found\n", file_name, 0, 0);
      return -1;
   }

   return 0;
}

#endif /* SLAPD_MODULES */


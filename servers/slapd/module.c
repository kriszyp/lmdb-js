#include "portable.h"
#include <stdio.h>
#include "slap.h"

#ifdef SLAPD_MODULES

#include <glib.h>
#include <gmodule.h>

int load_module(const char* file_name, int argc, char *argv[]) {
   GModule* module = NULL;
   void (*initialize) LDAP_P((int argc, char *argv[]));

   if (!g_module_supported()) {
      Debug(LDAP_DEBUG_ANY, "loadable modules not supported on this platform\n", 0, 0, 0);
      return FALSE;
   }
   
   if ((module = g_module_open(file_name, G_MODULE_BIND_LAZY)) == NULL) {
      Debug(LDAP_DEBUG_ANY, "failed to load module %s: %s\n", file_name, g_module_error(), 0);
      return FALSE;
   }

   Debug(LDAP_DEBUG_CONFIG, "loaded module %s\n", file_name, 0, 0);
   
   if (g_module_symbol(module, "init_module", (gpointer *) &initialize)) {
      initialize(argc, argv);
   } else {
      Debug(LDAP_DEBUG_CONFIG, "module %s: no init_module() function found\n", file_name, 0, 0);
      return FALSE;
   }

   return TRUE;
}

#endif /* SLAPD_MODULES */


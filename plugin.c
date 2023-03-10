/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from make-plugin-reg.py.
 */

#include "config.h"
#include "moduleinfo.h"

#include <gmodule.h>

/* wireshark 3 needs this define for proto_plugin struct definition */
#ifndef HAVE_PLUGINS
#define HAVE_PLUGINS
#endif

/* plugins are DLLs on Windows */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#include "epan/proto.h"

void proto_register_yimp(void);
void proto_reg_handoff_yimp(void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug_yimp;

    plug_yimp.register_protoinfo = proto_register_yimp;
    plug_yimp.register_handoff = proto_reg_handoff_yimp;
    proto_register_plugin(&plug_yimp);
}

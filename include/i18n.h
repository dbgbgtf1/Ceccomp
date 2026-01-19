#ifndef CONFIG_H
#include "config.h"
#endif
#ifndef I18N_H
#define I18N_H

#ifdef LOCALEDIR
#include <libintl.h>
#define _(string) gettext (string)
#else
#define _(string) string
#endif

#endif

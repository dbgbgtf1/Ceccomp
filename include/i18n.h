#ifndef I18N_H
#define I18N_H

#ifdef LOCALEDIR
#include <libintl.h>
#include <locale.h>
#define _(string) gettext (string)
#else
#define _(string) string
#endif

#endif

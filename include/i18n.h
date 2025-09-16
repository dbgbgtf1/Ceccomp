#ifndef I18N_H
#define I18N_H

#ifdef LOCALEDIR
#include <locale.h>
#include <libintl.h>
#define _(string) gettext(string)
#else
#define _(string) string
#endif

#endif

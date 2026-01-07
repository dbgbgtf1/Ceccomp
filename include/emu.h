#ifndef EMU
#define EMU

#include "parse_args.h"
#include "vector.h"

extern void emulate_v (vector_t *text_v, vector_t *code_ptr_v,
                       emu_arg_t *emu_arg);

extern void emulate (emu_arg_t *emu_arg);

#endif

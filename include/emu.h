#ifndef EMU
#define EMU

#include "utils/parse_args.h"
#include "utils/vector.h"

extern void emulate_v (vector_t *text_v, vector_t *code_ptr_v,
                       emu_arg_t *emu_arg, FILE *output_fp);

extern void emulate (emu_arg_t *emu_arg);

#endif

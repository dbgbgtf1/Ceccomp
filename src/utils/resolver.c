#include "resolver.h"
#include "parser.h"
#include <stdint.h>

static void
assign_line (assign_line_t *assign_line)
{
}
static void
jump_line (jump_line_t *jump_line)
{
}

static void
resolve_state_ment (state_ment_t *state_ment)
{
  switch (state_ment->type)
    {
    case ASSIGN_LINE:
      assign_line (&state_ment->assign_line);
    case JUMP_LINE:
      jump_line (&state_ment->jump_line);

    // nothing need to be done for these line
    case RETURN_LINE:
    case EMPTY_LINE:
    case EOF_LINE:
    case ERROR_LINE:
      break;
    }
}

void
resolver (vector_t *v)
{
  for (uint32_t idx = 0; idx < v->count; idx++)
    resolve_state_ment (get_vector (v, idx));
}

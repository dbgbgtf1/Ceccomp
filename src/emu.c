#include "emu.h"
#include "decoder/decoder.h"
#include "decoder/formatter.h"
#include "lexical/parser.h"
#include "lexical/scanner.h"
#include "lexical/token.h"
#include "main.h"
#include "resolver/resolver.h"
#include "utils/color.h"
#include "utils/error.h"
#include "utils/logger.h"
#include "utils/parse_args.h"
#include "utils/read_source.h"
#include "utils/vector.h"
#include <assert.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t A_reg = 0;
static uint32_t X_reg = 0;
static uint32_t mem[BPF_MEMWORDS] = { 0 };

static uint32_t syscall_nr = 0;
static uint32_t scmp_arch = 0;
static uint32_t low_pc = 0;
static uint32_t high_pc = 0;
static uint32_t low_args[6] = { 0 };
static uint32_t high_args[6] = { 0 };

static uint32_t scmp_data_len = sizeof (seccomp_data);
#define BASE_vars(value) ((value) - A)
static uint32_t *vars[] = {
  [BASE_vars (A)] = &A_reg,
  [BASE_vars (X)] = &X_reg,
  [BASE_vars (MEM)] = mem,
  [BASE_vars (ATTR_SYSCALL)] = &syscall_nr,
  [BASE_vars (ATTR_ARCH)] = &scmp_arch,
  [BASE_vars (ATTR_LOWPC)] = &low_pc,
  [BASE_vars (ATTR_HIGHPC)] = &high_pc,
  [BASE_vars (ATTR_LOWARG)] = low_args,
  [BASE_vars (ATTR_HIGHARG)] = high_args,
  [BASE_vars (ATTR_LEN)] = &scmp_data_len,
};

#define DO_OPERATE(operator) (*left operator (*right))

static void
assign_line (assign_line_t *assign_line)
{
  uint32_t *left = vars[BASE_vars (assign_line->left_var.type)];

  token_type right_type = assign_line->right_var.type;
  uint32_t *right = vars[BASE_vars (right_type)];
  if (right_type == ATTR_LOWARG || right_type == ATTR_HIGHARG)
    right += assign_line->right_var.data;
  if (right_type == NUMBER)
    right = &assign_line->right_var.data;

  switch (assign_line->operator)
    {
    case ADD_TO:
      DO_OPERATE (+=);
      break;
    case SUB_TO:
      DO_OPERATE (-=);
      break;
    case MULTI_TO:
      DO_OPERATE (*=);
      break;
    case DIVIDE_TO:
      DO_OPERATE (/=);
      break;
    case LSH_TO:
      DO_OPERATE (<<=);
      break;
    case RSH_TO:
      DO_OPERATE (>>=);
      break;
    case AND_TO:
      DO_OPERATE (&=);
      break;
    case OR_TO:
      DO_OPERATE (|=);
      break;
    case XOR_TO:
      DO_OPERATE (^=);
      break;
    case EQUAL:
      DO_OPERATE (=);
      break;
    case NEGATIVE:
      DO_OPERATE (= -);
      break;
    default:
      assert (!"Unknown alu operation");
    }
}

#define DO_COMPARE(comparator) (bool)(A_reg comparator right)

static label_t *
jump_line (jump_line_t *jump_line)
{
  label_t *jt = &jump_line->jt;
  label_t *jf = &jump_line->jf;

  if (!jump_line->if_condition)
    return jt;

  bool cond_true = false;
  if (jump_line->if_bang)
    cond_true = true;

  uint32_t right = 0;
  if (jump_line->cmpobj.type == X)
    right = X_reg;
  else
    right = jump_line->cmpobj.data;

  switch (jump_line->comparator)
    {
    case EQUAL_EQUAL:
      cond_true ^= DO_COMPARE (==);
      break;
    case BANG_EQUAL:
      cond_true ^= DO_COMPARE (!=);
      break;
    case GREATER_EQUAL:
      cond_true ^= DO_COMPARE (>=);
      break;
    case GREATER_THAN:
      cond_true ^= DO_COMPARE (>);
      break;
    case LESS_EQUAL:
      cond_true ^= DO_COMPARE (<=);
      break;
    case LESS_THAN:
      cond_true ^= DO_COMPARE (<);
      break;
    case AND:
      cond_true ^= DO_COMPARE (&);
      break;
    default:
      assert (!"Unknown comparator");
    }

  return (cond_true ? jt : jf);
}

/**
 * Process return line if return $A or return NUMBER. Sets real_ret to
 * resolved plain result like KILL; returns a valid string if statement
 * need to add a comment.
 */
static string_t
return_line (return_line_t *line, obj_t *real_ret)
{
  static char formatted_val[0x28];
  obj_t *ret_obj = &line->ret_obj;
  *real_ret = (obj_t){ .type = UNKNOWN };
  int sz;
  const string_t *tkstr;

  // append addtional return value comment for
  // return $A and return NUMBER
  if (ret_obj->type == A)
    {
      real_ret->type = decode_return_k (real_ret, A_reg);
      tkstr = token_pairs + real_ret->type;
      sz = snprintf (formatted_val, 0x28, "# A = %#x, %.*s", A_reg, tkstr->len,
                     tkstr->start);
    }
  else if (ret_obj->type == NUMBER)
    {
      real_ret->type = decode_return_k (real_ret, ret_obj->data);
      tkstr = token_pairs + real_ret->type;
      sz = snprintf (formatted_val, 0x28, "# %.*s", tkstr->len, tkstr->start);
    }
  else
    return (string_t){ 0 };

  register token_type tk = real_ret->type;
  if (tk == TRACE || tk == TRAP || tk == ERRNO)
    sz += snprintf (formatted_val + sz, 0x28 - sz, "(%u)", real_ret->data);
  assert (sz);
  return (string_t){ .start = formatted_val, .len = sz };
}

static uint32_t
code_nr_to_text_nr (vector_t *text_v, vector_t *code_ptr_v, statement_t *cur,
                    label_t *jmp)
{
  if (jmp->code_nr == 0) // if ... goto xxx; false case -> jmp.code_nr is NULL
    return cur->text_nr + 1;
  statement_t **ptr = get_vector (code_ptr_v, cur->code_nr + jmp->code_nr + 1);
  uint32_t text_nr = (*ptr)->text_nr;

  statement_t *statement;
  string_t *label_decl;
  uint32_t cur_line_nr = cur->text_nr; // compiler hint
  while (text_nr > cur_line_nr)
    {
      statement = get_vector (text_v, text_nr);

      label_decl = &statement->label_decl;
      if ((label_decl->start) && (label_decl->len == jmp->key.len)
          && (!strncmp (label_decl->start, jmp->key.start, jmp->key.len)))
        break;
      text_nr--;
    }
  assert (text_nr != cur_line_nr); // should find a tag to jump to
  return text_nr;
}

static void
print_label_decl (statement_t *statement)
{
  string_t *label_decl = &statement->label_decl;
  if (label_decl->start)
    {
      fwrite (label_decl->start, 1, label_decl->len, stdout);
      fputc (':', stdout);
      fputc (' ', stdout);
    }
}

static void
emulate_printer (statement_t *statement, bool is_skipped, bool quiet)
{
  if (quiet)
    return;

  bool global_color = color_enable;
  if (is_skipped && global_color)
    {
      fwrite (LIGHTCLR, 1, LITERAL_STRLEN (LIGHTCLR), stdout);
      push_color (false);
    }

  print_label_decl (statement);
  print_statement (stdout, statement);

  if (is_skipped && global_color)
    {
      pop_color ();
      fwrite (CLR, 1, LITERAL_STRLEN (CLR), stdout);
    }
}

static statement_t *
emulator (vector_t *text_v, vector_t *code_ptr_v, bool quiet)
{
  uint32_t read_idx = 1;
  uint32_t exec_idx = 1;
  label_t *jmp;

  statement_t *statement = NULL;
  for (; read_idx < text_v->count; read_idx++)
    {
      statement = get_vector (text_v, read_idx);

      if (read_idx < exec_idx)
        {
          emulate_printer (statement, true, quiet);
          continue;
        }

      exec_idx++;

      switch (statement->type)
        {
        case ASSIGN_LINE:
          assign_line (&statement->assign_line);
          break;
        case JUMP_LINE:
          jmp = jump_line (&statement->jump_line);
          exec_idx = code_nr_to_text_nr (text_v, code_ptr_v, statement, jmp);
          break;
        case RETURN_LINE:
            // make compiler happy
            ;
          obj_t real_ret;
          string_t ret_str = return_line (&statement->return_line, &real_ret);
          if (ret_str.start)
            {
              if (quiet)
                statement->return_line.ret_obj = real_ret;
              else
                {
                  statement->line_start = (char *)ret_str.start;
                  statement->comment = 0;
                  statement->line_len = ret_str.len;
                }
            }
          goto out;
        case EMPTY_LINE:
          break;
        case EOF_LINE:
        case ERROR_LINE:
          assert (!"Emulating EOF/ERROR line??");
        }
      emulate_printer (statement, false, quiet);
    }

out:
  assert (statement);
  assert (statement->type == RETURN_LINE);
  emulate_printer (statement, false, quiet);
  return statement;
}

static void
init_attr (emu_arg_t *emu_arg)
{
  if (emu_arg->sys_name == NULL)
    error ("%s", M_INPUT_SYS_NR);
  syscall_nr = seccomp_syscall_resolve_name_arch (emu_arg->scmp_arch,
                                                  emu_arg->sys_name);

  if ((int32_t)syscall_nr == __NR_SCMP_ERROR)
    {
      char *end;
      syscall_nr = strtoull (emu_arg->sys_name, &end, 0);
      if (*end != '\0')
        error ("%s", M_INVALID_SYSNR);
    }

  scmp_arch = emu_arg->scmp_arch;
  low_pc = emu_arg->ip & UINT32_MAX;
  high_pc = emu_arg->ip >> 32;
  for (uint32_t i = 0; i < 6; i++)
    {
      low_args[i] = emu_arg->args[i] & UINT32_MAX;
      high_args[i] = emu_arg->args[i] >> 32;
    }
}

void
emulate_v (vector_t *text_v, vector_t *code_ptr_v, emu_arg_t *emu_arg,
           FILE *output_fp)
{
  init_attr (emu_arg);

  statement_t *ret = emulator (text_v, code_ptr_v, emu_arg->quiet);
  uint32_t line_left = text_v->count - 1 - ret->text_nr;
  if (!emu_arg->quiet && line_left)
    print_as_comment (output_fp, "... %d line(s) skipped", line_left);

  if (!emu_arg->quiet)
    return;

  extern_obj_printer (output_fp, &ret->return_line.ret_obj);
  fputc ('\n', output_fp);
}

void
emulate (emu_arg_t *emu_arg)
{
  size_t lines = init_source (emu_arg->text_file) + 1;
  init_scanner (next_line ());
  init_parser (emu_arg->scmp_arch);
  init_table ();

  vector_t text_v;
  vector_t code_ptr_v;
  init_vector (&text_v, sizeof (statement_t), lines);
  init_vector (&code_ptr_v, sizeof (statement_t *), MIN (lines, 1025));
  parser (&text_v, &code_ptr_v);
  if (resolver (&code_ptr_v))
    error ("%s", M_EMU_TERMINATED);
  // if ERROR_LINE exists, then exits

  emulate_v (&text_v, &code_ptr_v, emu_arg, stdout);

  free_table ();
  free_source ();
  free_vector (&text_v);
  free_vector (&code_ptr_v);
}

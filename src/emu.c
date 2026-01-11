#include "emu.h"
#include "color.h"
#include "formatter.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "parse_args.h"
#include "parser.h"
#include "read_source.h"
#include "resolver.h"
#include "scanner.h"
#include "token.h"
#include "vector.h"
#include <assert.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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

static uint32_t *vars[] = {
  [ATTR_SYSCALL] = &syscall_nr,
  [ATTR_ARCH] = &scmp_arch,
  [ATTR_LOWPC] = &low_pc,
  [ATTR_HIGHPC] = &high_pc,
  [ATTR_LOWARG] = low_args,
  [ATTR_HIGHARG] = high_args,
  [A] = &A_reg,
  [X] = &X_reg,
  [MEM] = mem,
};

#define DO_OPERATE(operator) (*left operator (*right))

static void
assign_line (assign_line_t *assign_line)
{
  uint32_t *left = vars[assign_line->left_var.type];

  token_type right_type = assign_line->right_var.type;
  uint32_t *right = vars[right_type];
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
      assert (0);
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
      assert (0);
    }

  return (cond_true ? jt : jf);
}

static uint32_t
code_nr_to_text_nr (vector_t *text_v, vector_t *code_ptr_v, statement_t *cur,
                    label_t *jmp)
{
  statement_t **ptr = get_vector (code_ptr_v, cur->code_nr + jmp->code_nr + 1);
  uint32_t text_nr = (*ptr)->text_nr;

  statement_t *statement;
  string_t *label_decl;
  while (true)
    {
      statement = get_vector (text_v, text_nr);

      label_decl = &statement->label_decl;
      if ((label_decl->start) && (label_decl->len == jmp->key.len)
          && (!strncmp (label_decl->start, jmp->key.start, jmp->key.len)))
        break;
      text_nr--;
    }
  return text_nr;
}

static void
print_label_decl (statement_t *statement)
{
  string_t *label_decl = &statement->label_decl;
  if (label_decl->start != NULL)
    printf ("%.*s: ", label_decl->len, label_decl->start);
}

static void
emulate_printer (statement_t *statement, char *override_color, bool quiet)
{
  if (quiet)
    return;

  if (override_color)
    {
      printf ("%s", override_color);
      push_color (false);
    }

  print_label_decl (statement);
  print_statement (stdout, statement);

  if (override_color)
    {
      pop_color ();
      printf ("%s", CLR);
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
          emulate_printer (statement, LIGHTCLR, quiet);
          continue;
        }

      emulate_printer (statement, NULL, quiet);
      exec_idx++;

      switch (statement->type)
        {
        case ASSIGN_LINE:
          assign_line (&statement->assign_line);
          continue;
        case JUMP_LINE:
          jmp = jump_line (&statement->jump_line);
          exec_idx = code_nr_to_text_nr (text_v, code_ptr_v, statement, jmp);
          continue;
        case RETURN_LINE:
          break;
        case EMPTY_LINE:
          continue;
        case EOF_LINE:
        case ERROR_LINE:
          assert (0);
        }

      break;
    }

  assert (statement);
  assert (statement->type == RETURN_LINE);
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
    error ("%s", M_INVALID_SYSNR);

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
  init_source (emu_arg->text_file);
  init_scanner (next_line ());
  init_parser (emu_arg->scmp_arch);
  init_table ();

  vector_t text_v;
  vector_t code_ptr_v;
  init_vector (&text_v, sizeof (statement_t));
  init_vector (&code_ptr_v, sizeof (statement_t *));
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

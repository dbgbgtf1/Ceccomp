#include "asm.h"
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
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t retvals[] = {
  [KILL_PROC] = SCMP_ACT_KILL_PROCESS,
  [KILL] = SCMP_ACT_KILL,
  [ALLOW] = SCMP_ACT_ALLOW,
  [NOTIFY] = SCMP_ACT_NOTIFY,
  [LOG] = SCMP_ACT_LOG,
  [TRACE] = SCMP_ACT_TRACE (0),
  [TRAP] = _SCMP_ACT_TRAP (0),
  [ERRNO] = SCMP_ACT_ERRNO (0),
};

static filter
return_line (return_line_t *return_line)
{
  filter f = { .code = BPF_RET, .jf = 0, .jt = 0, .k = 0 };
  if (return_line->ret_obj.type == A)
    {
      f.code |= BPF_A;
      return f;
    }
  f.code |= BPF_K;
  if (return_line->ret_obj.type == NUMBER)
    f.k = return_line->ret_obj.data;
  else
    // KILL, KILL_PROC, ALLOW, NOTIFY, LOG has data = 0
    f.k = retvals[return_line->ret_obj.type] | return_line->ret_obj.data;
  return f;
}

static uint32_t operator_table[] = {
  [ADD_TO] = BPF_ADD,    [SUB_TO] = BPF_SUB, [MULTI_TO] = BPF_MUL,
  [DIVIDE_TO] = BPF_DIV, [LSH_TO] = BPF_LSH, [RSH_TO] = BPF_RSH,
  [AND_TO] = BPF_AND,    [OR_TO] = BPF_OR,   [XOR_TO] = BPF_XOR,
};

static filter
alu_line (assign_line_t *assign_line)
{
  filter f = { .code = BPF_ALU, .jf = 0, .jt = 0, .k = 0 };
  f.code |= operator_table[assign_line->operator];

  if (assign_line->right_var.type == X)
    f.code |= BPF_X;
  else if (assign_line->right_var.type == NUMBER)
    {
      f.code |= BPF_K;
      f.k = assign_line->right_var.data;
    }

  return f;
}

static filter
negative_line ()
{
  filter f = { .code = BPF_ALU | BPF_NEG, .jf = 0, .jt = 0, .k = 0 };
  return f;
}

static filter
st_stx_line (assign_line_t *assign_line)
{
  filter f = { .code = 0, .jf = 0, .jt = 0, .k = 0 };
  f.k = assign_line->left_var.data;
  if (assign_line->right_var.type == A)
    f.code |= BPF_ST;
  else if (assign_line->right_var.type == A)
    f.code |= BPF_STX;
  return f;
}

static filter
ldx_line (assign_line_t *assign_line)
{
  filter f = { .code = 0, .jf = 0, .jt = 0, .k = 0 };
  if (assign_line->right_var.type == A)
    {
      f.code |= BPF_MISC | BPF_TAX;
      return f;
    }
  if (assign_line->right_var.type == NUMBER)
    f.code |= BPF_LDX | BPF_IMM;
  else if (assign_line->right_var.type == MEM)
    f.code |= BPF_LDX | BPF_MEM;

  f.k = assign_line->right_var.data;
  return f;
}

static uint32_t offset_table[] = {
  [ATTR_SYSCALL] = offsetof (seccomp_data, nr),
  [ATTR_ARCH] = offsetof (seccomp_data, arch),
  [ATTR_LOWPC] = offsetof (seccomp_data, instruction_pointer),
  [ATTR_HIGHPC] = offsetof (seccomp_data, instruction_pointer) + 4,
  [ATTR_LOWARG] = offsetof (seccomp_data, args),
  [ATTR_HIGHARG] = offsetof (seccomp_data, args) + 4,
};

static uint32_t
offset_abs (obj_t *obj)
{
  uint32_t offset = offset_table[obj->type];
  if (obj->type == ATTR_LOWARG || obj->type == ATTR_HIGHARG)
    offset += obj->data * sizeof (uint64_t);
  return offset;
}

static filter
ld_line (assign_line_t *assign_line)
{
  filter f = { .code = 0, .jf = 0, .jt = 0, .k = 0 };

  if (assign_line->right_var.type == X)
    f.code |= BPF_MISC | BPF_TXA;
  else if (assign_line->right_var.type == NUMBER)
    {
      f.code |= BPF_LD | BPF_IMM;
      f.k = assign_line->right_var.data;
    }
  else if (assign_line->right_var.type == MEM)
    {
      f.code |= BPF_LD | BPF_MEM;
      f.k = assign_line->right_var.data;
    }
  else
    {
      f.code |= BPF_LD | BPF_W | BPF_ABS;
      f.k = offset_abs (&assign_line->right_var);
    }

  return f;
}

static filter
assign_line (assign_line_t *assign_line)
{
  if (assign_line->operator >= ADD_TO && assign_line->operator <= XOR_TO)
    return alu_line (assign_line);
  if (assign_line->operator == NEGATIVE)
    return negative_line ();
  if (assign_line->left_var.type == MEM)
    return st_stx_line (assign_line);
  if (assign_line->left_var.type == X)
    return ldx_line (assign_line);

  assert (assign_line->left_var.type == A);

  return ld_line (assign_line);
}

static void
reverse_jt_jt (jump_line_t *jump_line)
{
  label_t tmp = jump_line->jt;
  jump_line->jt = jump_line->jf;
  jump_line->jf = tmp;
}

static uint32_t comparator_table[] = {
  [EQUAL_EQUAL] = BPF_JEQ, [BANG_EQUAL] = BPF_JEQ,   [GREATER_EQUAL] = BPF_JGE,
  [LESS_THAN] = BPF_JGE,   [GREATER_THAN] = BPF_JGT, [LESS_EQUAL] = BPF_JGT,
  [AND] = BPF_JSET,
};

static filter
jump_line (jump_line_t *jump_line)
{
  filter f = { .code = BPF_JMP, .jf = 0, .jt = 0, .k = 0 };
  if (!jump_line->if_condition)
    {
      f.code |= BPF_JA;
      f.k |= jump_line->jt.code_nr;
      return f;
    }

  bool sym_reverse = false;
  token_type comparator = jump_line->comparator;
  if (comparator == BANG_EQUAL || comparator == LESS_EQUAL
      || comparator == LESS_THAN)
    sym_reverse = true;

  f.code |= comparator_table[jump_line->comparator];
  if (sym_reverse ^ jump_line->if_bang)
    reverse_jt_jt (jump_line);
  f.jt = jump_line->jt.code_nr;
  f.jf = jump_line->jf.code_nr;

  if (jump_line->cmpobj.type == X)
    f.code |= BPF_X;
  else if (jump_line->cmpobj.type == NUMBER)
    {
      f.code |= BPF_K;
      f.k = jump_line->cmpobj.data;
    }

  return f;
}

static filter
asm_statement (statement_t *statement)
{
  if (statement->type == RETURN_LINE)
    return return_line (&statement->return_line);
  if (statement->type == ASSIGN_LINE)
    return assign_line (&statement->assign_line);
  if (statement->type == JUMP_LINE)
    return jump_line (&statement->jump_line);

  assert (0);
}

typedef void (*fmt_handler) (uint8_t f[8], char *template);
#define LITERAL_STRLEN(str) (sizeof (str) - 1)

static void
hexify (uint8_t ch, char buf[2])
{
#define HEX_CODE "0123456789abcdef"
  buf[0] = HEX_CODE[ch >> 4];
  buf[1] = HEX_CODE[ch & 0xf];
}

#define HEXFMT_TEMPLATE "\"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\",\n"
#define HEXFMT_TEMPLATE_LEN LITERAL_STRLEN (HEXFMT_TEMPLATE)
static void
hexfmt_handle (uint8_t f[8], char *template)
{
  for (unsigned i = 0; i < 8; i++)
    hexify (f[i], template + 3 + 4 * i);
  fwrite (template, 1, HEXFMT_TEMPLATE_LEN, stdout);
}

#define HEXLINE_TEMPLATE "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
#define HEXLINE_TEMPLATE_LEN LITERAL_STRLEN (HEXLINE_TEMPLATE)
static void
hexline_handle (uint8_t f[8], char *template)
{
  for (unsigned i = 0; i < 8; i++)
    hexify (f[i], template + 2 + 4 * i);
  fwrite (template, 1, HEXLINE_TEMPLATE_LEN, stdout);
}

static void
raw_handle (uint8_t f[8], char *template)
{
  (void)template;
  fwrite (f, 1, 8, stdout);
}

static fmt_handler
set_print_fmt (print_mode_t print_mode, char *template)
{
  switch (print_mode)
    {
    case HEXFMT:
      memcpy (template, HEXFMT_TEMPLATE, HEXFMT_TEMPLATE_LEN + 1);
      return hexfmt_handle;
    case HEXLINE:
      memcpy (template, HEXLINE_TEMPLATE, HEXLINE_TEMPLATE_LEN + 1);
      return hexline_handle;
    case RAW:
      *template = '\0'; // for debugging, don't hurt performance
      return raw_handle;
    default:
      assert (!"Unknown fmt printer");
    }
}

void
assemble (FILE *fp, uint32_t scmp_arch, print_mode_t print_mode)
{
  init_source (fp);
  init_scanner (next_line ());
  init_parser (scmp_arch);
  init_table ();

  vector_t text_v;
  vector_t code_ptr_v;
  init_vector (&text_v, sizeof (statement_t));
  init_vector (&code_ptr_v, sizeof (statement_t *));
  parser (&text_v, &code_ptr_v);
  if (resolver (&code_ptr_v))
    error ("%s", M_ASM_TERMINATED);
  // if ERROR_LINE exists, then exits

  char fmt_template[64];
  fmt_handler handle = set_print_fmt (print_mode, fmt_template);
  for (uint32_t i = 1; i < code_ptr_v.count; i++)
    {
      statement_t **ptr = get_vector (&code_ptr_v, i);
      filter f = asm_statement (*ptr);
      handle ((uint8_t *)&f, fmt_template);
    }

  free_table ();
  free_source ();
  free_vector (&text_v);
  free_vector (&code_ptr_v);
}

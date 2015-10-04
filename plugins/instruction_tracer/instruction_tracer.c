#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"

#include "disas.h"

#define TARGET_NAME_BUF_SIZE 512
#define DICT_KEY_PROCNAME "procname"
#define LOGFILE_PATH "/tmp/decaf_instruction_trace.log"

#define TB_NULL 0x0
//((struct TranslationBlock *)NULL)


static plugin_interface_t instruction_tracer_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;

static DECAF_Handle instruction_tracer_block_begin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle instruction_tracer_block_end_handle = DECAF_NULL_HANDLE;
static DECAF_Handle instruction_tracer_insn_begin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle instruction_tracer_insn_end_handle = DECAF_NULL_HANDLE;
static DECAF_Handle instruction_tracer_block_trans_handle = DECAF_NULL_HANDLE;

static char target_name[TARGET_NAME_BUF_SIZE];
static uint32_t target_cr3 = 0;

static FILE* disas_logfile;

target_ulong begin_pc;

static int is_target_program(CPUState* env)
{
  return env->cr[3] == target_cr3;
}

static void instruction_tracer_block_end_callback(DECAF_Callback_Params* params)
{
  /*
  if (params->be.env->cr[3] == target_cr3) {
    //target_ulong block_size = params->be.tb->pc - params->be.tb->cs_base;
    target_ulong pc_start = params->be.tb->pc - params->be.tb->size;
    DECAF_printf("pc_start: %lu, pc: %lu, block_size: %lu\n", pc_start, params->be.tb->pc, params->be.tb->size);
    // Only for x86
    fprintf(logfile, ("----------------\n"));
    fprintf(logfile, "IN: %s\n", lookup_symbol(params->be.tb->cs_base));

    target_disas(logfile, pc_start, params->be.tb->size, 0);

    fprintf(logfile, "\n");
  }
  */
  if (is_target_program(params->be.env)) {
#ifdef INS_DEBUG
    DECAF_printf("*****block end*****\n");
#endif
    target_ulong current_pc = params->be.tb->cs_base + params->be.env->eip;
    DECAF_printf("current_pc: %lu, begin_pc: %lu\n", current_pc, begin_pc);
    target_disas(disas_logfile, begin_pc, current_pc - begin_pc, 0);
    fprintf(disas_logfile, "\n");
#ifdef INS_DEBUG
    DECAF_printf("*****block end callback exit*****\n");
#endif
  }
}

static void instruction_tracer_block_begin_callback(DECAF_Callback_Params* params)
{
  if (is_target_program(params->bb.env)) {
#ifdef INS_DEBUG
    DECAF_printf("*****block_begin*****\n");
#endif
    if (params->bb.env != NULL) {
#ifdef INS_DEBUG
      DECAF_printf("bb.env ok\n");
#endif
      if (params->bb.env->current_tb != TB_NULL) {
#ifdef INS_DEBUG
        DECAF_printf("current_tb ok\n");
#endif
        fprintf(disas_logfile, ("----------------\n"));
        fprintf(disas_logfile, "IN: %s\n", lookup_symbol(params->bb.env->current_tb->pc));
        begin_pc = params->bb.tb->pc;
      } else {
#ifdef INS_DEBUG
        DECAF_printf("current_tb is wrong\n");
#endif
      }
    } else {
#ifdef INS_DEBUG
      DECAF_printf("bb.env is wrong\n");
#endif
    }
#ifdef INS_DEBUG
    DECAF_printf("*****block begin callback exit*****\n");
#endif
  }
}

static void instruction_tracer_insn_begin_callback(DECAF_Callback_Params* params)
{
  return;
  if (is_target_program(params->ib.env)) {
    //TODO: not thread safe
#ifdef INS_DEBUG
    DECAF_printf("=====insn begin=====\n");
#endif
    if (params->ib.env != NULL) {
#ifdef INS_DEBUG
      DECAF_printf("ib.env ok\n");
#endif
      if (params->ib.env->current_tb == NULL) {
        return;
      }
      if (params->ib.env->current_tb != 0x0) {
#ifdef INS_DEBUG
        DECAF_printf("current_tb ok\n");
#endif
        begin_pc = params->ib.env->current_tb->pc;
      } else {
#ifdef INS_DEBUG
        DECAF_printf("current_tb is wrong\n");
#endif
      }
    } else {
#ifdef INS_DEBUG
      DECAF_printf("ib.env is wrong\n");
#endif
    }
#ifdef INS_DEBUG
    DECAF_printf("=====insn begin callback exit=====\n");
#endif
  }
}

static void instruction_tracer_insn_end_callback(DECAF_Callback_Params* params)
{
  return;
  if (is_target_program(params->ie.env)) {
#ifdef INS_DEBUG
    DECAF_printf("=====insn end=====\n");
#endif
    if (params->ie.env->current_tb == NULL) {
      return;
    }
    if (params->ie.env->current_tb != 0x0) {
#ifdef INS_DEBUG
      DECAF_printf("current_tb ok\n");
#endif
      target_ulong current_pc = params->ie.env->current_tb->pc;
      DECAF_printf("current_pc: %lu, begin_pc: %lu\n", current_pc, begin_pc);
      target_disas(disas_logfile, begin_pc, current_pc - begin_pc, 0);
    } else {
#ifdef INS_DEBUG
      DECAF_printf("current_tb is wrong\n");
#endif
    }
#ifdef INS_DEBUG
    DECAF_printf("=====insn end callback exit=====\n");
#endif
  }
}
/* static void disasm_x86(target_ulong base, target_ulong size) */
/* { */
/*   int count; */
/*   struct disassemble_info disasm_info; */
/*   INIT_DISASSEMBLE_INFO(disasm_info, out, fprintf); */
/*  */
/*   disasm_info.read_memory_func = target_read_memory; */
/*   disasm_info.buffer_vma = base; */
/*   disasm_info.buffer_length = size; */
/*  */
/*   disasm_info.endian = BFD_ENDIAN_LITTLE; */
/*  */
/*   disasm_info.mach = bfd_mach_i386_i386; */
/*   print_insn_i386 */
/*  */
/*   for (pc = code; size > 0; pc += count, size -= count) { */
/* 	  fprintf(out, "0x" TARGET_FMT_lx ":  ", pc); */
/* 	  count = print_insn_i386(pc, &disasm_info); */
/*     fprintf(out, "\n"); */
/* 	  if (count < 0) */
/* 	    break; */
/*     if (size < count) { */
/*       fprintf(out, */
/*         "Disassembler disagrees with translator over instruction " */
/*         "decoding\n" */
/*         "Please report this to qemu-devel@nongnu.org\n"); */
/*       break; */
/*     } */
/*   } */
/* } */

static void instruction_tracer_block_trans_callback(DECAF_Callback_Params* params)
{
  if (params->bt.tb->target_cr3 == target_cr3) {
    target_ulong pc_start = params->bt.tb->pc_start;
    target_ulong block_size = params->bt.tb->block_size;
    DECAF_printf("pc_start: %lu, block_size: %lu\n", pc_start, block_size);
    fprintf(disas_logfile, ("----------------\n"));
    fprintf(disas_logfile, "IN: %s\n", lookup_symbol(pc_start));
    target_disas(disas_logfile, pc_start, block_size, 0);
    fprintf(disas_logfile, "\n");
  }
}

static void instruction_tracer_load_main_module_callback(VMI_Callback_Params* params)
{
  if (target_cr3 != 0) {
    return;
  }
  if (params->cp.name == NULL) {
    return;
  }
  if (strcmp(params->cp.name, target_name) == 0) {
    DECAF_printf("Process %s(cr3: %d, pid: %d) you specified starts\n", params->cp.name, params->cp.cr3, params->cp.pid);
    target_cr3 = params->cp.cr3;
    //instruction_tracer_insn_end_handle
    //  = DECAF_register_callback(DECAF_INSN_BEGIN_CB, &instruction_tracer_insn_begin_callback, NULL);
    //DECAF_printf("DECAF_INSN_BEGIN_CB is registered\n");
    //instruction_tracer_insn_begin_handle
    //  = DECAF_register_callback(DECAF_INSN_END_CB, &instruction_tracer_insn_end_callback, NULL);
    //DECAF_printf("DECAF_INSN_END_CB is registered\n");
    //instruction_tracer_block_begin_handle
    //  = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, &instruction_tracer_block_begin_callback, NULL);
    //DECAF_printf("DECAF_BLOCK_BEGIN_CB is registered\n");
    //instruction_tracer_block_end_handle
    //  = DECAF_register_callback(DECAF_BLOCK_END_CB, &instruction_tracer_block_end_callback, NULL);
    //DECAF_printf("DECAF_BLOCK_END_CB is registered\n");
    instruction_tracer_block_trans_handle
      = DECAF_register_callback(DECAF_BLOCK_TRANS_CB, &instruction_tracer_block_trans_callback, NULL);

    if ((disas_logfile = fopen(LOGFILE_PATH, "w+")) == NULL) {
      DECAF_printf("log file open error!\n");
    }
  }
}

void do_instruction_trace(Monitor* monitor, const QDict* qdict)
{
  if (target_cr3 != 0) {
    return;
  }
  DECAF_printf("do_instruction_trace\n");
    if ((qdict != NULL) && (qdict_haskey(qdict, DICT_KEY_PROCNAME))) {
      strncpy(target_name, qdict_get_str(qdict, DICT_KEY_PROCNAME), TARGET_NAME_BUF_SIZE);
    }
    target_name[TARGET_NAME_BUF_SIZE - 1] = '\0';
}

static int instruction_tracer_init(void)
{
  DECAF_printf("initializing instruction tracer...\n");

  processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB,
      &instruction_tracer_load_main_module_callback, NULL);
  if (processbegin_handle == DECAF_NULL_HANDLE) {
    DECAF_printf("Could not register initial callback\n");
  }

    return 0;
}

static void instraction_tracer_cleanup(void)
{
  DECAF_printf("cleaning up instruction tracer...\n");
  if (processbegin_handle != DECAF_NULL_HANDLE) {
    VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);
    processbegin_handle = DECAF_NULL_HANDLE;
  }
  if (instruction_tracer_block_begin_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, instruction_tracer_block_begin_handle);
  }
  if (instruction_tracer_block_end_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_BLOCK_END_CB, instruction_tracer_block_end_handle);
  }
  if (instruction_tracer_insn_begin_callback != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, instruction_tracer_insn_begin_handle);
  }
  if (instruction_tracer_insn_end_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_END_CB, instruction_tracer_insn_end_handle);
  }

  if (disas_logfile != NULL) {
    fclose(disas_logfile);
  }
  DECAF_printf("cleaned up\n");
}

static mon_cmd_t instruction_tracer_term_cmds[] = {
  {
    .name         = "instruction_tracer",
    .args_type    = "procname:s?",
    .mhandler.cmd = do_instruction_trace,
    .params       = "[procname]",
    .help         = "Trace instructions of program [procname]"
  },
  {NULL, NULL, },
};

plugin_interface_t* init_plugin(void)
{
  DECAF_printf("start init_plugin\n");
  instruction_tracer_interface.mon_cmds = instruction_tracer_term_cmds;
  DECAF_printf("mon_cmds done\n");
  instruction_tracer_interface.plugin_cleanup = &instraction_tracer_cleanup;
  DECAF_printf("plugin_cleanup done\n");

  instruction_tracer_init();
  DECAF_printf("instruction_tracer done\n");
  return (&instruction_tracer_interface);
}

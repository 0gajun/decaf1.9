#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include "cpu-all.h"

#include "disas.h"

#define TARGET_NAME_BUF_SIZE 512
#define DICT_KEY_PROCNAME "procname"
#define LOGFILE_PATH "/tmp/decaf_instruction_trace.log"

#define MAX_CODE_BUF 5120

static plugin_interface_t instruction_tracer_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle processfinish_handle = DECAF_NULL_HANDLE;

static DECAF_Handle instruction_tracer_cpu_exec_handle = DECAF_NULL_HANDLE;

static char target_name[TARGET_NAME_BUF_SIZE];
static int target_name_len = TARGET_NAME_BUF_SIZE;
static uint32_t target_cr3 = 0;

FILE* disas_logfile;

target_ulong begin_pc;

static unsigned char code_buf[MAX_CODE_BUF];

static inline int is_target_program(CPUState* env)
{
  return env->cr[3] == target_cr3;
}

static void instruction_tracer_cpu_exec_callback(DECAF_Callback_Params* params)
{
  int i;

  if (params->ce.env == NULL) {
    DECAF_printf("NULL\n");
    return;
  }
  if (is_target_program(params->ce.env)) {
    /* if (params->ce.tb_size == 0) { */
    /*   DECAF_printf("\nnull is detected -> eip: 0x%x\n", params->ce.env->eip); */
    /*   fprintf(disas_logfile, "null member is detected\n"); */
    /*   return; */
    /* } */
    if (!params->ce.is_valid) {
      DECAF_printf("not valid\n\n");
      fprintf(disas_logfile, "null member is detected\n\n");
      return;
    }

    target_ulong d_pc = params->ce.tb_pc;
    target_ulong d_size = params->ce.tb_size;

    target_disas(disas_logfile, d_pc, d_size, 0);
    fprintf(disas_logfile, "=\n");

    for (i = 0; i < d_size && i < MAX_CODE_BUF; i++) {
      code_buf[i] = ldub_code(d_pc + i);
      fprintf(disas_logfile, "%02x", code_buf[i]);
    }

    /* if (i => MAX_CODE_BUF) { */
    /*   DECAF_printf("code buffer overflown\n"); */
    /*   code_buf[MAX_CODE_BUF - 1] = '\0'; */
    /* } else { */
    /*   code_buf[i] = '\0'; */
    /* } */

    //fwrite(code_buf, sizeof(unsigned char), i - 1, disas_logfile);

    fprintf(disas_logfile, "\n\n");
  }
}

static void instruction_tracer_process_finished_callback(VMI_Callback_Params* params)
{
  if (target_cr3 == params->rp.cr3) {
    DECAF_printf("target process finished...\n");
    fflush(disas_logfile);  
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
  if (strncmp(params->cp.name, target_name, target_name_len) == 0) {
    
    DECAF_printf("Process %s(cr3: %d, pid: %d) you specified starts\n", params->cp.name, params->cp.cr3, params->cp.pid);
    target_cr3 = params->cp.cr3;
    instruction_tracer_cpu_exec_handle
      = DECAF_register_callback(DECAF_CPU_EXEC_CB, &instruction_tracer_cpu_exec_callback, NULL);
    processfinish_handle
      = VMI_register_callback(VMI_REMOVEPROC_CB, &instruction_tracer_process_finished_callback, NULL);

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
      target_name_len = strlen(target_name);
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
  if (disas_logfile != NULL) {
    fclose(disas_logfile);
  }
  if (processbegin_handle != DECAF_NULL_HANDLE) {
    VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);
    processbegin_handle = DECAF_NULL_HANDLE;
  }
  if (instruction_tracer_cpu_exec_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_CPU_EXEC_CB, instruction_tracer_cpu_exec_handle);
    instruction_tracer_cpu_exec_handle = DECAF_NULL_HANDLE;
  }
  if (processfinish_handle != DECAF_NULL_HANDLE) {
    VMI_unregister_callback(VMI_REMOVEPROC_CB, processfinish_handle);
    processfinish_handle = DECAF_NULL_HANDLE;
  }
  DECAF_printf("cleaned up\n");
}

static mon_cmd_t instruction_tracer_term_cmds[] = {
  {
    .name         = "trace",
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

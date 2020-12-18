#include "hook_trace.h"


static void debugInfo(FILE* out,const void* ip)
{
	char *debuginfo_path=NULL;

	Dwfl_Callbacks callbacks={
		.find_elf=dwfl_linux_proc_find_elf,
		.find_debuginfo=dwfl_standard_find_debuginfo,
		.debuginfo_path=&debuginfo_path,
	};

	Dwfl* dwfl=dwfl_begin(&callbacks);
	assert(dwfl!=NULL);

	assert(dwfl_linux_proc_report (dwfl, getpid())==0);
	assert(dwfl_report_end (dwfl, NULL, NULL)==0);

	Dwarf_Addr addr = (uintptr_t)ip;

	Dwfl_Module* module=dwfl_addrmodule (dwfl, addr);

	const char *module_name = dwfl_module_info(
		module, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	fprintf(out, "%p in %s", ip, module_name);

	dwfl_end(dwfl); // required to avoid fd leak
}

void __attribute__((noinline)) printStackTrace(FILE* out, int skip)
{

	unw_context_t uc;
	unw_getcontext(&uc);

	unw_cursor_t cursor;
	unw_init_local(&cursor, &uc);

  fprintf(out, "stack trace: pid = %d\n", get_thread_id());
  fprintf(out, "------------------------------------------------------------\n");

	while(unw_step(&cursor)>0)
	{

		unw_word_t ip;
		unw_get_reg(&cursor, UNW_REG_IP, &ip);

		if (ip == 0) {
			break;
		}

		unw_word_t offset;
		char name[4096];
		int rc;
		if ((rc = unw_get_proc_name(&cursor, name,sizeof(name), &offset)) == 0) {
			if(skip<=0)
			{
				fprintf(out,"\tat ");
				debugInfo(out,(void*)(ip-5)); // ip stores the return address, here we pass ip-5 to point to the address of callq
				fprintf(out,"\n");
			}

			if(strcmp(name,"main")==0)
				break;

			skip--;
		}
		else if (rc == UNW_EUNSPEC) {
			printf("unw_get_proc_name: An unspecified error occurred.\n");
		}
		else if (rc == UNW_ENOINFO) {
			printf("unw_get_proc_name: Libunwind was unable to determine the name of the procedure.\n");
		}
		else if (rc == UNW_ENOMEM) {
			printf("unw_get_proc_name: The procedure name is too long to fit in the buffer provided. A truncated version of the name has been returned.\n");
		}
		else {
			printf("unw_get_proc_name: failure due to unknown reasons.\n");
		}
	}

  fprintf(out, "------------------------------------------------------------\n%c", 0);

  fflush(out);  // require in-time flush
}
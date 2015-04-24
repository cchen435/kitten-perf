#include <lwk/cpuinfo.h>
#include <arch/processor.h>
#include <arch/page.h>

// Impedance match with LWK name changes
#define cpuinfo_x86 cpuinfo
#define cpu_data(cpu) cpu_info[cpu].arch

#ifdef CONFIG_PERFCTR

#if CONFIG_SMP
#define current_cpu_data cpu_info[smp_processor_id()].arch
#else
#define cpu_data (&(boot_cpu_data.arch))
#define current_cput_data boot_cpu_data.arch
#endif

#endif

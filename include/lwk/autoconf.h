/*
 * Automatically generated C config: don't edit
 * LWK kernel version: 1.3.0Kitten
 * Wed Apr 22 18:43:05 2015
 */
#define AUTOCONF_INCLUDED
#define CONFIG_X86_64 1
#define CONFIG_X86 1
#define CONFIG_X86_MCE 1
#define CONFIG_X86_MCE_INJECT 1
#define CONFIG_OUTPUT_FORMAT "elf64-x86-64"
#define CONFIG_BFDARCH "i386"
#define CONFIG_KALLSYMS 1
#define CONFIG_KALLSYSM_ALL 1
#define CONFIG_LOCALVERSION_AUTO 1
#define CONFIG_PCI_DEVICE_DB 1

/*
 * Target Configuration
 */
#undef CONFIG_PC
#undef CONFIG_CRAY_GEMINI
#define CONFIG_PISCES 1
#undef CONFIG_MK8
#undef CONFIG_MPSC
#undef CONFIG_MK1OM
#define CONFIG_GENERIC_CPU 1
#define CONFIG_TIMER_PERIODIC 1
#undef CONFIG_TIMER_ONESHOT
#undef CONFIG_TASK_MEAS
#undef CONFIG_TASK_MEAS_INTEL_SANDY_MSR
#undef CONFIG_TASK_MEAS_INTEL_IVY_MSR
#define CONFIG_SCHED_EDF 1
#define CONFIG_SCHED_EDF_NWC 1
#undef CONFIG_SCHED_EDF_WC
#undef CONFIG_SCHED_EDF_RR
#define CONFIG_X86_CMOV 1
#define CONFIG_X86_L1_CACHE_BYTES 64
#define CONFIG_X86_L1_CACHE_SHIFT 6
#define CONFIG_X86_INTERNODE_CACHE_BYTES 64
#define CONFIG_X86_INTERNODE_CACHE_SHIFT 6
#define CONFIG_NR_CPUS 64
#define CONFIG_PHYSICAL_START 0x200000

/*
 * Virtualization
 */
#define CONFIG_PALACIOS 1
#undef CONFIG_PALACIOS_INTERNAL
#define CONFIG_PALACIOS_EXTERNAL 1
#define CONFIG_PALACIOS_PATH "../palacios"
#undef CONFIG_BUILT_IN_GUEST_OS
#define CONFIG_HAS_IOMEM 1
#define CONFIG_HAS_IOPORT 1
#define CONFIG_SMP 1
#define CONFIG_ACPI 1

/*
 * Networking
 */
#undef CONFIG_NETWORK

/*
 * Block Device
 */
#define CONFIG_BLOCK_DEVICE 1

/*
 * Device drivers
 */
#define CONFIG_DEVFS 1
#undef CONFIG_SATA

/*
 * Performance-monitoring counters support
 */
#define CONFIG_PERFCTR 1
#undef CONFIG_PERFCTR_INIT_TESTS
#define CONFIG_PERFCTR_VIRTUAL 1
#define CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK 1
#define CONFIG_XPMEM 1
#undef CONFIG_XPMEM_NS
#define CONFIG_XPMEM_FWD 1

/*
 * Kernel hacking
 */
#define CONFIG_DEBUG_KERNEL 1
#define CONFIG_LOG_BUF_SHIFT 15
#undef CONFIG_DEBUG_MUTEXES
#undef CONFIG_DEBUG_SPINLOCK
#undef CONFIG_DEBUG_SPINLOCK_SLEEP
#define CONFIG_DEBUG_INFO 1
#undef CONFIG_DEBUG_HW_NOISE
#undef CONFIG_KGDB
#define CONFIG_FRAME_POINTER 1
#undef CONFIG_UNWIND_INFO
#define CONFIG_FORCED_INLINING 1
#undef CONFIG_DEBUG_RODATA
#undef CONFIG_ACPI_DEBUG

/*
 * Linux Compatibility Layer
 */
#undef CONFIG_LINUX
#define CONFIG_X86_IO_APIC 1
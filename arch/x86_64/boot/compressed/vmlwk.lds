/*
 * Automatically generated C config: don't edit
 * LWK kernel version: 1.3.0Kitten
 * Wed Apr 22 18:43:05 2015
 */
/*
 * Target Configuration
 */
/*
 * Virtualization
 */
/*
 * Networking
 */
/*
 * Block Device
 */
/*
 * Device drivers
 */
/*
 * Performance-monitoring counters support
 */
/*
 * Kernel hacking
 */
/*
 * Linux Compatibility Layer
 */
/* Align . to a 8 byte boundary equals to maximum function alignment. */
/* .data section */
/* RODATA provided for backward compatibility.
 * All archs are supposed to use RO_DATA() */
/* .text section. Map to function alignment to avoid address changes
 * during second ld run in second ld pass when generating System.map */
/* sched.text is aling to function alignment to secure we have same
 * address even at second ld pass when generating System.map */
/* spinlock.text is aling to function alignment to secure we have same
 * address even at second ld pass when generating System.map */
  /* DWARF debug sections.
		Symbols in the DWARF debugging sections are relative to
		the beginning of the section so we begin them at 0.  */
  /* Stabs debugging sections.  */
/* const.h: Macros for dealing with constants.  */
/* Some constant macros are used in both assembler and
 * C code.  Therefore we cannot annotate them always with
 * 'UL' and other type specifiers unilaterally.  We
 * use the following macros to deal with this.
 */
/**
 * Define the base page size, 4096K on x86_64.
 * PAGE_SHIFT defines the base page size.
 */
/**
 * The kernel is mapped into the virtual address space of every task:
 *
 *     [PAGE_OFFSET, TOP_OF_MEMORY)  Kernel-space virtual memory region
 *     [0, PAGE_OFFSET]              User-space virtual memory region
 */
/**
 * The bootloader loads the LWK at address __PHYSICAL_START in physical memory.
 * This must be aligned on a 2 MB page boundary... or else.
 */
/**
 * If you hit this error when compiling the LWK, change your config file so that
 * CONFIG_PHYSICAL_START is aligned to a 2 MB boundary.
 */
/**
 * The kernel page tables map the kernel image text and data starting at
 * virtual address __START_KERNEL_map. The kernel text starts at
 * __START_KERNEL.
 */
/* See Documentation/x86_64/mm.txt for a description of the memory map. */
/**
 * Macros for converting between physical address and kernel virtual address.
 * NOTE: These only work for kernel virtual addresses in the identity map.
 */
OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(startup_64)
SECTIONS
{
 /* Be careful parts of head.S assume startup_32 is at
	 * address 0.
	 */
 . = 0;
 .text : {
  _head = . ;
  *(.text.head)
  _ehead = . ;
  *(.text.compressed)
  _text = .; /* Text */
  *(.text)
  *(.text.*)
  _etext = . ;
 }
 .rodata : {
  _rodata = . ;
  *(.rodata) /* read-only data */
  *(.rodata.*)
  _erodata = . ;
 }
 .data : {
  _data = . ;
  *(.data)
  *(.data.*)
  _edata = . ;
 }
 . = ALIGN(64);
 .bss : {
  _bss = . ;
  *(.bss)
  *(.bss.*)
  *(COMMON)
  . = ALIGN(8); /* For convenience during zeroing */
  _end = . ;
  . = ALIGN(4096);
  pgtable = . ;
  . = . + 4096 * 6;
  _heap = . ;
 }
}

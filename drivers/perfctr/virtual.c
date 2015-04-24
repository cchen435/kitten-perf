/* $Id: virtual.c,v 1.117 2007/10/06 13:02:07 mikpe Exp $
 * Virtual per-process performance counters.
 *
 * Copyright (C) 1999-2007  Mikael Pettersson
 */
#include <lwk/version.h>
#include <linux/init.h>
#include <linux/compiler.h>	/* for unlikely() in 2.4.18 and older */
#include <lwk/ptrace.h>
#include <lwk/kfs.h>
#include <linux/fs.h>

#include <linux/perfctr.h>

#include <asm/io.h>
#include <asm/uaccess.h>

#include "cpumask.h"
#include "virtual.h"

/****************************************************************
 *								*
 * Data types and macros.					*
 *								*
 ****************************************************************/

struct vperfctr {
/* User-visible fields: (must be first for mmap()) */
	struct perfctr_cpu_state cpu_state;
/* Kernel-private fields: */
	int si_signo;
	atomic_t count;
	spinlock_t owner_lock;
	struct task_struct *owner;
	/* sampling_timer and bad_cpus_allowed are frequently
	   accessed, so they get to share a cache line */
	unsigned int sampling_timer ____cacheline_aligned;
#ifdef CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK
	atomic_t bad_cpus_allowed;
#endif
	unsigned int preserve;
	unsigned int resume_cstatus;
#ifdef CONFIG_PERFCTR_INTERRUPT_SUPPORT
	unsigned int ireload_needed; /* only valid if resume_cstatus != 0 */
#endif
	/* children_lock protects inheritance_id and children,
	   when parent is not the one doing release_task() */
	spinlock_t children_lock;
	unsigned long long inheritance_id;
	struct perfctr_sum_ctrs children;
	/* schedule_work() data for when an operation cannot be
	   done in the current context due to locking rules */
	//struct work_struct work;
	struct task_struct *parent_tsk;
};


#define get_task_struct(tsk) do {} while(0)
#define put_task_struct(tsk) do {} while(0)
#define ptrace_check_attach(tsk, val) 1 

#define IS_RUNNING(perfctr)	perfctr_cstatus_enabled((perfctr)->cpu_state.user.cstatus)

/****************************************************************
 *								*
 * Resource management.						*
 *								*
 ****************************************************************/

/* Allocate a `struct vperfctr'. Claim and reserve
   an entire page so that it can be mmap():ed. */
static struct vperfctr *vperfctr_alloc(void)
{
	struct vperfctr *perf;

	//if (inc_nrctrs() != 0)
	//	return ERR_PTR(-EBUSY);
	perf = (struct vperfctr *) kmem_alloc (sizeof (struct vperfctr)); 
	if (!perf) {
		return ERR_PTR(-ENOMEM);
	}

	return perf;
}

static void vperfctr_free(struct vperfctr *perfctr)
{
	kmem_free(perfctr);
}

static struct vperfctr *get_empty_vperfctr(void)
{
	struct vperfctr *perfctr = vperfctr_alloc();
	if (!IS_ERR(perfctr)) {
		atomic_set(&perfctr->count, 1);
		spin_lock_init(&perfctr->owner_lock);
		spin_lock_init(&perfctr->children_lock);
	}
	return perfctr;
}

static void put_vperfctr(struct vperfctr *perfctr)
{
		vperfctr_free(perfctr);
}


/****************************************************************
 *								*
 * Basic counter operations.					*
 * These must all be called by the owner process only.		*
 * These must all be called with preemption disabled.		*
 *								*
 ****************************************************************/

/* PRE: IS_RUNNING(perfctr)
 * Suspend the counters.
 */
static inline void vperfctr_suspend(struct vperfctr *perfctr)
{
	perfctr_cpu_suspend(&perfctr->cpu_state);
}

/* PRE: perfctr == current->arch.thread.perfctr && IS_RUNNING(perfctr)
 * Restart the counters.
 */
static inline void vperfctr_resume(struct vperfctr *perfctr)
{
	perfctr_cpu_resume(&perfctr->cpu_state);
	//vperfctr_reset_sampling_timer(perfctr);
}

/* Sample the counters but do not suspend them. */
static void vperfctr_sample(struct vperfctr *perfctr)
{
	if (IS_RUNNING(perfctr)) {
		perfctr_cpu_sample(&perfctr->cpu_state);
	}
}

/****************************************************************
 *								*
 * Process management operations.				*
 * These must all, with the exception of vperfctr_unlink()	*
 * and __vperfctr_set_cpus_allowed(), be called by the owner	*
 * process only.						*
 *								*
 ****************************************************************/

/* Called from exit_thread() or do_vperfctr_unlink().
 * If the counters are running, stop them and sample their final values.
 * Mark the vperfctr object as dead.
 * Optionally detach the vperfctr object from its owner task.
 * PREEMPT note: exit_thread() does not run with preemption disabled.
 */
static void vperfctr_unlink(struct task_struct *owner, struct vperfctr *perfctr, int do_unlink)
{
	/* this synchronises with sys_vperfctr() */
	spin_lock(&perfctr->owner_lock);
	perfctr->owner = NULL;
	spin_unlock(&perfctr->owner_lock);

	/* perfctr suspend+detach must be atomic wrt process suspend */
	/* this also synchronises with perfctr_set_cpus_allowed() */
	//task_lock(owner);
	if (IS_RUNNING(perfctr) && owner == current)
		vperfctr_suspend(perfctr);
	if (do_unlink)
		owner->arch.thread.perfctr = NULL;
	//task_unlock(owner);

	perfctr->cpu_state.user.cstatus = 0;
	perfctr->resume_cstatus = 0;
	if (do_unlink)
		put_vperfctr(perfctr);
}

void __vperfctr_exit(struct vperfctr *perfctr)
{
	vperfctr_unlink(current, perfctr, 0);
}

/* schedule() --> switch_to() --> .. --> __vperfctr_suspend().
 * If the counters are running, suspend them.
 * PREEMPT note: switch_to() runs with preemption disabled.
 */
void __vperfctr_suspend(struct vperfctr *perfctr)
{
	if (IS_RUNNING(perfctr))
		vperfctr_suspend(perfctr);
}

/* schedule() --> switch_to() --> .. --> __vperfctr_resume().
 * PRE: perfctr == current->arch.thread.perfctr
 * If the counters are runnable, resume them.
 * PREEMPT note: switch_to() runs with preemption disabled.
 */
void __vperfctr_resume(struct vperfctr *perfctr)
{
	if (IS_RUNNING(perfctr)) {
		vperfctr_resume(perfctr);
	}
}

/* Called from update_one_process() [triggered by timer interrupt].
 * PRE: perfctr == current->thread.perfctr.
 * Sample the counters but do not suspend them.
 * Needed to avoid precision loss due to multiple counter
 * wraparounds between resume/suspend for CPU-bound processes.
 * PREEMPT note: called in IRQ context with preemption disabled.
 */
void __vperfctr_sample(struct vperfctr *perfctr)
{
	if (perfctr->sampling_timer == 0)
		vperfctr_sample(perfctr);
}

/****************************************************************
 *								*
 * Virtual perfctr system calls implementation.			*
 * These can be called by the owner process (tsk == current),	*
 * a monitor process which has the owner under ptrace ATTACH	*
 * control (tsk && tsk != current), or anyone with a handle to	*
 * an unlinked perfctr (!tsk).					*
 *								*
 ****************************************************************/

static int do_vperfctr_write(struct vperfctr *perfctr,
			     unsigned int domain,
			     const void __user *srcp,
			     unsigned int srcbytes,
			     struct task_struct *tsk)
{
	void *tmp;
	int err;

	if (!tsk)
		return -ESRCH;	/* attempt to update unlinked perfctr */

	if (srcbytes > PAGE_SIZE) /* primitive sanity check */
		return -EINVAL;
	tmp = kmem_alloc(srcbytes);
	if (!tmp)
		return -ENOMEM;
	err = -EFAULT;
	if (copy_from_user(tmp, srcp, srcbytes))
		goto out_kfree;

	if (IS_RUNNING(perfctr)) {
		if (tsk == current)
			vperfctr_suspend(perfctr);
		perfctr->cpu_state.user.cstatus = 0;
		perfctr->resume_cstatus = 0;
	}

	switch (domain) {
	case VPERFCTR_DOMAIN_CONTROL: {
		struct vperfctr_control control;

		err = -EINVAL;
		if (srcbytes > sizeof(control))
			break;
		control.si_signo = perfctr->si_signo;
		control.preserve = perfctr->preserve;
		memcpy(&control, tmp, srcbytes);
		/* XXX: validate si_signo? */
		perfctr->si_signo = control.si_signo;
		perfctr->preserve = control.preserve;
		err = 0;
		break;
	}
	case PERFCTR_DOMAIN_CPU_CONTROL:
		err = -EINVAL;
		if (srcbytes > sizeof(perfctr->cpu_state.control.header))
			break;
		memcpy(&perfctr->cpu_state.control.header, tmp, srcbytes);
		err = 0;
		break;
	case PERFCTR_DOMAIN_CPU_MAP:
		err = -EINVAL;
		if (srcbytes > sizeof(perfctr->cpu_state.control.pmc_map))
			break;
		memcpy(perfctr->cpu_state.control.pmc_map, tmp, srcbytes);
		err = 0;
		break;
	default:
		err = perfctr_cpu_control_write(&perfctr->cpu_state.control,
						domain, tmp, srcbytes);
	}

 out_kfree:
	kmem_free(tmp);
	return err;
}

static int vperfctr_enable_control(struct vperfctr *perfctr, struct task_struct *tsk)
{
	int err;
	unsigned int next_cstatus;
	unsigned int nrctrs, i;

	if (perfctr->cpu_state.control.header.nractrs ||
	    perfctr->cpu_state.control.header.nrictrs) {
		cpumask_t old_mask, new_mask;

		//old_mask = tsk->cpus_allowed;
		old_mask = tsk->cpu_mask;
		cpus_andnot(new_mask, old_mask, perfctr_cpus_forbidden_mask);

		if (cpus_empty(new_mask))
			return -EINVAL;
	}

	perfctr->cpu_state.user.cstatus = 0;
	perfctr->resume_cstatus = 0;

	/* remote access note: perfctr_cpu_update_control() is ok */
	err = perfctr_cpu_update_control(&perfctr->cpu_state, 0);
	if (err < 0)
		return err;
	next_cstatus = perfctr->cpu_state.user.cstatus;
	if (!perfctr_cstatus_enabled(next_cstatus))
		return 0;

	if (!perfctr_cstatus_has_tsc(next_cstatus))
		perfctr->cpu_state.user.tsc_sum = 0;

	nrctrs = perfctr_cstatus_nrctrs(next_cstatus);
	for(i = 0; i < nrctrs; ++i)
		if (!(perfctr->preserve & (1<<i)))
			perfctr->cpu_state.user.pmc[i].sum = 0;

	spin_lock(&perfctr->children_lock);
	memset(&perfctr->children, 0, sizeof perfctr->children);
	spin_unlock(&perfctr->children_lock);

	return 0;
}

static inline void vperfctr_ireload(struct vperfctr *perfctr)
{
#ifdef CONFIG_PERFCTR_INTERRUPT_SUPPORT
	if (perfctr->ireload_needed) {
		perfctr->ireload_needed = 0;
		/* remote access note: perfctr_cpu_ireload() is ok */
		perfctr_cpu_ireload(&perfctr->cpu_state);
	}
#endif
}

static int do_vperfctr_resume(struct vperfctr *perfctr, struct task_struct *tsk)
{
	unsigned int resume_cstatus;
	int ret;

	if (!tsk)
		return -ESRCH;	/* attempt to update unlinked perfctr */

	/* PREEMPT note: preemption is disabled over the entire
	   region because we're updating an active perfctr. */

	if (IS_RUNNING(perfctr) && tsk == current)
		vperfctr_suspend(perfctr);

	resume_cstatus = perfctr->resume_cstatus;
	if (perfctr_cstatus_enabled(resume_cstatus)) {
		perfctr->cpu_state.user.cstatus = resume_cstatus;
		perfctr->resume_cstatus = 0;
		vperfctr_ireload(perfctr);
		ret = 0;
	} else {
		ret = vperfctr_enable_control(perfctr, tsk);
		resume_cstatus = perfctr->cpu_state.user.cstatus;
	}

	if (ret >= 0 && perfctr_cstatus_enabled(resume_cstatus) && tsk == current)
		vperfctr_resume(perfctr);


	return ret;
}

static int do_vperfctr_suspend(struct vperfctr *perfctr, struct task_struct *tsk)
{
	if (!tsk)
		return -ESRCH;	/* attempt to update unlinked perfctr */

	/* PREEMPT note: preemption is disabled over the entire
	   region since we're updating an active perfctr. */

	if (IS_RUNNING(perfctr)) {
		if (tsk == current)
			vperfctr_suspend(perfctr);
		perfctr->resume_cstatus = perfctr->cpu_state.user.cstatus;
		perfctr->cpu_state.user.cstatus = 0;
	}


	return 0;
}

static int do_vperfctr_unlink(struct vperfctr *perfctr, struct task_struct *tsk)
{
	if (tsk)
		vperfctr_unlink(tsk, perfctr, 1);
	return 0;
}

static int do_vperfctr_clear(struct vperfctr *perfctr, struct task_struct *tsk)
{
	if (!tsk)
		return -ESRCH;	/* attempt to update unlinked perfctr */

	/* PREEMPT note: preemption is disabled over the entire
	   region because we're updating an active perfctr. */

	if (IS_RUNNING(perfctr) && tsk == current)
		vperfctr_suspend(perfctr);

	memset(&perfctr->cpu_state, 0, sizeof perfctr->cpu_state);
	perfctr->resume_cstatus = 0;

	spin_lock(&perfctr->children_lock);
	perfctr->inheritance_id = 0;
	memset(&perfctr->children, 0, sizeof perfctr->children);
	spin_unlock(&perfctr->children_lock);

	return 0;
}

static int do_vperfctr_control(struct vperfctr *perfctr,
			       unsigned int cmd,
			       struct task_struct *tsk)
{
	switch (cmd) {
	case VPERFCTR_CONTROL_UNLINK:
		return do_vperfctr_unlink(perfctr, tsk);
	case VPERFCTR_CONTROL_SUSPEND:
		return do_vperfctr_suspend(perfctr, tsk);
	case VPERFCTR_CONTROL_RESUME:
		return do_vperfctr_resume(perfctr, tsk);
	case VPERFCTR_CONTROL_CLEAR:
		return do_vperfctr_clear(perfctr, tsk);
	default:
		return -EINVAL;
	}
}

static int do_vperfctr_read(struct vperfctr *perfctr,
			    unsigned int domain,
			    void __user *dstp,
			    unsigned int dstbytes,
			    struct task_struct *tsk)
{
	union {
		struct perfctr_sum_ctrs sum;
		struct vperfctr_control control;
		struct perfctr_sum_ctrs children;
	} *tmp;
	unsigned int tmpbytes;
	int ret;

	tmpbytes = dstbytes;
	if (tmpbytes > PAGE_SIZE) /* primitive sanity check */
		return -EINVAL;
	if (tmpbytes < sizeof(*tmp))
		tmpbytes = sizeof(*tmp);
	tmp = kmem_alloc(tmpbytes);
	if (!tmp)
		return -ENOMEM;

	/* PREEMPT note: While we're reading our own control, another
	   process may ptrace ATTACH to us and update our control.
	   Disable preemption to ensure we get a consistent copy.
	   Not needed for other cases since the perfctr is either
	   unlinked or its owner is ptrace ATTACH suspended by us. */

	switch (domain) {
	case VPERFCTR_DOMAIN_SUM: {
		int j;

		vperfctr_sample(perfctr);
		tmp->sum.tsc = perfctr->cpu_state.user.tsc_sum;
		for(j = 0; j < ARRAY_SIZE(tmp->sum.pmc); ++j)
			tmp->sum.pmc[j] = perfctr->cpu_state.user.pmc[j].sum;
		ret = sizeof(tmp->sum);
		break;
	}
	case VPERFCTR_DOMAIN_CONTROL:
		tmp->control.si_signo = perfctr->si_signo;
		tmp->control.preserve = perfctr->preserve;
		ret = sizeof(tmp->control);
		break;
	case VPERFCTR_DOMAIN_CHILDREN:
		if (tsk)
			spin_lock(&perfctr->children_lock);
		tmp->children = perfctr->children;
		if (tsk)
			spin_unlock(&perfctr->children_lock);
		ret = sizeof(tmp->children);
		break;
	case PERFCTR_DOMAIN_CPU_CONTROL:
		if (tmpbytes > sizeof(perfctr->cpu_state.control.header))
			tmpbytes = sizeof(perfctr->cpu_state.control.header);
		memcpy(tmp, &perfctr->cpu_state.control.header, tmpbytes);
		ret = tmpbytes;
		break;
	case PERFCTR_DOMAIN_CPU_MAP:
		if (tmpbytes > sizeof(perfctr->cpu_state.control.pmc_map))
			tmpbytes = sizeof(perfctr->cpu_state.control.pmc_map);
		memcpy(tmp, perfctr->cpu_state.control.pmc_map, tmpbytes);
		ret = tmpbytes;
		break;
	default:
		ret = -EFAULT;
		if (copy_from_user(tmp, dstp, dstbytes) == 0)
			ret = perfctr_cpu_control_read(&perfctr->cpu_state.control,
						       domain, tmp, dstbytes);
	}

	if (ret > 0) {
		if (ret > dstbytes)
			ret = dstbytes;
		if (ret > 0 && copy_to_user(dstp, tmp, ret))
			ret = -EFAULT;
	}
	kmem_free(tmp);
	return ret;
}


/* new system API, not supportting file system */


asmlinkage long sys_vperfctr_init() 
{
	struct task_struct  *tsk;
	struct vperfctr *perfctr;

	int err;

	tsk = current; 
	perfctr = NULL;

	if (!tsk) {
		printk(KERN_INFO __FILE__ "vperfctr init: tsk is empty\n");
		return -1;
	}

	perfctr = tsk->arch.thread.perfctr;
	if (perfctr)
		return -EEXIST;

	perfctr = get_empty_vperfctr();
	if (IS_ERR(perfctr)) {
		printk(KERN_INFO __FILE__ "vperfctr init: cannot get empty vperfctr\n");
		err = PTR_ERR(perfctr);
		return err;
	}

	perfctr->owner = tsk;
	tsk->arch.thread.perfctr = perfctr;

	return 0; 
}


asmlinkage long sys_vperfctr_write(unsigned int domain, 
									const void __user *argp,
									unsigned int argbytes)
{
	struct vperfctr *perfctr;
	struct task_struct *tsk;
	int ret;

	tsk = current;
	if (IS_ERR(tsk)) {
		printk(KERN_INFO __FILE__ "vperfctr write: tsk is empty\n");
		return PTR_ERR(tsk);
	}

	perfctr = tsk->arch.thread.perfctr;

	if (IS_ERR(perfctr)) {
		printk(KERN_INFO __FILE__ "vperfctr write: perfct is empty\n");
		return PTR_ERR(perfctr);
	}

	ret = do_vperfctr_write(perfctr, domain, argp, argbytes, tsk);
	return ret;
}


asmlinkage long sys_vperfctr_control(unsigned int cmd)
{
	struct vperfctr *perfctr;
	struct task_struct *tsk;
	int ret;

	tsk = current;
	if (IS_ERR(tsk)) {
		printk(KERN_INFO __FILE__ "vperfctr control: tsk is empty\n");
		return PTR_ERR(tsk);
	}

	perfctr = tsk->arch.thread.perfctr;

	if (IS_ERR(perfctr)) {
		printk(KERN_INFO __FILE__ "vperfctr control: perfct is empty\n");
		return PTR_ERR(perfctr);
	}

	ret = do_vperfctr_control(perfctr, cmd, tsk);
	return ret;
}


asmlinkage long sys_vperfctr_read(unsigned int domain, void __user *argp,
		unsigned int argbytes)
{
	struct vperfctr *perfctr;
	struct task_struct *tsk;
	int ret;
	
	tsk = current;
	if (IS_ERR(tsk)) {
		printk(KERN_INFO __FILE__ "vperfctr read: tsk is empty\n");
		return PTR_ERR(tsk);
	}

	perfctr = tsk->arch.thread.perfctr;

	if (IS_ERR(perfctr)) {
		printk(KERN_INFO __FILE__ "vperfctr read: perfct is empty\n");
		return PTR_ERR(perfctr);
	}

	ret = do_vperfctr_read(perfctr, domain, argp, argbytes, tsk);
	return ret;
}

/****************************************************************
 *								*
 * module_init/exit						*
 *								*
 ****************************************************************/
int __init vperfctr_init(void)
{
	//return vperfctrfs_init();
	return 0;
}

void __exit vperfctr_exit(void)
{
	//vperfctrfs_exit();
	return;
}


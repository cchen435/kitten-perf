

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
	struct task_struck *tsk;
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




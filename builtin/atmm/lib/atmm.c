// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/pgtable.h>
#include <asm/pgtable.h>
#include <asm/sysreg.h>
#include <asm/cacheflush.h>

#include "atmm.h"

static int atmm_safe_read(void *dst, const void *src, size_t sz)
{
	return copy_from_kernel_nofault(dst, src, sz);
}

static int atmm_soft_walk(struct mm_struct *mm, unsigned long va,
			  unsigned long *pa)
{
	pgd_t pgdv;
	p4d_t p4dv;
	pud_t pudv;
	pmd_t pmdv;
	pte_t ptev;
	unsigned long v;
	unsigned long phys;

	if (!mm || !mm->pgd)
		return -EINVAL;

	if (atmm_safe_read(&pgdv, (void *)pgd_offset(mm, va), sizeof(pgdv)))
		return -EFAULT;
	if (pgd_none(pgdv))
		return -ENOENT;

	if (atmm_safe_read(&p4dv, (void *)p4d_offset(&pgdv, va), sizeof(p4dv)))
		return -EFAULT;
	if (p4d_none(p4dv))
		return -ENOENT;

	if (atmm_safe_read(&pudv, (void *)pud_offset(&p4dv, va), sizeof(pudv)))
		return -EFAULT;
	if (pud_none(pudv))
		return -ENOENT;

	if (atmm_safe_read(&pmdv, (void *)pmd_offset(&pudv, va), sizeof(pmdv)))
		return -EFAULT;
	if (pmd_none(pmdv))
		return -ENOENT;
	if (pmd_leaf(pmdv)) {
		v = pmd_val(pmdv);
		phys = (v & PHYS_MASK & ~((1UL << 21) - 1)) |
			(va & ((1UL << 21) - 1));
		*pa = phys;
		return 0;
	}

	if (atmm_safe_read(&ptev,
			   (void *)pte_offset_kernel(&pmdv, va), sizeof(ptev)))
		return -EFAULT;
	if (pte_none(ptev))
		return -ENOENT;

	phys = page_to_phys(pte_page(ptev)) | (va & ~PAGE_MASK);
	*pa = phys;
	return 0;
}

int atmm_translate(pid_t pid, unsigned long va, unsigned long *pa)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	u64 ttbr0;
	u64 new_ttbr0;
	u64 par;
	unsigned long out;
	int ret;

	if (!pa)
		return -EINVAL;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return -ESRCH;
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return -ESRCH;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ESRCH;

	if (!mm->pgd) {
		mmput(mm);
		return -EINVAL;
	}

	preempt_disable();
	ttbr0 = read_sysreg_s(SYS_TTBR0_EL1);
	new_ttbr0 = ((u64)ASID(mm) << 48) | virt_to_phys(mm->pgd) | 1;
	dsb(ish);
	asm volatile("msr ttbr0_el1, %0" : : "r"(new_ttbr0));
	dsb(ish);
	isb();
	asm volatile("at s1e0r, %0" : : "r"(va));
	isb();
	par = read_sysreg_s(SYS_PAR_EL1);
	dsb(ish);
	asm volatile("msr ttbr0_el1, %0" : : "r"(ttbr0));
	dsb(ish);
	isb();
	preempt_enable();

	if (par & 1) {
		ret = atmm_soft_walk(mm, va, &out);
		mmput(mm);
		if (ret)
			return ret;
	} else {
		out = ((par >> 12) & 0xFFFFFFFFFULL) << 12 | (va & 0xFFF);
		mmput(mm);
	}

	*pa = out;
	return 0;
}

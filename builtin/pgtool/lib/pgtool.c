// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pgtable.h>
#include <asm/memory.h>
#include <asm/pgtable.h>

#include "atmm.h"
#include "pgtool.h"

#if CONFIG_PGTABLE_LEVELS < 3
#error pgtool needs CONFIG_PGTABLE_LEVELS >= 3
#endif

#define PG_ATTR_INDEX(value)	(((value) & PTE_ATTRINDX_MASK) >> 2)

struct pg_symbols {
	struct pid *(*find_get_pid)(int nr);
	struct task_struct *(*get_pid_task)(struct pid *pid, enum pid_type type);
	void (*put_pid)(struct pid *pid);
	void (*put_task_struct)(struct task_struct *task);
	struct mm_struct *(*get_task_mm)(struct task_struct *task);
	void (*mmput)(struct mm_struct *mm);
	long (*copy_from_kernel_nofault)(void *dst, const void *src, size_t size);
};

struct pg_run {
	unsigned long vaddr;
	unsigned long paddr;
	unsigned long size;
	u64 raw;
	u32 flags;
	u8 level;
};

struct pg_walk {
	int (*visit)(const struct pg_segment *seg, void *arg);
	void *arg;
	struct pg_stats stats;
	struct pg_run run;
	unsigned long start;
	unsigned long end;
	bool open;
	bool clamp;
};

static struct pg_symbols pg_sym;
static bool pg_on = true;

/*
 * Every indirect call to a resolved symbol sits in a __nocfi function, the
 * prototypes above are the kernel ones of 5.10 up to 6.12.
 */
static __nocfi long pg_nofault_read(void *dst, const void *src, size_t size)
{
	return pg_sym.copy_from_kernel_nofault(dst, src, size);
}

static __nocfi struct pid *pg_pid_get(int nr)
{
	return pg_sym.find_get_pid(nr);
}

static __nocfi struct task_struct *pg_pid_task(struct pid *pid)
{
	return pg_sym.get_pid_task(pid, PIDTYPE_PID);
}

static __nocfi void pg_pid_put(struct pid *pid)
{
	pg_sym.put_pid(pid);
}

static __nocfi void pg_task_put(struct task_struct *task)
{
	pg_sym.put_task_struct(task);
}

static __nocfi struct mm_struct *pg_task_mm(struct task_struct *task)
{
	return pg_sym.get_task_mm(task);
}

static __nocfi void pg_mm_put(struct mm_struct *mm)
{
	pg_sym.mmput(mm);
}

int pg_init(const struct pg_cfg *cfg)
{
	unsigned long addr;

	if (!cfg || !cfg->resolve) {
		return -EINVAL;
	}

	addr = cfg->resolve("find_get_pid");
	if (!addr) {
		return -ENODATA;
	}
	pg_sym.find_get_pid = (struct pid *(*)(int))addr;

	addr = cfg->resolve("get_pid_task");
	if (!addr) {
		return -ENODATA;
	}
	pg_sym.get_pid_task = (struct task_struct *(*)(struct pid *,
						       enum pid_type))addr;

	addr = cfg->resolve("put_pid");
	if (!addr) {
		return -ENODATA;
	}
	pg_sym.put_pid = (void (*)(struct pid *))addr;

	addr = cfg->resolve("put_task_struct");
	if (!addr) {
		return -ENODATA;
	}
	pg_sym.put_task_struct = (void (*)(struct task_struct *))addr;

	addr = cfg->resolve("get_task_mm");
	if (!addr) {
		return -ENODATA;
	}
	pg_sym.get_task_mm = (struct mm_struct *(*)(struct task_struct *))addr;

	addr = cfg->resolve("mmput");
	if (!addr) {
		return -ENODATA;
	}
	pg_sym.mmput = (void (*)(struct mm_struct *))addr;

	addr = cfg->resolve("copy_from_kernel_nofault");
	if (!addr) {
		return -ENODATA;
	}
	pg_sym.copy_from_kernel_nofault = (long (*)(void *, const void *,
						    size_t))addr;

	pg_on = true;
	return 0;
}

void pg_exit(void)
{
	pg_sym.find_get_pid = NULL;
	pg_sym.get_pid_task = NULL;
	pg_sym.put_pid = NULL;
	pg_sym.put_task_struct = NULL;
	pg_sym.get_task_mm = NULL;
	pg_sym.mmput = NULL;
	pg_sym.copy_from_kernel_nofault = NULL;
}

void pg_enable(bool on)
{
	pg_on = on;
}

bool pg_enabled(void)
{
	return pg_on;
}

unsigned long pg_va_limit(void)
{
	return 1UL << VA_BITS;
}

static int pg_check(void)
{
	if (!pg_on) {
		return -EPERM;
	}
	if (!pg_sym.find_get_pid) {
		return -ENODATA;
	}
	return 0;
}

int pg_open_pid(struct pg_ctx *ctx, pid_t pid)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	int ret;

	ret = pg_check();
	if (ret) {
		return ret;
	}
	if (!ctx) {
		return -EINVAL;
	}

	pid_struct = pg_pid_get(pid);
	if (!pid_struct) {
		return -ESRCH;
	}
	task = pg_pid_task(pid_struct);
	pg_pid_put(pid_struct);
	if (!task) {
		return -ESRCH;
	}
	mm = pg_task_mm(task);
	pg_task_put(task);
	if (!mm || !mm->pgd) {
		if (mm) {
			pg_mm_put(mm);
		}
		return -ESRCH;
	}

	ctx->mm = mm;
	ctx->pid = pid;
	return 0;
}

int pg_open_mm(struct pg_ctx *ctx, struct mm_struct *mm)
{
	int ret;

	ret = pg_check();
	if (ret) {
		return ret;
	}
	if (!ctx || !mm || !mm->pgd) {
		return -EINVAL;
	}

	mmget(mm);
	ctx->mm = mm;
	ctx->pid = 0;
	return 0;
}

void pg_close(struct pg_ctx *ctx)
{
	if (!ctx || !ctx->mm) {
		return;
	}
	pg_mm_put(ctx->mm);
	ctx->mm = NULL;
	ctx->pid = 0;
}

static bool pg_leaf_device(pte_t attr)
{
	unsigned long index = PG_ATTR_INDEX(pte_val(attr));

	if (index == MT_DEVICE_nGnRnE || index == MT_DEVICE_nGnRE) {
		return true;
	}
#ifdef MT_DEVICE_GRE
	/* the GRE index is gone from arm64 in 6.x */
	if (index == MT_DEVICE_GRE) {
		return true;
	}
#endif
	return false;
}

static u32 pg_leaf_flags(pte_t attr)
{
	u32 flags = 0;

	if (pte_write(attr)) {
		flags |= PG_FLAG_WRITE;
	}
	if (pte_user_exec(attr)) {
		flags |= PG_FLAG_EXEC;
	}
	/* pte_user exists from 6.1 only, the bit test is the same predicate */
	if (pte_val(attr) & PTE_USER) {
		flags |= PG_FLAG_USER;
	}
	if (pte_dirty(attr)) {
		flags |= PG_FLAG_DIRTY;
	}
	if (pte_young(attr)) {
		flags |= PG_FLAG_YOUNG;
	}
	if (pte_special(attr)) {
		flags |= PG_FLAG_SPECIAL;
	}
	if (pte_cont(attr)) {
		flags |= PG_FLAG_CONT;
	}
	if (pg_leaf_device(attr)) {
		flags |= PG_FLAG_DEVICE;
	}
	return flags;
}

static int pg_flush(struct pg_walk *walk)
{
	struct pg_segment seg;

	if (!walk->open) {
		return 0;
	}
	walk->open = false;
	if (!walk->visit) {
		return 0;
	}

	seg.vaddr = walk->run.vaddr;
	seg.paddr = walk->run.paddr;
	seg.size = walk->run.size;
	seg.raw = walk->run.raw;
	seg.flags = walk->run.flags;
	seg.level = walk->run.level;
	return walk->visit(&seg, walk->arg);
}

static int pg_emit(struct pg_walk *walk, const struct pg_run *leaf)
{
	int ret;

	if (walk->open && walk->run.level == leaf->level &&
	    walk->run.flags == leaf->flags &&
	    walk->run.vaddr + walk->run.size == leaf->vaddr &&
	    walk->run.paddr + walk->run.size == leaf->paddr) {
		walk->run.size += leaf->size;
		return 0;
	}

	ret = pg_flush(walk);
	if (ret) {
		return ret;
	}
	walk->run = *leaf;
	walk->open = true;
	return 0;
}

static int pg_leaf(struct pg_walk *walk, unsigned long addr, unsigned long size,
		   unsigned long raw, pte_t attr, u8 level)
{
	struct pg_run leaf;
	unsigned long base;
	unsigned long skip;

	/*
	 * A window can start inside a huge leaf, the segment is then trimmed on
	 * both ends, size never covers anything outside [start, end).
	 */
	base = addr & ~(size - 1);
	leaf.vaddr = base;
	leaf.paddr = pte_pfn(attr) << PAGE_SHIFT;
	leaf.size = size;
	leaf.raw = raw;
	leaf.flags = pg_leaf_flags(attr);
	leaf.level = level;

	if (walk->clamp && base < walk->start) {
		skip = walk->start - base;
		leaf.vaddr += skip;
		leaf.paddr += skip;
		leaf.size -= skip;
	}
	if (walk->clamp && leaf.vaddr + leaf.size > walk->end) {
		leaf.size = walk->end - leaf.vaddr;
	}

	if (level == PG_LEVEL_PUD) {
		walk->stats.huge_pud++;
	} else if (level == PG_LEVEL_PMD) {
		walk->stats.huge_pmd++;
	}
	if (pte_write(attr)) {
		walk->stats.writable++;
	} else {
		walk->stats.readonly++;
	}
	if (pte_user_exec(attr)) {
		walk->stats.executable++;
	}
	if (pte_dirty(attr)) {
		walk->stats.dirty++;
	}
	walk->stats.mapped_bytes += leaf.size;
	return pg_emit(walk, &leaf);
}

static int pg_read_entry(struct pg_walk *walk, void *dst, const void *src,
			 size_t size)
{
	if (pg_nofault_read(dst, src, size)) {
		walk->stats.unreadable++;
		return -EFAULT;
	}
	return 0;
}

static int pg_walk_pte(struct pg_walk *walk, pmd_t pmdv, unsigned long addr,
		       unsigned long end)
{
	pte_t ptev;
	pte_t *ptep;
	int ret;

	ptep = pte_offset_kernel(&pmdv, addr);
	for (; addr < end; addr += PAGE_SIZE, ptep++) {
		if (pg_read_entry(walk, &ptev, ptep, sizeof(ptev))) {
			continue;
		}
		if (pte_none(ptev) || !pte_present(ptev)) {
			continue;
		}
		walk->stats.present++;
		ret = pg_leaf(walk, addr, PAGE_SIZE, pte_val(ptev), ptev,
			      PG_LEVEL_PTE);
		if (ret) {
			return ret;
		}
	}
	return 0;
}

static int pg_step_pmd(struct pg_walk *walk, pmd_t *pmdp, unsigned long addr,
		       unsigned long next)
{
	pmd_t pmdv;

	if (pg_read_entry(walk, &pmdv, pmdp, sizeof(pmdv))) {
		return 0;
	}
	if (pmd_none(pmdv)) {
		return 0;
	}
	if (pmd_leaf(pmdv)) {
		return pg_leaf(walk, addr, PMD_SIZE, pmd_val(pmdv),
			       pmd_pte(pmdv), PG_LEVEL_PMD);
	}
	if (pmd_bad(pmdv)) {
		return 0;
	}
	return pg_walk_pte(walk, pmdv, addr, next);
}

static int pg_walk_pmd(struct pg_walk *walk, pud_t pudv, unsigned long addr,
		       unsigned long end)
{
	pmd_t *pmdp;
	unsigned long next;
	int ret = 0;

	pmdp = pmd_offset(&pudv, addr);
	do {
		next = pmd_addr_end(addr, end);
		ret = pg_step_pmd(walk, pmdp, addr, next);
		if (ret) {
			break;
		}
		addr = next;
		pmdp++;
	} while (addr != end);
	return ret;
}

static int pg_step_pud(struct pg_walk *walk, pud_t *pudp, unsigned long addr,
		       unsigned long next)
{
	pud_t pudv;

	if (pg_read_entry(walk, &pudv, pudp, sizeof(pudv))) {
		return 0;
	}
	if (pud_none(pudv)) {
		return 0;
	}
	if (pud_leaf(pudv)) {
		return pg_leaf(walk, addr, PUD_SIZE, pud_val(pudv),
			       pud_pte(pudv), PG_LEVEL_PUD);
	}
	if (pud_bad(pudv)) {
		return 0;
	}
	return pg_walk_pmd(walk, pudv, addr, next);
}

static int pg_walk_pud(struct pg_walk *walk, p4d_t p4dv, unsigned long addr,
		       unsigned long end)
{
	pud_t *pudp;
	unsigned long next;
	int ret = 0;

	pudp = pud_offset(&p4dv, addr);
	do {
		next = pud_addr_end(addr, end);
		ret = pg_step_pud(walk, pudp, addr, next);
		if (ret) {
			break;
		}
		addr = next;
		pudp++;
	} while (addr != end);
	return ret;
}

static int pg_step_p4d(struct pg_walk *walk, p4d_t *p4dp, unsigned long addr,
		       unsigned long next)
{
	p4d_t p4dv;

	if (pg_read_entry(walk, &p4dv, p4dp, sizeof(p4dv))) {
		return 0;
	}
	if (p4d_none(p4dv) || p4d_bad(p4dv)) {
		return 0;
	}
	return pg_walk_pud(walk, p4dv, addr, next);
}

static int pg_walk_p4d(struct pg_walk *walk, pgd_t pgdv, unsigned long addr,
		       unsigned long end)
{
	p4d_t *p4dp;
	unsigned long next;
	int ret = 0;

	p4dp = p4d_offset(&pgdv, addr);
	do {
		next = p4d_addr_end(addr, end);
		ret = pg_step_p4d(walk, p4dp, addr, next);
		if (ret) {
			break;
		}
		addr = next;
		p4dp++;
	} while (addr != end);
	return ret;
}

static int pg_step_pgd(struct pg_walk *walk, pgd_t *pgdp, unsigned long addr,
		       unsigned long next)
{
	pgd_t pgdv;

	if (pg_read_entry(walk, &pgdv, pgdp, sizeof(pgdv))) {
		return 0;
	}
	if (pgd_none(pgdv) || pgd_bad(pgdv)) {
		return 0;
	}
	return pg_walk_p4d(walk, pgdv, addr, next);
}

static int pg_walk_pgd(struct pg_walk *walk, struct mm_struct *mm,
		       unsigned long start, unsigned long end)
{
	pgd_t *pgdp;
	unsigned long addr;
	unsigned long next;
	int ret = 0;

	addr = start;
	pgdp = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		ret = pg_step_pgd(walk, pgdp, addr, next);
		if (ret) {
			break;
		}
		addr = next;
		pgdp++;
	} while (addr != end);
	return ret;
}

static int pg_window(struct pg_ctx *ctx, unsigned long start, unsigned long end)
{
	int ret;

	ret = pg_check();
	if (ret) {
		return ret;
	}
	if (!ctx || !ctx->mm) {
		return -EINVAL;
	}
	if (!PAGE_ALIGNED(start) || !PAGE_ALIGNED(end) || start >= end) {
		return -EINVAL;
	}
	if (end > pg_va_limit()) {
		return -EINVAL;
	}
	return 0;
}

int pg_walk(struct pg_ctx *ctx, unsigned long start, unsigned long end,
	    int (*visit)(const struct pg_segment *seg, void *arg), void *arg)
{
	struct pg_walk walk = { 0 };
	int ret;

	ret = pg_window(ctx, start, end);
	if (ret) {
		return ret;
	}

	walk.visit = visit;
	walk.arg = arg;
	walk.start = start;
	walk.end = end;
	walk.clamp = true;
	ret = pg_walk_pgd(&walk, ctx->mm, start, end);
	if (ret) {
		return ret;
	}
	return pg_flush(&walk);
}

int pg_stat(struct pg_ctx *ctx, unsigned long start, unsigned long end,
	    struct pg_stats *stats)
{
	struct pg_walk walk = { 0 };
	int ret;

	if (!stats) {
		return -EINVAL;
	}
	ret = pg_window(ctx, start, end);
	if (ret) {
		return ret;
	}

	walk.start = start;
	walk.end = end;
	walk.clamp = true;
	ret = pg_walk_pgd(&walk, ctx->mm, start, end);
	if (ret) {
		return ret;
	}
	*stats = walk.stats;
	return 0;
}

struct pg_first {
	struct pg_segment seg;
	bool found;
};

static int pg_take_first(const struct pg_segment *seg, void *arg)
{
	struct pg_first *first = arg;

	first->seg = *seg;
	first->found = true;
	return 1;
}

int pg_lookup(struct pg_ctx *ctx, unsigned long vaddr, struct pg_segment *seg)
{
	struct pg_first first = { 0 };
	struct pg_walk walk = { 0 };
	unsigned long start;
	int ret;

	if (!seg) {
		return -EINVAL;
	}
	start = vaddr & PAGE_MASK;
	ret = pg_window(ctx, start, start + PAGE_SIZE);
	if (ret) {
		return ret;
	}

	walk.visit = pg_take_first;
	walk.arg = &first;
	walk.start = start;
	walk.end = start + PAGE_SIZE;
	ret = pg_walk_pgd(&walk, ctx->mm, start, start + PAGE_SIZE);
	if (ret < 0) {
		return ret;
	}
	if (walk.open) {
		ret = pg_flush(&walk);
		if (ret < 0) {
			return ret;
		}
	}
	if (!first.found) {
		return -ENOENT;
	}
	*seg = first.seg;
	return 0;
}

int pg_query(struct pg_ctx *ctx, unsigned long vaddr, unsigned long *paddr)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	int ret;

	ret = pg_check();
	if (ret) {
		return ret;
	}
	if (!ctx || !ctx->mm || !paddr) {
		return -EINVAL;
	}
	if (vaddr >= pg_va_limit()) {
		return -EINVAL;
	}
	if (!ctx->pid) {
		return -EOPNOTSUPP;
	}

	pid_struct = pg_pid_get(ctx->pid);
	if (!pid_struct) {
		return -ESRCH;
	}
	task = pg_pid_task(pid_struct);
	pg_pid_put(pid_struct);
	if (!task) {
		return -ESRCH;
	}
	mm = pg_task_mm(task);
	pg_task_put(task);
	if (mm != ctx->mm) {
		if (mm) {
			pg_mm_put(mm);
		}
		return -ESRCH;
	}
	pg_mm_put(mm);
	return atmm_translate(ctx->pid, vaddr, paddr);
}

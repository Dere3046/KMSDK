// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/thread_info.h>
#include <linux/version.h>

#include "type_info.h"
#include "seccomp.h"

#define SC_BTF_KIND_STRUCT 4

/*
 * The layout of the running kernel is the authority. The task and seccomp
 * members below are public types and the compiler resolves them, the filter
 * cache is not: struct seccomp_filter and struct action_cache live inside
 * kernel/seccomp.c and only an opaque forward declaration reaches a module, so
 * their offsets exist at runtime through BTF or not at all. This library does
 * not guess an offset for a type it cannot see.
 */
struct sc_layout {
	long off_filter_cache;
	long off_cache_allow_native;
	bool ok;
};

struct sc_syms {
	void (*filter_release)(struct task_struct *tsk);
	long (*copy_from_kernel_nofault)(void *dst, const void *src, size_t size);
	int (*lookup_size_offset)(unsigned long addr, unsigned long *size,
				  unsigned long *offset);
};

static struct ti_ctx *sc_btf;
static bool sc_ti_owner;
static struct sc_layout sc_geo;
static struct sc_syms sc_sym;

/*
 * The release routine changed shape inside the 6.6 to 6.11 window, older
 * images detach the filter under the siglock and expect a task without a
 * sighand, newer ones take the siglock themselves and expect PF_EXITING, and
 * some stable backports carry the newer body on an older version number. The
 * prologue is probed for the bit test of PF_EXITING so the running image and
 * not a version macro decides the shape.
 */
static bool sc_exiting_gate;

#define SC_PF_EXITING_BIT 2
#define SC_PROBE_INSNS 32

/*
 * tbnz or tbz, the opcode sits in 31:24 with its low bit selecting the taken
 * sense, the bit position sits in 23:19
 */
#define SC_ARM64_BIT_BRANCH_OPC 0x36000000
#define SC_ARM64_BIT_BRANCH_MASK 0x7e000000
#define SC_ARM64_BIT_POS_MASK 0x1f

static bool sc_has_exiting_gate(const unsigned long *insn, u32 count)
{
	u32 i;

	for (i = 0; i < count; i++) {
		if ((insn[i] & SC_ARM64_BIT_BRANCH_MASK) !=
		    SC_ARM64_BIT_BRANCH_OPC)
			continue;
		if (((insn[i] >> 19) & SC_ARM64_BIT_POS_MASK) ==
		    SC_PF_EXITING_BIT)
			return true;
	}
	return false;
}

static __nocfi long sc_call_copy_nofault(void *dst, const void *src,
					   size_t size)
{
	return sc_sym.copy_from_kernel_nofault(dst, src, size);
}

static __nocfi int sc_call_lookup_size(unsigned long addr,
				       unsigned long *size,
				       unsigned long *offset)
{
	return sc_sym.lookup_size_offset(addr, size, offset);
}

static void sc_probe_release_shape(unsigned long addr)
{
	unsigned long size = 0;
	unsigned long insn[SC_PROBE_INSNS];
	u32 count;

	if (!addr || !sc_sym.copy_from_kernel_nofault)
		return;
	if (sc_sym.lookup_size_offset &&
	    sc_call_lookup_size(addr, &size, NULL))
		size = 0;
	if (!size)
		size = sizeof(insn);
	count = min_t(unsigned long, size, sizeof(insn)) / sizeof(insn[0]);
	if (!count)
		return;
	if (sc_call_copy_nofault(insn, (const void *)addr,
					    count * sizeof(insn[0])))
		return;
	sc_exiting_gate = sc_has_exiting_gate(insn, count);
}

static bool sc_read_member(struct ti_ctx *ctx, const char *type,
			   const char *member, long *out)
{
	u32 id, bit_off, bit_sz;

	if (ti_type_by_name(ctx, type, BIT(SC_BTF_KIND_STRUCT), &id))
		return false;
	if (ti_member_off(ctx, id, member, &bit_off, &bit_sz))
		return false;
	if (bit_off % 8 || bit_sz != 0)
		return false;
	*out = bit_off / 8;
	return true;
}

int seccomp_init(const struct seccomp_cfg *cfg)
{
	struct ti_resolver res;
	int ret;

	if (!cfg || !cfg->resolve)
		return -EINVAL;
	res.name_to_addr = cfg->resolve;

	memset(&sc_geo, 0, sizeof(sc_geo));
	memset(&sc_sym, 0, sizeof(sc_sym));
	sc_exiting_gate = false;

	/*
	 * A type_info base another library already brought up is adopted, only a
	 * base this library creates is torn down again, so a library that shares
	 * the instance keeps working after seccomp_exit.
	 */
	if (ti_ready()) {
		sc_btf = ti_base();
	} else {
		ret = ti_init(&res);
		if (ret)
			return ret;
		sc_btf = ti_base();
		sc_ti_owner = true;
	}
	if (!sc_btf)
		return -ENODATA;

	/*
	 * Only the filter cache needs runtime offsets, every task and seccomp
	 * member this library writes is public and the compiler resolves it. A
	 * kernel whose BTF does not carry the filter layout is refused rather
	 * than served with a guessed offset.
	 */
	if (sc_read_member(sc_btf, "seccomp_filter", "cache",
			   &sc_geo.off_filter_cache) ||
	    sc_read_member(sc_btf, "action_cache", "allow_native",
			   &sc_geo.off_cache_allow_native))
		return -ENODATA;
	sc_geo.ok = true;

	sc_sym.filter_release = (void *)cfg->resolve("seccomp_filter_release");
	sc_sym.copy_from_kernel_nofault =
		(void *)cfg->resolve("copy_from_kernel_nofault");
	sc_sym.lookup_size_offset =
		(void *)cfg->resolve("kallsyms_lookup_size_offset");
	if (!sc_sym.filter_release || !sc_sym.copy_from_kernel_nofault)
		return -ENOSYS;

	sc_probe_release_shape((unsigned long)sc_sym.filter_release);
	return 0;
}

void seccomp_exit(void)
{
	if (sc_ti_owner)
		ti_exit();
	sc_btf = NULL;
	sc_ti_owner = false;
	memset(&sc_geo, 0, sizeof(sc_geo));
	memset(&sc_sym, 0, sizeof(sc_sym));
	sc_exiting_gate = false;
}

static unsigned long *sc_bitmap(void *filter)
{
	return (unsigned long *)((char *)filter + sc_geo.off_filter_cache +
				 sc_geo.off_cache_allow_native);
}

static struct sighand_struct *sc_task_sighand(struct task_struct *tsk)
{
	return tsk->sighand;
}

static __nocfi void sc_call_release(struct task_struct *tsk)
{
	sc_sym.filter_release(tsk);
}

static struct task_struct *sc_shape_alloc(struct task_struct *tsk)
{
	struct task_struct *shape;

	/*
	 * The shape needs the flags, the sighand and the seccomp state of the
	 * task, and the seccomp state sits past the middle of the struct, so a
	 * full task is copied. The copy is never scheduled and never published,
	 * it only carries the fields the release routine reads.
	 */
	shape = kzalloc(sizeof(*shape), GFP_KERNEL);
	if (!shape)
		return NULL;

	memcpy(shape, tsk, offsetof(struct task_struct, seccomp) +
			    sizeof(struct seccomp));
	shape->seccomp.filter = NULL;
	return shape;
}

static void sc_detach_real(struct task_struct *tsk,
			   struct sighand_struct *sighand)
{
	spin_lock_irq(&sighand->siglock);
	tsk->seccomp.filter = NULL;
	spin_unlock_irq(&sighand->siglock);
}

/*
 * The release routine reads the seccomp state of the task it receives and
 * takes the siglock of that task. A task without a sighand is the contract of
 * the older shape, the real sighand and the gate flag are the contract of the
 * newer one, and both fields have to be in place before the routine runs
 * because the routine takes that lock itself. A copy of the task carries them
 * across, so the real task stays untouched apart from the detach below.
 */
static int sc_release_saved(struct task_struct *tsk, void *filter)
{
	struct sighand_struct *sighand;
	struct task_struct *shape;

	sighand = sc_task_sighand(tsk);
	if (!sighand)
		return -EINVAL;

	shape = sc_shape_alloc(tsk);
	if (!shape)
		return -ENOMEM;

	/*
	 * The older shape detaches the filter of the real task under its own
	 * siglock and expects to find it there, the newer shape takes the
	 * siglock itself and detaches the filter of the task it receives. The
	 * reference travels into the copy and the real task is cleared under
	 * the lock for the older shape, so both shapes consume the reference
	 * exactly once. The copy keeps its own seccomp state clear until the
	 * filter is placed in it, which keeps the newer shape's null check away
	 * from the reference.
	 */
	if (sc_exiting_gate) {
		shape->flags |= PF_EXITING;
		shape->sighand = sighand;
	} else {
		shape->sighand = NULL;
		sc_detach_real(tsk, sighand);
	}
	shape->seccomp.filter = filter;

	sc_call_release(shape);
	kfree(shape);
	return 0;
}

static void sc_reset(struct task_struct *tsk)
{
	struct sighand_struct *sighand;

	sighand = sc_task_sighand(tsk);
	if (!sighand)
		return;

	/*
	 * TIF_SECCOMP is the arm64 gate of the work loop, the generic entry
	 * mask of another architecture is not reachable from a module because
	 * the kernel config that selects it is not part of the module header
	 * set. The bit of the addressed task is cleared, not the bit of the
	 * caller, and the siglock that guards the mode and filter fields below
	 * is held across it.
	 */
	spin_lock_irq(&sighand->siglock);
	clear_bit(TIF_SECCOMP, &task_thread_info(tsk)->flags);
	tsk->seccomp.mode = 0;
	atomic_set(&tsk->seccomp.filter_count, 0);
	tsk->seccomp.filter = NULL;
	spin_unlock_irq(&sighand->siglock);
}

int seccomp_disable_current(void)
{
	void *filter;
	int ret;

	if (!sc_geo.ok || !sc_sym.filter_release)
		return -ENODATA;
	if (!current->sighand)
		return 0;

	/*
	 * The filter goes first. kernel/seccomp.c detaches the tree before it
	 * drops the mode, so no window exists in which a mode still asks for a
	 * filter whose pointer is already gone. The mode, the count and the
	 * thread flag follow in sc_reset.
	 */
	filter = current->seccomp.filter;
	if (filter) {
		ret = sc_release_saved(current, filter);
		if (ret)
			return ret;
	}
	sc_reset(current);
	return 0;
}

/*
 * The kernel entry of the same job is a void function of one task, this name
 * stays clear of it so the two can never be confused at a call site.
 */
int sc_filter_release(struct task_struct *tsk)
{
	void *filter;
	int ret;

	if (!tsk)
		return -EINVAL;
	if (!sc_geo.ok || !sc_sym.filter_release)
		return -ENODATA;
	if (!sc_task_sighand(tsk))
		return -EINVAL;

	filter = tsk->seccomp.filter;
	if (!filter)
		return 0;

	ret = sc_release_saved(tsk, filter);
	if (ret)
		return ret;
	sc_reset(tsk);
	return 0;
}

void *seccomp_filter_of(struct task_struct *tsk)
{
	if (!tsk || !sc_geo.ok)
		return NULL;
	return tsk->seccomp.filter;
}

int seccomp_cache_allow(void *filter, int nr)
{
	if (!filter || !sc_geo.ok || nr < 0)
		return -EINVAL;
	set_bit(nr, sc_bitmap(filter));
	return 0;
}

int seccomp_cache_clear(void *filter, int nr)
{
	if (!filter || !sc_geo.ok || nr < 0)
		return -EINVAL;
	clear_bit(nr, sc_bitmap(filter));
	return 0;
}

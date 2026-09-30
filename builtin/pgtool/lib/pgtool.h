// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef PGTOOL_H
#define PGTOOL_H

#include <linux/types.h>

struct mm_struct;

/*
 * Read only inspector for the page tables of one mm. Every descriptor is
 * copied out with copy_from_kernel_nofault and the kernel offset helpers only
 * ever receive those stack copies, so no path here writes a page table entry
 * and no bare dereference of page table memory is made. Only descriptors the
 * arch reports as present are decoded, swap and migration markers are skipped
 * while PROT_NONE entries stay visible because their fields still follow the
 * hardware layout.
 *
 * arm64 only, built for CONFIG_PGTABLE_LEVELS >= 3. 1G and 2M blocks are
 * decoded with pud_leaf and pmd_leaf, a folded level reports the descriptor its
 * parent holds, so the same code walks 3, 4 and 5 level page tables.
 *
 * pg_walk, pg_stat and pg_lookup take no lock, allocate nothing and do not
 * sleep, they are safe in atomic context. What they return is a snapshot: the
 * page tables of a live mm are only stable while the caller holds
 * mmap_read_lock on that mm, without it a torn read is possible.
 *
 * pg_open_pid, pg_open_mm and pg_close take task and mm references, they do not
 * sleep but they do change refcounts and belong in process context. pg_query
 * runs the atmm hardware translation, it needs a context opened by pid and must
 * not run in interrupt context.
 *
 * pgtool resolves its whole helper set through the consumer callback, which
 * must be a __nocfi wrapper such as the KallRecon kr_name_to_addr, so no task,
 * mm or copy helper is linked and the indirect calls sit in __nocfi functions.
 */
struct pg_cfg {
	unsigned long (*resolve)(const char *name);
};

/*
 * Resolves find_get_pid, get_pid_task, put_pid, put_task_struct, get_task_mm,
 * mmput and copy_from_kernel_nofault. Returns 0, -EINVAL for a null cfg or
 * resolve, -ENODATA for a symbol the resolver does not know. pg_exit drops the
 * resolved symbols, every context must be closed before it runs.
 */
int pg_init(const struct pg_cfg *cfg);
void pg_exit(void);

/*
 * Runtime switch. While it is off every other call fails with -EPERM. It only
 * gates reads, pgtool has no write path to gate.
 */
void pg_enable(bool on);
bool pg_enabled(void);

/* upper bound of the user range, the whole range is [0, pg_va_limit()) */
unsigned long pg_va_limit(void);

/*
 * Context of one mm, caller allocated and owned. Zero it before the first open,
 * pg_open_pid and pg_open_mm take an mm reference that pg_close drops, a
 * context that is never closed pins the mm. pg_open_mm expects an mm that is
 * alive at the call, it cannot tell a dying mm from a live one, and it accepts
 * any mm with a pgd, a walk over one without a user half such as init_mm
 * reports nothing. Only a context opened by pid can be used with pg_query.
 */
struct pg_ctx {
	struct mm_struct *mm;
	pid_t pid;
};

/* 0, -ESRCH when the pid has no mm, -EINVAL for a bad mm or context */
int pg_open_pid(struct pg_ctx *ctx, pid_t pid);
int pg_open_mm(struct pg_ctx *ctx, struct mm_struct *mm);
void pg_close(struct pg_ctx *ctx);

#define PG_LEVEL_PTE	1
#define PG_LEVEL_PMD	2
#define PG_LEVEL_PUD	3

#define PG_FLAG_WRITE	0x0001
#define PG_FLAG_EXEC	0x0002
#define PG_FLAG_USER	0x0004
#define PG_FLAG_DIRTY	0x0008
#define PG_FLAG_YOUNG	0x0010
#define PG_FLAG_DEVICE	0x0020
#define PG_FLAG_SPECIAL	0x0040
#define PG_FLAG_CONT	0x0080

/*
 * One mapping handed to the visit callback. vaddr, paddr and size are the
 * covered range, a huge leaf is one segment of PUD_SIZE or PMD_SIZE at its own
 * alignment, pte entries of a contiguous hint group stay separate and carry
 * PG_FLAG_CONT. raw is the descriptor as read, it is never written back.
 * Adjacent leaves merge into one segment while level, flags, virtual and
 * physical contiguity all hold.
 */
struct pg_segment {
	unsigned long vaddr;
	unsigned long paddr;
	unsigned long size;
	u64 raw;
	u32 flags;
	u8 level;
};

/*
 * present counts pte entries the arch reports as present, huge_pmd and huge_pud
 * count block mappings, mapped_bytes is the size of the segments covered inside
 * the walked range. writable, readonly, executable and dirty count every
 * reported leaf once, huge leaves included. unreadable counts descriptors that
 * copy_from_kernel_nofault refused, those entries are treated as unmapped.
 *
 * Flags are read from the leaf descriptor, the writable marker is the software
 * DBM bit the kernel keeps set while AP[2] still traps the first store, so a
 * writable leaf is reported writable, executable means the user execute never
 * bit is clear.
 */
struct pg_stats {
	u64 present;
	u64 huge_pmd;
	u64 huge_pud;
	u64 writable;
	u64 readonly;
	u64 executable;
	u64 dirty;
	u64 unreadable;
	u64 mapped_bytes;
};

/*
 * Walks [start, end), both page aligned and below pg_va_limit. visit returns 0
 * to continue, a positive value stops the walk and a negative value aborts it,
 * both are returned as is. visit may be NULL to only collect the counters of
 * pg_stat. Returns 0, -EINVAL for an unaligned or out of range window.
 */
int pg_walk(struct pg_ctx *ctx, unsigned long start, unsigned long end,
	    int (*visit)(const struct pg_segment *seg, void *arg), void *arg);

/* counters of [start, end), the walk above without the callback */
int pg_stat(struct pg_ctx *ctx, unsigned long start, unsigned long end,
	    struct pg_stats *stats);

/*
 * Mapping that covers vaddr, the whole leaf is returned so vaddr may sit above
 * seg->vaddr, -ENOENT when nothing is mapped there.
 */
int pg_lookup(struct pg_ctx *ctx, unsigned long vaddr, struct pg_segment *seg);

/*
 * Physical address behind vaddr, delegated to atmm_translate. The pid is
 * resolved once more here, a context that outlived its process is refused with
 * -ESRCH instead of translating whatever task owns that pid now, a small
 * window between that check and the atmm lookup remains. Addresses at or above
 * pg_va_limit are refused, the hardware walk behind atmm only covers the user
 * half and would otherwise report the kernel translation of that address.
 * Returns -EOPNOTSUPP for a context opened by mm.
 */
int pg_query(struct pg_ctx *ctx, unsigned long vaddr, unsigned long *paddr);

#endif

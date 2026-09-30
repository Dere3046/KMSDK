// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef ATMM_H
#define ATMM_H

#include <linux/types.h>

enum atmm_fault {
	ATMM_FAULT_NONE = 0,
	ATMM_FAULT_ADDR_SIZE,
	ATMM_FAULT_TRANSLATION,
	ATMM_FAULT_ACCESS_FLAG,
	ATMM_FAULT_PERMISSION,
	ATMM_FAULT_SYNC_EXTERNAL,
	ATMM_FAULT_SYNC_PARITY,
	ATMM_FAULT_ALIGNMENT,
	ATMM_FAULT_TLB_CONFLICT,
	ATMM_FAULT_ATOMIC_UNSUPPORTED,
	ATMM_FAULT_UNKNOWN,
};

int atmm_translate(pid_t pid, unsigned long va, unsigned long *pa);
int atmm_translate_fault(pid_t pid, unsigned long va, unsigned long *pa,
			 enum atmm_fault *fault);

#endif

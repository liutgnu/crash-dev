/* loongarch64.c - core analysis suite
 *
 * Copyright (C) 2021 Loongson Technology Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifdef LOONGARCH64

#include <elf.h>
#include "defs.h"

/*
 * This matches the beginning of both kernel struct pt_regs and the
 * elf_gregset_t layout exported in NT_PRSTATUS notes.
 */
struct loongarch64_pt_regs {
	/* Saved main processor registers. */
	unsigned long regs[32];

	/* Saved special registers. */
	unsigned long orig_a0;
	unsigned long csr_epc;
	unsigned long csr_badvaddr;
	unsigned long csr_crmd;
	unsigned long csr_prmd;
	unsigned long csr_euen;
	unsigned long csr_ecfg;
	unsigned long csr_estat;
};

struct loongarch64_unwind_frame {
        unsigned long sp;
        unsigned long pc;
        unsigned long ra;
        unsigned long fp;
};

typedef struct __attribute__((__packed__)) {
	short sp_offset;
	short fp_offset;
	short ra_offset;
	unsigned int sp_reg:4;
	unsigned int fp_reg:4;
	unsigned int ra_reg:4;
	unsigned int type:3;
	unsigned int signal:1;
} loongarch64_kernel_orc_entry;

#define LOONGARCH64_ORC_REG_UNDEFINED	0
#define LOONGARCH64_ORC_REG_PREV_SP	1
#define LOONGARCH64_ORC_REG_SP		2
#define LOONGARCH64_ORC_REG_FP		3

#define LOONGARCH64_ORC_TYPE_UNDEFINED	0
#define LOONGARCH64_ORC_TYPE_END_OF_STACK 1
#define LOONGARCH64_ORC_TYPE_CALL	2
#define LOONGARCH64_ORC_TYPE_REGS	3

#define LOONGARCH64_LOOKUP_BLOCK_ORDER	8
#define LOONGARCH64_LOOKUP_BLOCK_SIZE	(1 << LOONGARCH64_LOOKUP_BLOCK_ORDER)
#define LOONGARCH64_INSN_SIZE		4
#define LOONGARCH64_VECSIZE		0x200
#define LOONGARCH64_EXCEPTION_VECTOR_NUM 128
#define LOONGARCH64_IRQ_STACK_SAVED_SP_OFFSET 16
#define LOONGARCH64_EXCCODE_INT_START	64
#define LOONGARCH64_EXCCODE_INT_END	78

static int loongarch64_pgd_vtop(ulong *pgd, ulong vaddr,
			physaddr_t *paddr, int verbose);
static int loongarch64_uvtop(struct task_context *tc, ulong vaddr,
			physaddr_t *paddr, int verbose);
static int loongarch64_kvtop(struct task_context *tc, ulong kvaddr,
			physaddr_t *paddr, int verbose);
static int loongarch64_translate_pte(ulong pte, void *physaddr,
			ulonglong pte64);

static void loongarch64_cmd_mach(void);
static void loongarch64_display_machine_stats(void);

static void loongarch64_back_trace_cmd(struct bt_info *bt);
static void loongarch64_analyze_function(ulong start, ulong offset,
			struct loongarch64_unwind_frame *current,
			struct loongarch64_unwind_frame *previous);
static void loongarch64_dump_backtrace_entry(struct bt_info *bt,
			struct syment *sym, struct loongarch64_unwind_frame *current,
			struct loongarch64_unwind_frame *previous, int level);
static void loongarch64_dump_exception_stack(struct bt_info *bt, char *pt_regs);
static int loongarch64_is_exception_entry(struct syment *sym);
static ulong loongarch64_exception_pc(int cpu, ulong pc);
static int loongarch64_is_unwind_text(ulong pc);
static int loongarch64_use_irq_prstatus_ra(ulong pc, ulong ra);
static int loongarch64_valid_saved_regs(struct bt_info *bt,
			struct loongarch64_pt_regs *regs, ulong *pc);
static int loongarch64_eframe_search(struct bt_info *bt);
static void loongarch64_display_full_frame(struct bt_info *bt,
			struct loongarch64_unwind_frame *current,
			struct loongarch64_unwind_frame *previous);
static void loongarch64_stackframe_init(void);
static void loongarch64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp);
static int loongarch64_get_dumpfile_stack_frame(struct bt_info *bt,
			ulong *nip, ulong *ksp);
static int loongarch64_get_frame(struct bt_info *bt, ulong *pcp, ulong *spp);
static int loongarch64_init_active_task_regs(void);
static int loongarch64_get_crash_notes(void);
static int loongarch64_get_elf_notes(void);
static void loongarch64_irq_stack_init(void);
static void loongarch64_ORC_init(void);
static int loongarch64_orc_unwind(struct bt_info *bt,
			struct loongarch64_unwind_frame *current,
			struct loongarch64_unwind_frame *previous);
static int loongarch64_on_irq_stack(int cpu, ulong stkptr);
static void loongarch64_set_irq_stack(struct bt_info *bt);
static int loongarch64_switch_from_irq_stack(struct bt_info *bt,
			struct loongarch64_unwind_frame *current);
static int loongarch64_find_next_kernel_text(struct bt_info *bt,
			struct loongarch64_unwind_frame *current);

/*
 * 3 Levels paging       PAGE_SIZE=16KB
 *  PGD  |  PMD  |  PTE  |  OFFSET  |
 *  11   |  11   |  11   |    14    |
 */
/* From arch/loongarch/include/asm/pgtable{,-64}.h */
typedef struct { ulong pgd; } pgd_t;
typedef struct { ulong pmd; } pmd_t;
typedef struct { ulong pte; } pte_t;

#define TASK_SIZE64	(1UL << 40)

#define PMD_SHIFT	(PAGESHIFT() + (PAGESHIFT() - 3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))

#define PGDIR_SHIFT	(PMD_SHIFT + (PAGESHIFT() - 3))
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))

#define PTRS_PER_PTE	(1UL << (PAGESHIFT() - 3))
#define PTRS_PER_PMD	PTRS_PER_PTE
#define PTRS_PER_PGD	PTRS_PER_PTE
#define USER_PTRS_PER_PGD	((TASK_SIZE64 / PGDIR_SIZE)?(TASK_SIZE64 / PGDIR_SIZE) : 1)

#define pte_index(addr)	(((addr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))
#define pmd_index(addr)	(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pgd_index(addr)	(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

#define LOONGARCH64_CPU_RIXI	(1UL << 23)	/* CPU has TLB Read/eXec Inhibit */

#define LOONGARCH64_EF_R0		0
#define LOONGARCH64_EF_RA		1
#define LOONGARCH64_EF_SP		3
#define LOONGARCH64_EF_FP		22
#define LOONGARCH64_EF_ORIG_A0		32
#define LOONGARCH64_EF_CSR_EPC		33
#define LOONGARCH64_EF_CSR_BADVADDR	34
#define LOONGARCH64_EF_CSR_CRMD		35
#define LOONGARCH64_EF_CSR_PRMD		36
#define LOONGARCH64_EF_CSR_EUEN		37
#define LOONGARCH64_EF_CSR_ECFG		38
#define LOONGARCH64_EF_CSR_ESTAT	39

static struct machine_specific loongarch64_machine_specific = { 0 };

/*
 * Holds registers during the crash.
 */
static struct loongarch64_pt_regs *panic_task_regs;

/*
 * Check and print the flags on the page
 */
static void
check_page_flags(ulong pte)
{
#define CHECK_PAGE_FLAG(flag)				\
	if ((_PAGE_##flag) && (pte & _PAGE_##flag))	\
		fprintf(fp, "%s" #flag, others++ ? "|" : "")

	int others = 0;
	fprintf(fp, "(");

	if (pte) {
		CHECK_PAGE_FLAG(VALID);
		CHECK_PAGE_FLAG(DIRTY);
		CHECK_PAGE_FLAG(PLV);

		/* Determine whether it is a huge page format */
		if (pte & _PAGE_HGLOBAL) {
			CHECK_PAGE_FLAG(HUGE);
			CHECK_PAGE_FLAG(HGLOBAL);
		} else {
			CHECK_PAGE_FLAG(GLOBAL);
		}

		CHECK_PAGE_FLAG(PRESENT);
		CHECK_PAGE_FLAG(WRITE);
		CHECK_PAGE_FLAG(PROTNONE);
		CHECK_PAGE_FLAG(SPECIAL);
		CHECK_PAGE_FLAG(NO_READ);
		CHECK_PAGE_FLAG(NO_EXEC);
		CHECK_PAGE_FLAG(RPLV);
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");
}

/*
 * Translate a PTE, returning TRUE if the page is present.
 * If a physaddr pointer is passed in, don't print anything.
 */
static int
loongarch64_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char *arglist[MAXARGS];
	int page_present;
	int c, len1, len2, len3;
	ulong paddr;

	paddr = PTOB(pte >> _PFN_SHIFT);
	page_present = !!(pte & _PAGE_PRESENT);

	if (physaddr) {
		*(ulong *)physaddr = paddr;
		return page_present;
	}

	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf1, len1, CENTER | LJUST, "PTE"));

	if (!page_present) {
		swap_location(pte, buf1);
		if ((c = parse_line(buf1, arglist)) != 3)
			error(FATAL, "cannot determine swap location\n");

		len2 = MAX(strlen(arglist[0]), strlen("SWAP"));
		len3 = MAX(strlen(arglist[2]), strlen("OFFSET"));

		fprintf(fp, "%s  %s\n",
			mkstring(buf2, len2, CENTER|LJUST, "SWAP"),
			mkstring(buf3, len3, CENTER|LJUST, "OFFSET"));

		strcpy(buf2, arglist[0]);
		strcpy(buf3, arglist[2]);
		fprintf(fp, "%s  %s  %s\n",
			mkstring(ptebuf, len1, CENTER|RJUST, NULL),
			mkstring(buf2, len2, CENTER|RJUST, NULL),
			mkstring(buf3, len3, CENTER|RJUST, NULL));
		return page_present;
	}

	sprintf(physbuf, "%lx", paddr);
	len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
	fprintf(fp, "%s  ", mkstring(buf1, len2, CENTER | LJUST, "PHYSICAL"));

	fprintf(fp, "FLAGS\n");
	fprintf(fp, "%s  %s  ",
		mkstring(ptebuf, len1, CENTER | RJUST, NULL),
		mkstring(physbuf, len2, CENTER | RJUST, NULL));

	check_page_flags(pte);

	return page_present;
}

/*
 * Identify and print the segment name to which the virtual address belongs
 */
static void
get_segment_name(ulong vaddr, int verbose)
{
	const char * segment;

	if (verbose) {
		if (vaddr < 0x4000000000000000lu)
			segment = "xuvrange";
		else if (vaddr < 0x8000000000000000lu)
			segment = "xsprange";
		else if (vaddr < 0xc000000000000000lu)
			segment = "xkprange";
		else
			segment = "xkvrange";

		fprintf(fp, "SEGMENT: %s\n", segment);
	}
}

/*
 * Virtual to physical memory translation. This function will be called
 * by both loongarch64_kvtop and loongarch64_uvtop.
 */
static int
loongarch64_pgd_vtop(ulong *pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_ptr, pgd_val;
	ulong *pmd_ptr, pmd_val;
	ulong *pte_ptr, pte_val;

	get_segment_name(vaddr, verbose);

	if (IS_XKPRANGE(vaddr)) {
		*paddr = VTOP(vaddr);
		return TRUE;
	}

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %016lx\n", (ulong)pgd);

	pgd_ptr = pgd + pgd_index(vaddr);
	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_val = ULONG(machdep->pgd + PAGEOFFSET(pgd_ptr));
	if (verbose)
		fprintf(fp, "  PGD: %16lx => %16lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;

	pmd_ptr = (ulong *)(VTOP(pgd_val) + sizeof(pmd_t) * pmd_index(vaddr));
	FILL_PMD(PAGEBASE(pmd_ptr), PHYSADDR, PAGESIZE());
	pmd_val = ULONG(machdep->pmd + PAGEOFFSET(pmd_ptr));
	if (verbose)
		fprintf(fp, "  PMD: %016lx => %016lx\n", (ulong)pmd_ptr, pmd_val);
	if (!pmd_val)
		goto no_page;

	pte_ptr = (ulong *)(VTOP(pmd_val) + sizeof(pte_t) * pte_index(vaddr));
	FILL_PTBL(PAGEBASE(pte_ptr), PHYSADDR, PAGESIZE());
	pte_val = ULONG(machdep->ptbl + PAGEOFFSET(pte_ptr));
	if (verbose)
		fprintf(fp, "  PTE: %016lx => %016lx\n", (ulong)pte_ptr, pte_val);
	if (!pte_val)
		goto no_page;

	if (!(pte_val & _PAGE_PRESENT)) {
		if (verbose) {
			fprintf(fp, "\n");
			loongarch64_translate_pte((ulong)pte_val, 0, pte_val);
		}
		return FALSE;
	}

	*paddr = PTOB(pte_val >> _PFN_SHIFT) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %016lx\n\n", PAGEBASE(*paddr));
		loongarch64_translate_pte(pte_val, 0, 0);
	}

	return TRUE;
no_page:
	fprintf(fp, "invalid\n");
	return FALSE;
}

/* Translates a user virtual address to its physical address. cmd_vtop() sets
 * the verbose flag so that the pte translation gets displayed; all other
 * callers quietly accept the translation.
 */
static int
loongarch64_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong mm, active_mm;
	ulong *pgd;

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) {
		readmem(tc->task + OFFSET(task_struct_active_mm),
			KVADDR, &active_mm, sizeof(void *),
			"task active_mm contents", FAULT_ON_ERROR);

		 if (!active_mm)
			 error(FATAL,
			       "no active_mm for this kernel thread\n");

		readmem(active_mm + OFFSET(mm_struct_pgd),
			KVADDR, &pgd, sizeof(long),
			"mm_struct pgd", FAULT_ON_ERROR);
	} else {
		if ((mm = task_mm(tc->task, TRUE)))
			pgd = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
		else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd),
			KVADDR, &pgd, sizeof(long), "mm_struct pgd",
			FAULT_ON_ERROR);
	}

	return loongarch64_pgd_vtop(pgd, vaddr, paddr, verbose);;
}

/* Translates a user virtual address to its physical address. cmd_vtop() sets
 * the verbose flag so that the pte translation gets displayed; all other
 * callers quietly accept the translation.
 */
static int
loongarch64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!verbose) {
		if (IS_XKPRANGE(kvaddr)) {
			*paddr = VTOP(kvaddr);
			return TRUE;
		}
	}

	return loongarch64_pgd_vtop((ulong *)vt->kernel_pgd[0], kvaddr, paddr,
			     verbose);
}

/*
 * Machine dependent command.
 */
static void
loongarch64_cmd_mach(void)
{
	int c;

	while ((c = getopt(argcnt, args, "cmo")) != EOF) {
		switch (c) {
		case 'c':
		case 'm':
		case 'o':
			option_not_supported(c);
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	loongarch64_display_machine_stats();
}

/*
 * "mach" command output.
 */
static void
loongarch64_display_machine_stats(void)
{
	struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

	fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
	fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "               CPUS: %d\n", get_cpus_to_display());
	fprintf(fp, "    PROCESSOR SPEED: ");
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "%ld Mhz\n", mhz);
	else
		fprintf(fp, "(unknown)\n");
	fprintf(fp, "                 HZ: %d\n", machdep->hz);
	fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
	fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());

}

/*
 * Unroll a kernel stack.
 */
static void
loongarch64_back_trace_cmd(struct bt_info *bt)
{
	struct loongarch64_unwind_frame current, previous;
	struct loongarch64_pt_regs *regs;
	char pt_regs[SIZE(pt_regs)];
	int level = 0;
	int invalid_ok = 1;
	int on_irq_stack;

	if (bt->flags & BT_REGS_NOT_FOUND)
		return;

	previous.sp = previous.pc = previous.ra = previous.fp = 0;

	current.pc = bt->instptr;
	current.sp = bt->stkptr;
	current.ra = 0;
	current.fp = 0;

	if (!INSTACK(current.sp, bt) &&
	    (bt->flags & BT_REGS_NOT_FOUND) == 0 &&
	    loongarch64_on_irq_stack(bt->tc->processor, current.sp))
		loongarch64_set_irq_stack(bt);

	if (!INSTACK(current.sp, bt))
		return;

	on_irq_stack = loongarch64_on_irq_stack(bt->tc->processor, current.sp);
	if (bt->machdep) {
		regs = (struct loongarch64_pt_regs *)bt->machdep;
		/*
		 * PRSTATUS RA from IRQ stacks is not always a reliable caller for
		 * hypervisor dumps.  Use it only for IRQ leaf frames where it keeps
		 * the in-flight interrupt call chain before crossing stacks.
		 */
		if (!on_irq_stack ||
		    loongarch64_use_irq_prstatus_ra(current.pc,
		    regs->regs[LOONGARCH64_EF_RA]))
			previous.pc = current.ra = regs->regs[LOONGARCH64_EF_RA];
		current.fp = regs->regs[LOONGARCH64_EF_FP];
	}

	while (current.sp < bt->stacktop) {
		struct syment *symbol = NULL;
		ulong offset;

		current.pc = loongarch64_exception_pc(bt->tc->processor,
		    current.pc);

		if (CRASHDEBUG(8))
			fprintf(fp, "level %d pc %#lx ra %#lx sp %lx\n",
				level, current.pc, current.ra, current.sp);

		if (!IS_KVADDR(current.pc) && !invalid_ok) {
			if (loongarch64_switch_from_irq_stack(bt, &current) ||
			    loongarch64_find_next_kernel_text(bt, &current)) {
				invalid_ok = 1;
				continue;
			}
			return;
		}

		symbol = value_search(current.pc, &offset);
		if ((!symbol || !loongarch64_is_unwind_text(current.pc)) &&
		    !invalid_ok) {
			if (loongarch64_switch_from_irq_stack(bt, &current) ||
			    loongarch64_find_next_kernel_text(bt, &current)) {
				invalid_ok = 1;
				continue;
			}
			error(FATAL, "PC is unknown symbol (%lx)", current.pc);
			return;
		}
		if (symbol && !loongarch64_is_unwind_text(current.pc))
			symbol = NULL;
		invalid_ok = 0;

		/*
		 * If we get an address which points to the start of a
		 * function, then it could one of the following:
		 *
		 *  - we are dealing with a noreturn function.  The last call
		 *    from a noreturn function has an ra which points to the
		 *    start of the function after it.  This is common in the
		 *    oops callchain because of die() which is annotated as
		 *    noreturn.
		 *
		 *  - we have taken an exception at the start of this function.
		 *    In this case we already have the RA in current.ra.
		 *
		 *  - we are in one of these routines which appear with zero
		 *    offset in manually-constructed stack frames:
		 *
		 *    * ret_from_exception
		 *    * ret_from_irq
		 *    * ret_from_fork
		 *    * ret_from_kernel_thread
		 */
		if (symbol && !STRNEQ(symbol->name, "ret_from") && !offset &&
			!current.ra && current.sp < bt->stacktop - SIZE(pt_regs)) {
			if (CRASHDEBUG(8))
				fprintf(fp, "zero offset at %s, try previous symbol\n",
					symbol->name);

			symbol = value_search(current.pc - 4, &offset);
			if (!symbol) {
				error(FATAL, "PC is unknown symbol (%lx)", current.pc);
				return;
			}
		}

		if (loongarch64_orc_unwind(bt, &current, &previous)) {
			/* ORC has already calculated the caller frame. */
		} else if (symbol && loongarch64_is_exception_entry(symbol) &&
		    current.sp <= bt->stacktop - SIZE(pt_regs)) {

			GET_STACK_DATA(current.sp, pt_regs, sizeof(pt_regs));
			regs = (struct loongarch64_pt_regs *) (pt_regs + OFFSET(pt_regs_regs));
			previous.ra = regs->regs[LOONGARCH64_EF_RA];
			previous.sp = regs->regs[LOONGARCH64_EF_SP];
			previous.fp = regs->regs[LOONGARCH64_EF_FP];
			current.ra = regs->csr_epc;

			if (CRASHDEBUG(8))
				fprintf(fp, "exception pc %#lx ra %#lx sp %lx\n",
					previous.pc, previous.ra, previous.sp);

			/* The PC causing the exception may have been invalid */
			invalid_ok = 1;
		} else if (symbol) {
			loongarch64_analyze_function(symbol->value, offset, &current, &previous);
		} else {
			/*
			 * The current PC is invalid. Assume that the code
			 * jumped through a invalid pointer and that the SP has
			 * not been adjusted.
			 */
			previous.sp = current.sp;
		}

		if (symbol)
			loongarch64_dump_backtrace_entry(bt, symbol, &current, &previous, level++);

		current.pc = current.ra;
		current.sp = previous.sp;
		current.ra = previous.ra;
		current.fp = previous.fp;

		if (CRASHDEBUG(8))
			fprintf(fp, "next %d pc %#lx ra %#lx sp %lx\n",
				level, current.pc, current.ra, current.sp);

		previous.sp = previous.pc = previous.ra = previous.fp = 0;

		if (current.sp >= bt->stacktop &&
		    loongarch64_switch_from_irq_stack(bt, &current)) {
			invalid_ok = 1;
			continue;
		}
	}
}

static void
loongarch64_analyze_function(ulong start, ulong offset,
		      struct loongarch64_unwind_frame *current,
		      struct loongarch64_unwind_frame *previous)
{
	ulong i;
	ulong rapos = 0;
	ulong spadjust = 0;
	uint32_t *funcbuf, *ip;

	if (CRASHDEBUG(8))
		fprintf(fp, "%s: start %#lx offset %#lx\n",
			__func__, start, offset);

	if (!offset) {
		previous->sp = current->sp;
		return;
	}

	ip = funcbuf = (uint32_t *)GETBUF(offset);
	if (!readmem(start, KVADDR, funcbuf, offset,
		     "loongarch64_analyze_function", RETURN_ON_ERROR)) {
		FREEBUF(funcbuf);
		error(WARNING, "Cannot read function at %16lx\n", start);
		return;
	}

	for (i = 0; i < offset; i += 4) {
		ulong insn = *ip & 0xffffffff;
		ulong si12 = (insn >> 10) & 0xfff;	/* bit[10:21] */

		if (CRASHDEBUG(8))
			fprintf(fp, "insn @ %#lx = %#lx\n", start + i, insn);

		if ((insn & 0xffc003ff) == 0x02800063 || /* addi.w sp,sp,si12 */
		    (insn & 0xffc003ff) == 0x02c00063) { /* addi.d sp,sp,si12 */
			if (!(si12 & 0x800)) /* si12 < 0 */
				break;
			spadjust += 0x1000 - si12;
			if (CRASHDEBUG(8))
				fprintf(fp, "si12 =%lu ,spadjust = %lu\n", si12, spadjust);
		} else if ((insn & 0xffc003ff) == 0x29800061 || /* st.w ra,sp,si12 */
			   (insn & 0xffc003ff) == 0x29c00061) { /* st.d ra,sp,si12 */
			rapos = current->sp + si12;
			if (CRASHDEBUG(8))
				fprintf(fp, "rapos %lx\n", rapos);
			break;
		}

		ip++;
	}

	FREEBUF(funcbuf);

	previous->sp = current->sp + spadjust;

	if (rapos) {
		ulong ra;

		if (!readmem(rapos, KVADDR, &ra, sizeof(ra), "RA from stack",
		    RETURN_ON_ERROR)) {
			error(FATAL, "Cannot read RA from stack %lx", rapos);
			return;
		}

		if (IS_KVADDR(ra) || !IS_KVADDR(current->ra))
			current->ra = ra;
	}
}

static void
loongarch64_dump_backtrace_entry(struct bt_info *bt, struct syment *sym,
			struct loongarch64_unwind_frame *current,
			struct loongarch64_unwind_frame *previous, int level)
{
	const char *name = sym ? sym->name : "(invalid)";
	struct load_module *lm;
	char *name_plus_offset = NULL;
	struct syment *symp;
	ulong symbol_offset;
	char buf[BUFSIZE];
	char pt_regs[SIZE(pt_regs)];

	if (bt->flags & BT_SYMBOL_OFFSET) {
		symp = value_search(current->pc, &symbol_offset);

		if (symp && symbol_offset)
			name_plus_offset =
				value_to_symstr(current->pc, buf, bt->radix);
	}

	fprintf(fp, "%s#%d [%016lx] %s at %016lx", level < 10 ? " " : "", level,
		current->sp, name_plus_offset ? name_plus_offset : name,
		current->pc);

	if (module_symbol(current->pc, NULL, &lm, NULL, 0))
		fprintf(fp, " [%s]", lm->mod_name);

	fprintf(fp, "\n");

	/*
	 * 'bt -l', get a line number associated with a current pc address.
	 */
	if (bt->flags & BT_LINE_NUMBERS) {
		get_line_number(current->pc, buf, FALSE);
		if (strlen(buf))
			fprintf(fp, "    %s\n", buf);
	}

	/* bt -f */
	if (bt->flags & BT_FULL) {
		if (sym && loongarch64_is_exception_entry(sym)) {
			GET_STACK_DATA(current->sp, &pt_regs, SIZE(pt_regs));
			loongarch64_dump_exception_stack(bt, pt_regs);
		}
		fprintf(fp, "    "
			"[PC: %016lx RA: %016lx SP: %016lx SIZE: %ld]\n",
			current->pc, current->ra, current->sp,
			previous->sp - current->sp);
		loongarch64_display_full_frame(bt, current, previous);
	}
}

static void
loongarch64_dump_exception_stack(struct bt_info *bt, char *pt_regs)
{
	struct loongarch64_pt_regs *regs;
	int i;
	char buf[BUFSIZE];

	regs = (struct loongarch64_pt_regs *) (pt_regs + OFFSET(pt_regs_regs));

	for (i = 0; i < 32; i += 4) {
		fprintf(fp, "    $%2d      : %016lx %016lx %016lx %016lx\n",
			i, regs->regs[i], regs->regs[i+1],
			regs->regs[i+2], regs->regs[i+3]);
	}

	value_to_symstr(loongarch64_exception_pc(bt->tc->processor,
	    regs->csr_epc), buf, 16);
	fprintf(fp, "    era      : %016lx %s\n", regs->csr_epc, buf);

	value_to_symstr(regs->regs[LOONGARCH64_EF_RA], buf, 16);
	fprintf(fp, "    ra       : %016lx %s\n", regs->regs[LOONGARCH64_EF_RA], buf);

	fprintf(fp, "    CSR crmd : %016lx\n", regs->csr_crmd);
	fprintf(fp, "    CSR prmd : %016lx\n", regs->csr_prmd);
	fprintf(fp, "    CSR ecfg : %016lx\n", regs->csr_ecfg);
	fprintf(fp, "    CSR estat: %016lx\n", regs->csr_estat);
	fprintf(fp, "    CSR euen : %016lx\n", regs->csr_euen);

	fprintf(fp, "    BadVA    : %016lx\n", regs->csr_badvaddr);
}

static int
loongarch64_is_exception_entry(struct syment *sym)
{
	return STREQ(sym->name, "ret_from_exception") ||
		STREQ(sym->name, "ret_from_irq") ||
		STREQ(sym->name, "work_resched") ||
		STREQ(sym->name, "handle_sys") ||
		STREQ(sym->name, "handle_syscall") ||
		STREQ(sym->name, "handle_ade") ||
		STREQ(sym->name, "handle_ale") ||
		STREQ(sym->name, "handle_bce") ||
		STREQ(sym->name, "handle_bp") ||
		STREQ(sym->name, "handle_fpe") ||
		STREQ(sym->name, "handle_fpu") ||
		STREQ(sym->name, "handle_iasub") ||
		STREQ(sym->name, "handle_ib") ||
		STREQ(sym->name, "handle_int") ||
		STREQ(sym->name, "handle_ipe") ||
		STREQ(sym->name, "handle_lbt") ||
		STREQ(sym->name, "handle_lsx") ||
		STREQ(sym->name, "handle_mcheck") ||
		STREQ(sym->name, "handle_oac") ||
		STREQ(sym->name, "handle_parchk") ||
		STREQ(sym->name, "handle_reserved") ||
		STREQ(sym->name, "handle_ri") ||
		STREQ(sym->name, "handle_tlb_protect") ||
		STREQ(sym->name, "tlb_do_page_fault_0") ||
		STREQ(sym->name, "tlb_do_page_fault_1") ||
		STREQ(sym->name, "handle_vint") ||
		STREQ(sym->name, "handle_watch") ||
		STREQ(sym->name, "handle_lasx");
}

static ulong
loongarch64_exception_pc(int cpu, ulong pc)
{
	ulong eentry, pcpu_handler, offset, type, func;
	ulong exception_table, exception_handlers;
	int i;

	if (!IS_KVADDR(pc) || !symbol_exists("exception_handlers"))
		return pc;

	exception_handlers = symbol_value("exception_handlers");
	eentry = exception_handlers;
	if (symbol_exists("eentry"))
		readmem(symbol_value("eentry"), KVADDR, &eentry, sizeof(eentry),
		    "LoongArch eentry", RETURN_ON_ERROR|QUIET);

	/*
	 * pcpu_handlers exists only for NUMA non-RT kernels.  When absent,
	 * the boot-time eentry/exception_handlers mapping below is still valid.
	 */
	if (symbol_exists("pcpu_handlers")) {
		for (i = 0; i < kt->cpus; i++) {
			if (cpu >= 0 && cpu < kt->cpus && i != cpu)
				continue;
			if (!readmem(symbol_value("pcpu_handlers") +
			    (i * sizeof(ulong)), KVADDR, &pcpu_handler,
			    sizeof(pcpu_handler), "LoongArch pcpu_handlers",
			    RETURN_ON_ERROR|QUIET))
				continue;
			if (!pcpu_handler)
				continue;
			if (pc >= pcpu_handler &&
			    pc < pcpu_handler + LOONGARCH64_VECSIZE *
			    LOONGARCH64_EXCEPTION_VECTOR_NUM) {
				pc = pc + eentry - pcpu_handler;
				break;
			}
		}
	}

	if (pc < eentry || pc >= eentry + LOONGARCH64_EXCCODE_INT_END * LOONGARCH64_VECSIZE)
		return pc;

	offset = (pc - eentry) % LOONGARCH64_VECSIZE;
	type = (pc - eentry) / LOONGARCH64_VECSIZE;

	if (type < LOONGARCH64_EXCCODE_INT_START &&
	    symbol_exists("exception_table")) {
		exception_table = symbol_value("exception_table");
		if (!readmem(exception_table + (type * sizeof(ulong)), KVADDR,
		    &func, sizeof(func), "LoongArch exception_table",
		    RETURN_ON_ERROR|QUIET))
			func = 0;
	} else if (type >= LOONGARCH64_EXCCODE_INT_START &&
	    type <= LOONGARCH64_EXCCODE_INT_END &&
	    symbol_exists("handle_vint")) {
		func = symbol_value("handle_vint");
	} else if (symbol_exists("handle_reserved")) {
		func = symbol_value("handle_reserved");
	} else {
		func = 0;
	}

	return func ? func + offset : pc;
}


static int
loongarch64_is_unwind_text(ulong pc)
{
	struct syment *symbol;
	ulong offset;

	if (!is_kernel_text(pc))
		return FALSE;

	symbol = value_search(pc, &offset);
	if (!symbol || symbol->name[0] == '.' ||
	    STREQ(symbol->name, "_PROCEDURE_LINKAGE_TABLE_") ||
	    STREQ(symbol->name, "empty_zero_page") ||
	    STRNEQ(symbol->name, "__start_") ||
	    STRNEQ(symbol->name, "__end_"))
		return FALSE;

	return TRUE;
}


static int
loongarch64_use_irq_prstatus_ra(ulong pc, ulong ra)
{
	struct syment *pcsym, *rasym;
	ulong offset;

	if (!loongarch64_is_unwind_text(pc) ||
	    !loongarch64_is_unwind_text(ra))
		return FALSE;

	pcsym = value_search(pc, &offset);
	rasym = value_search(ra, &offset);
	if (!pcsym || !rasym)
		return FALSE;

	return STREQ(pcsym->name, "generic_handle_domain_irq") &&
	    STREQ(rasym->name, "handle_cpu_irq");
}

static int
loongarch64_valid_saved_regs(struct bt_info *bt,
			struct loongarch64_pt_regs *regs, ulong *pc)
{
	ulong saved_pc;

	saved_pc = loongarch64_exception_pc(bt->tc->processor, regs->csr_epc);
	if (!loongarch64_is_unwind_text(saved_pc))
		return FALSE;

	if (!INSTACK(regs->regs[LOONGARCH64_EF_SP], bt))
		return FALSE;

	if (regs->regs[LOONGARCH64_EF_RA] &&
	    !loongarch64_is_unwind_text(regs->regs[LOONGARCH64_EF_RA]))
		return FALSE;

	*pc = saved_pc;
	return TRUE;
}

static void
loongarch64_irq_stack_init(void)
{
	int i;
	struct syment *sp;
	struct machine_specific *ms = machdep->machspec;
	ulong p;

	if (!(symbol_exists("irq_stack") &&
	    (sp = per_cpu_symbol_search("irq_stack"))))
		return;

	ms->irq_stack_size = machdep->stacksize;
	if (!(ms->irq_stacks = (ulong *)malloc((size_t)(kt->cpus *
	    sizeof(ulong)))))
		error(FATAL, "cannot malloc irq_stack addresses\n");

	machdep->flags |= IRQSTACKS;

	for (i = 0; i < kt->cpus; i++) {
		p = kt->__per_cpu_offset[i] + sp->value;
		if (!readmem(p, KVADDR, &ms->irq_stacks[i], sizeof(ulong),
		    "IRQ stack pointer", RETURN_ON_ERROR))
			ms->irq_stacks[i] = 0;
	}
}

static int
loongarch64_on_irq_stack(int cpu, ulong stkptr)
{
	struct machine_specific *ms = machdep->machspec;

	if (cpu < 0 || cpu >= kt->cpus || !ms->irq_stacks ||
	    !ms->irq_stacks[cpu] || !ms->irq_stack_size)
		return FALSE;

	return (stkptr >= ms->irq_stacks[cpu]) &&
	    (stkptr < (ms->irq_stacks[cpu] + ms->irq_stack_size));
}

static void
loongarch64_set_irq_stack(struct bt_info *bt)
{
	struct machine_specific *ms = machdep->machspec;

	bt->stackbase = ms->irq_stacks[bt->tc->processor];
	bt->stacktop = bt->stackbase + ms->irq_stack_size;
	alter_stackbuf(bt);
}

static int
loongarch64_switch_from_irq_stack(struct bt_info *bt,
			struct loongarch64_unwind_frame *current)
{
	struct machine_specific *ms = machdep->machspec;
	struct loongarch64_pt_regs *regs;
	char pt_regs[SIZE(pt_regs)];
	ulong irq_stack, saved_sp_addr, saved_sp, saved_pc;
	ulong task_stackbase, task_stacktop;

	if (bt->tc->processor < 0 || bt->tc->processor >= kt->cpus ||
	    !ms->irq_stacks || !ms->irq_stack_size)
		return FALSE;

	irq_stack = ms->irq_stacks[bt->tc->processor];
	if (!irq_stack || current->sp < irq_stack ||
	    current->sp > irq_stack + ms->irq_stack_size + 64)
		return FALSE;

	/* Matches the kernel's IRQ_STACK_START layout. */
	saved_sp_addr = irq_stack + ms->irq_stack_size -
	    LOONGARCH64_IRQ_STACK_SAVED_SP_OFFSET;
	if (!readmem(saved_sp_addr, KVADDR, &saved_sp, sizeof(saved_sp),
	    "saved task stack pointer", RETURN_ON_ERROR))
		return FALSE;

	task_stackbase = GET_STACKBASE(bt->task);
	task_stacktop = GET_STACKTOP(bt->task);
	if (saved_sp < task_stackbase || saved_sp >= task_stacktop)
		return FALSE;

	bt->stackbase = task_stackbase;
	bt->stacktop = task_stacktop;
	alter_stackbuf(bt);
	if (saved_sp <= bt->stacktop - SIZE(pt_regs)) {
		GET_STACK_DATA(saved_sp, pt_regs, sizeof(pt_regs));
		regs = (struct loongarch64_pt_regs *)(pt_regs +
		    OFFSET(pt_regs_regs));
		if (loongarch64_valid_saved_regs(bt, regs, &saved_pc)) {
			current->pc = saved_pc;
			current->sp = regs->regs[LOONGARCH64_EF_SP];
			current->ra = regs->regs[LOONGARCH64_EF_RA];
			current->fp = regs->regs[LOONGARCH64_EF_FP];
			return TRUE;
		}
	}

	current->sp = saved_sp;
	current->ra = 0;
	return loongarch64_find_next_kernel_text(bt, current);
}

static int
loongarch64_find_next_kernel_text(struct bt_info *bt,
			struct loongarch64_unwind_frame *current)
{
	ulong sp, pc;

	if (!INSTACK(current->sp, bt))
		return FALSE;

	sp = current->sp + sizeof(ulong);
	sp = roundup(sp, sizeof(ulong));
	for (; sp < bt->stacktop; sp += sizeof(ulong)) {
		GET_STACK_DATA(sp, &pc, sizeof(pc));
		pc = loongarch64_exception_pc(bt->tc->processor, pc);
		if (!loongarch64_is_unwind_text(pc))
			continue;

		current->pc = pc;
		current->sp = sp;
		return TRUE;
	}

	return FALSE;
}

static int
loongarch64_orc_ip(ulong ip_entry_addr, ulong *ip)
{
	int ip_entry;

	if (!readmem(ip_entry_addr, KVADDR, &ip_entry, sizeof(ip_entry),
	    "LoongArch ORC ip", RETURN_ON_ERROR|QUIET))
		return FALSE;

	*ip = ip_entry_addr + ip_entry;
	return TRUE;
}

static struct loongarch64_orc_entry *
loongarch64_orc_get_entry(struct loongarch64_ORC_data *orc)
{
	loongarch64_kernel_orc_entry korc;
	struct loongarch64_orc_entry *entry = &orc->orc_entry_data;

	if (!readmem(orc->orc_entry, KVADDR, &korc, sizeof(korc),
	    "LoongArch ORC entry", RETURN_ON_ERROR|QUIET))
		return NULL;

	entry->sp_offset = korc.sp_offset;
	entry->fp_offset = korc.fp_offset;
	entry->ra_offset = korc.ra_offset;
	entry->sp_reg = korc.sp_reg;
	entry->fp_reg = korc.fp_reg;
	entry->ra_reg = korc.ra_reg;
	entry->type = korc.type;
	entry->signal = korc.signal;

	return entry;
}

static struct loongarch64_orc_entry *
loongarch64_orc_find_in_table(ulong ip_table, ulong orc_table,
			uint num_entries, ulong ip)
{
	int index;
	ulong first, last, mid, found, vaddr;
	struct machine_specific *ms = machdep->machspec;
	struct loongarch64_ORC_data *orc = &ms->orc;

	if (!num_entries)
		return NULL;

	first = ip_table;
	last = ip_table + ((num_entries - 1) * sizeof(int));
	found = first;

	while (first <= last) {
		mid = first + (((last - first) / sizeof(int)) / 2) *
		    sizeof(int);

		if (!loongarch64_orc_ip(mid, &vaddr))
			return NULL;

		if (vaddr <= ip) {
			found = mid;
			first = mid + sizeof(int);
		} else {
			if (mid == ip_table)
				break;
			last = mid - sizeof(int);
		}
	}

	index = (found - ip_table) / sizeof(int);
	orc->ip_entry = found;
	orc->orc_entry = orc_table + (index * SIZE(orc_entry));

	return loongarch64_orc_get_entry(orc);
}

static struct loongarch64_orc_entry *
loongarch64_orc_find(ulong ip)
{
	uint idx, start, stop, num_entries;
	struct machine_specific *ms = machdep->machspec;
	struct loongarch64_ORC_data *orc = &ms->orc;

	if (!orc->enabled)
		return NULL;

	if ((ip >= kt->stext) && (ip < kt->etext)) {
		if (orc->lookup_num_blocks < 2)
			return NULL;

		idx = (ip - kt->stext) / LOONGARCH64_LOOKUP_BLOCK_SIZE;
		if (idx >= orc->lookup_num_blocks - 1)
			return NULL;

		if (!readmem(orc->orc_lookup + (idx * sizeof(uint)), KVADDR,
		    &start, sizeof(start), "LoongArch ORC lookup start",
		    RETURN_ON_ERROR|QUIET))
			return NULL;
		if (!readmem(orc->orc_lookup + ((idx + 1) * sizeof(uint)),
		    KVADDR, &stop, sizeof(stop), "LoongArch ORC lookup stop",
		    RETURN_ON_ERROR|QUIET))
			return NULL;
		stop++;

		if ((orc->__start_orc_unwind + (start * SIZE(orc_entry))) >=
		    orc->__stop_orc_unwind)
			return NULL;
		if ((orc->__start_orc_unwind + (stop * SIZE(orc_entry))) >
		    orc->__stop_orc_unwind)
			return NULL;

		return loongarch64_orc_find_in_table(
		    orc->__start_orc_unwind_ip + (start * sizeof(int)),
		    orc->__start_orc_unwind + (start * SIZE(orc_entry)),
		    stop - start, ip);
	}

	if (is_kernel_text(ip)) {
		num_entries = (orc->__stop_orc_unwind_ip -
		    orc->__start_orc_unwind_ip) / sizeof(int);
		return loongarch64_orc_find_in_table(orc->__start_orc_unwind_ip,
		    orc->__start_orc_unwind, num_entries, ip);
	}

	return NULL;
}

static int
loongarch64_orc_read_stack(ulong addr, ulong *value)
{
	return readmem(addr, KVADDR, value, sizeof(*value),
	    "LoongArch ORC stack", RETURN_ON_ERROR|QUIET);
}

static ulong
loongarch64_orc_adjust_pc(int cpu, ulong ra)
{
	ra = loongarch64_exception_pc(cpu, ra);
	return loongarch64_is_unwind_text(ra) ? ra : 0;
}

static int
loongarch64_orc_unwind(struct bt_info *bt,
			struct loongarch64_unwind_frame *current,
			struct loongarch64_unwind_frame *previous)
{
	ulong cfa, pcval, fpval = current->fp;
	struct loongarch64_orc_entry *orc;
	struct loongarch64_pt_regs regs;

	orc = loongarch64_orc_find(current->pc);
	if (!orc)
		return FALSE;

	if (CRASHDEBUG(8))
		fprintf(fp,
		    "orc pc %lx sp %lx fp %lx -> spo %d fpo %d rao %d "
		    "spr %u fpr %u rar %u type %u\n",
		    current->pc, current->sp, current->fp, orc->sp_offset,
		    orc->fp_offset, orc->ra_offset, orc->sp_reg, orc->fp_reg,
		    orc->ra_reg, orc->type);

	if (orc->type == LOONGARCH64_ORC_TYPE_UNDEFINED ||
	    orc->type == LOONGARCH64_ORC_TYPE_END_OF_STACK)
		return FALSE;

	switch (orc->sp_reg) {
	case LOONGARCH64_ORC_REG_SP:
		cfa = current->sp + orc->sp_offset;
		break;
	case LOONGARCH64_ORC_REG_FP:
		if (!current->fp)
			return FALSE;
		cfa = current->fp;
		break;
	default:
		return FALSE;
	}

	switch (orc->fp_reg) {
	case LOONGARCH64_ORC_REG_PREV_SP:
		if (!loongarch64_orc_read_stack(cfa + orc->fp_offset, &fpval))
			return FALSE;
		break;
	case LOONGARCH64_ORC_REG_UNDEFINED:
		break;
	default:
		return FALSE;
	}

	switch (orc->type) {
	case LOONGARCH64_ORC_TYPE_CALL:
		if (orc->ra_reg == LOONGARCH64_ORC_REG_PREV_SP) {
			if (!loongarch64_orc_read_stack(cfa + orc->ra_offset,
			    &pcval))
				return FALSE;
		} else if (orc->ra_reg == LOONGARCH64_ORC_REG_UNDEFINED) {
			if (!current->ra || current->ra == current->pc)
				return FALSE;
			pcval = current->ra;
		} else {
			return FALSE;
		}
		if (pcval >= LOONGARCH64_INSN_SIZE)
			pcval -= LOONGARCH64_INSN_SIZE;
		pcval = loongarch64_orc_adjust_pc(bt->tc->processor, pcval);
		if (!pcval && current->ra >= LOONGARCH64_INSN_SIZE)
			pcval = loongarch64_orc_adjust_pc(bt->tc->processor,
			    current->ra - LOONGARCH64_INSN_SIZE);
		if (!pcval)
			return FALSE;
		previous->sp = cfa;
		previous->fp = fpval;
		previous->ra = 0;
		current->ra = pcval;
		return TRUE;

	case LOONGARCH64_ORC_TYPE_REGS:
		if (!readmem(cfa, KVADDR, &regs, sizeof(regs),
		    "LoongArch ORC pt_regs", RETURN_ON_ERROR|QUIET))
			return FALSE;
		/*
		 * The kernel unwinder treats user-mode or empty pt_regs as a
		 * clean end.  Crash does not need to distinguish that from a
		 * fallback here; a non-kernel ERA simply stops ORC unwinding.
		 */
		pcval = loongarch64_exception_pc(bt->tc->processor, regs.csr_epc);
		if (!loongarch64_is_unwind_text(pcval))
			return FALSE;
		previous->sp = regs.regs[LOONGARCH64_EF_SP];
		previous->fp = regs.regs[LOONGARCH64_EF_FP];
		previous->ra = regs.regs[LOONGARCH64_EF_RA];
		current->ra = pcval;
		return TRUE;
	}

	return FALSE;
}

static void
loongarch64_ORC_init(void)
{
	int i;
	char *orc_symbols[] = {
		"lookup_num_blocks",
		"__start_orc_unwind_ip",
		"__stop_orc_unwind_ip",
		"__start_orc_unwind",
		"__stop_orc_unwind",
		"orc_lookup",
		NULL
	};
	struct machine_specific *ms = machdep->machspec;
	struct loongarch64_ORC_data *orc = &ms->orc;

	STRUCT_SIZE_INIT(orc_entry, "orc_entry");
	if (!VALID_STRUCT(orc_entry) ||
	    SIZE(orc_entry) != sizeof(loongarch64_kernel_orc_entry)) {
		error(WARNING, "LoongArch64 ORC unwinder: "
		    "orc_entry structure has changed\n");
		return;
	}

	if (!MEMBER_EXISTS("orc_entry", "sp_offset") ||
	    !MEMBER_EXISTS("orc_entry", "fp_offset") ||
	    !MEMBER_EXISTS("orc_entry", "ra_offset") ||
	    !MEMBER_EXISTS("orc_entry", "sp_reg") ||
	    !MEMBER_EXISTS("orc_entry", "fp_reg") ||
	    !MEMBER_EXISTS("orc_entry", "ra_reg") ||
	    !MEMBER_EXISTS("orc_entry", "type")) {
		error(WARNING, "LoongArch64 ORC unwinder: "
		    "orc_entry members have changed\n");
		return;
	}

	for (i = 0; orc_symbols[i]; i++) {
		if (!symbol_exists(orc_symbols[i]))
			return;
	}

	if (!readmem(symbol_value("lookup_num_blocks"), KVADDR,
	    &orc->lookup_num_blocks, sizeof(orc->lookup_num_blocks),
	    "LoongArch ORC lookup_num_blocks", RETURN_ON_ERROR|QUIET))
		return;

	orc->__start_orc_unwind_ip = symbol_value("__start_orc_unwind_ip");
	orc->__stop_orc_unwind_ip = symbol_value("__stop_orc_unwind_ip");
	orc->__start_orc_unwind = symbol_value("__start_orc_unwind");
	orc->__stop_orc_unwind = symbol_value("__stop_orc_unwind");
	orc->orc_lookup = symbol_value("orc_lookup");
	orc->enabled = TRUE;
}

/*
 * 'bt -f' commend output
 * Display all stack data contained in a frame
 */
static void
loongarch64_display_full_frame(struct bt_info *bt, struct loongarch64_unwind_frame *current,
			  struct loongarch64_unwind_frame *previous)
{
	int i, u_idx;
	ulong *up;
	ulong words, addr;
	char buf[BUFSIZE];

	if (previous->sp < current->sp)
		return;

	if (!(INSTACK(previous->sp, bt) && INSTACK(current->sp, bt)))
		return;

	words = (previous->sp - current->sp) / sizeof(ulong) + 1;
	addr = current->sp;
	u_idx = (current->sp - bt->stackbase) / sizeof(ulong);

	for (i = 0; i < words; i++, u_idx++) {
		if (!(i & 1))
			fprintf(fp, "%s    %lx: ", i ? "\n" : "", addr);

		up = (ulong *)(&bt->stackbuf[u_idx*sizeof(ulong)]);
		fprintf(fp, "%s ", format_stack_entry(bt, buf, *up, 0));
		addr += sizeof(ulong);
	}
	fprintf(fp, "\n");
}

static void
loongarch64_stackframe_init(void)
{
	long task_struct_thread = MEMBER_OFFSET("task_struct", "thread");
	long thread_reg03_sp = MEMBER_OFFSET("thread_struct", "reg03");
	long thread_reg01_ra = MEMBER_OFFSET("thread_struct", "reg01");

	if ((task_struct_thread == INVALID_OFFSET) ||
	    (thread_reg03_sp == INVALID_OFFSET) ||
	    (thread_reg01_ra == INVALID_OFFSET)) {
		error(FATAL,
		      "cannot determine thread_struct offsets\n");
		return;
	}

	ASSIGN_OFFSET(task_struct_thread_reg03) =
		task_struct_thread + thread_reg03_sp;
	MEMBER_OFFSET_INIT(pt_regs_regs, "pt_regs", "regs");
	STRUCT_SIZE_INIT(pt_regs, "pt_regs");
	ASSIGN_OFFSET(task_struct_thread_reg01) =
		task_struct_thread + thread_reg01_ra;

	MEMBER_OFFSET_INIT(elf_prstatus_pr_reg, "elf_prstatus", "pr_reg");
	STRUCT_SIZE_INIT(note_buf, "note_buf_t");
	loongarch64_irq_stack_init();
}

/*
 * Get a stack frame combination of pc and ra from the most relevant spot.
 */
static void
loongarch64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	ulong ksp, nip;
	int ret = 0;

	nip = ksp = 0;
	bt->machdep = NULL;

	if (DUMPFILE() && is_task_active(bt->task)) {
		ret = loongarch64_get_dumpfile_stack_frame(bt, &nip, &ksp);
	}
	else {
		ret = loongarch64_get_frame(bt, &nip, &ksp);
	}

	if (!ret)
		error(WARNING, "cannot determine starting stack frame for task %lx\n",
			bt->task);

	if (pcp)
		*pcp = nip;
	if (spp)
		*spp = ksp;
}

/*
 * Get the starting point for the active cpu in a diskdump.
 */
static int
loongarch64_get_dumpfile_stack_frame(struct bt_info *bt, ulong *nip, ulong *ksp)
{
	const struct machine_specific *ms = machdep->machspec;
	struct loongarch64_pt_regs *regs;
	ulong epc, sp;

	if (!ms->crash_task_regs) {
		bt->flags |= BT_REGS_NOT_FOUND;
		return FALSE;
	}

	/*
	 * We got registers for panic task from crash_notes. Just return them.
	 */
	regs = &ms->crash_task_regs[bt->tc->processor];
	epc = regs->csr_epc;
	sp = regs->regs[LOONGARCH64_EF_SP];

	if (!epc && !sp) {
		bt->flags |= BT_REGS_NOT_FOUND;
		return FALSE;
	}

	if (nip)
		*nip = epc;
	if (ksp)
		*ksp = sp;

	bt->machdep = regs;

	return TRUE;
}

/*
 * Do the work for loongarch64_get_stack_frame() for non-active tasks.
 * Get SP and PC values for idle tasks.
 */
static int
loongarch64_get_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	if (!bt->tc || !(tt->flags & THREAD_INFO))
		return FALSE;

	if (!readmem(bt->task + OFFSET(task_struct_thread_reg01),
		     KVADDR, pcp, sizeof(*pcp),
		     "thread_struct.regs01",
		     RETURN_ON_ERROR)) {
		return FALSE;
	}

	if (!readmem(bt->task + OFFSET(task_struct_thread_reg03),
		     KVADDR, spp, sizeof(*spp),
		     "thread_struct.regs03",
		     RETURN_ON_ERROR)) {
		return FALSE;
	}

	return TRUE;
}

static int
loongarch64_init_active_task_regs(void)
{
	int retval;

	retval = loongarch64_get_crash_notes();
	if (retval == TRUE)
		return retval;

	return loongarch64_get_elf_notes();
}

/*
 * Retrieve task registers for the time of the crash.
 */
static int
loongarch64_get_crash_notes(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong crash_notes;
	Elf64_Nhdr *note;
	ulong offset;
	char *buf, *p;
	ulong *notes_ptrs;
	ulong i;

	/*
	 * crash_notes contains per cpu memory for storing cpu states
	 * in case of system crash.
	 */
	if (!symbol_exists("crash_notes"))
		return FALSE;

	crash_notes = symbol_value("crash_notes");

	notes_ptrs = (ulong *)GETBUF(kt->cpus*sizeof(notes_ptrs[0]));

	/*
	 * Read crash_notes for the first CPU. crash_notes are in standard ELF
	 * note format.
	 */
	if (!readmem(crash_notes, KVADDR, &notes_ptrs[kt->cpus-1],
	    sizeof(notes_ptrs[kt->cpus-1]), "crash_notes",
		     RETURN_ON_ERROR)) {
		error(WARNING, "cannot read crash_notes\n");
		FREEBUF(notes_ptrs);
		return FALSE;
	}

	if (symbol_exists("__per_cpu_offset")) {

		/*
		 * Add __per_cpu_offset for each cpu to form the pointer to the notes
		 */
		for (i = 0; i < kt->cpus; i++) {
			if (IS_KVADDR(notes_ptrs[kt->cpus-1]))
				notes_ptrs[i] = notes_ptrs[kt->cpus-1] + kt->__per_cpu_offset[i];
			else
				notes_ptrs[i] = crash_notes + kt->__per_cpu_offset[i];
		}
	}

	buf = GETBUF(SIZE(note_buf));

	if (!(panic_task_regs = calloc((size_t)kt->cpus, sizeof(*panic_task_regs))))
		error(FATAL, "cannot calloc panic_task_regs space\n");

	for (i = 0; i < kt->cpus; i++) {

		if (!readmem(notes_ptrs[i], KVADDR, buf, SIZE(note_buf), "note_buf_t",
			     RETURN_ON_ERROR)) {
			error(WARNING,
				"cannot find NT_PRSTATUS note for cpu: %d\n", i);
			goto fail;
		}

		/*
		 * Do some sanity checks for this note before reading registers from it.
		 */
		note = (Elf64_Nhdr *)buf;
		p = buf + sizeof(Elf64_Nhdr);

		/*
		 * dumpfiles created with qemu won't have crash_notes, but there will
		 * be elf notes; dumpfiles created by kdump do not create notes for
		 * offline cpus.
		 */
		if (note->n_namesz == 0 && (DISKDUMP_DUMPFILE() || KDUMP_DUMPFILE())) {
			if (DISKDUMP_DUMPFILE())
				note = diskdump_get_prstatus_percpu(i);
			else if (KDUMP_DUMPFILE())
				note = netdump_get_prstatus_percpu(i);
			if (note) {
				/*
				 * SIZE(note_buf) accounts for a "final note", which is a
				 * trailing empty elf note header.
				 */
				long notesz = SIZE(note_buf) - sizeof(Elf64_Nhdr);

				if (sizeof(Elf64_Nhdr) + roundup(note->n_namesz, 4) +
				    note->n_descsz == notesz)
					BCOPY((char *)note, buf, notesz);
			} else {
				error(WARNING,
					"cannot find NT_PRSTATUS note for cpu: %d\n", i);
				continue;
			}
		}

		/*
		 * Check the sanity of NT_PRSTATUS note only for each online cpu.
		 */
		if (note->n_type != NT_PRSTATUS) {
			error(WARNING, "invalid NT_PRSTATUS note (n_type != NT_PRSTATUS)\n");
			goto fail;
		}
		if (!STRNEQ(p, "CORE")) {
			error(WARNING, "invalid NT_PRSTATUS note (name != \"CORE\"\n");
			goto fail;
		}

		/*
		 * Find correct location of note data. This contains elf_prstatus
		 * structure which has registers etc. for the crashed task.
		 */
		offset = sizeof(Elf64_Nhdr);
		offset = roundup(offset + note->n_namesz, 4);
		p = buf + offset; /* start of elf_prstatus */

		BCOPY(p + OFFSET(elf_prstatus_pr_reg), &panic_task_regs[i],
		      sizeof(panic_task_regs[i]));
	}

	/*
	 * And finally we have the registers for the crashed task. This is
	 * used later on when dumping backtrace.
	 */
	ms->crash_task_regs = panic_task_regs;

	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	return TRUE;

fail:
	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	free(panic_task_regs);
	return FALSE;
}

static int
loongarch64_get_elf_notes(void)
{
	struct machine_specific *ms = machdep->machspec;
	int i;

	if (!DISKDUMP_DUMPFILE() && !KDUMP_DUMPFILE() && !NETDUMP_DUMPFILE())
		return FALSE;

	panic_task_regs = calloc(kt->cpus, sizeof(*panic_task_regs));
	if (!panic_task_regs)
		error(FATAL, "cannot calloc panic_task_regs space\n");

	for (i = 0; i < kt->cpus; i++) {
		Elf64_Nhdr *note = NULL;
		size_t len;

		if (DISKDUMP_DUMPFILE())
			note = diskdump_get_prstatus_percpu(i);
		else if (KDUMP_DUMPFILE() || NETDUMP_DUMPFILE())
			note = netdump_get_prstatus_percpu(i);

		if (!note) {
			error(WARNING,
			      "cannot find NT_PRSTATUS note for cpu: %d\n", i);
			continue;
		}

		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note->n_namesz, 4);

		BCOPY((char *)note + len + OFFSET(elf_prstatus_pr_reg),
		      &panic_task_regs[i], sizeof(panic_task_regs[i]));
	}

	ms->crash_task_regs = panic_task_regs;

	return TRUE;
}

/*
 * Accept or reject a symbol from the kernel namelist.
 */
static int
loongarch64_verify_symbol(const char *name, ulong value, char type)
{
	if (!strncmp(name, ".L", 2) || !strncmp(name, "L0", 2))
		return FALSE;

	if (CRASHDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	if (STREQ(name, "_text") || STREQ(name, "_stext"))
		machdep->flags |= KSYMS_START;

	return (name && strlen(name) && (machdep->flags & KSYMS_START) &&
		!STRNEQ(name, "__func__.") && !STRNEQ(name, "__crc_"));
}

/*
 * Override smp_num_cpus if possible and necessary.
 */
static int
loongarch64_get_smp_cpus(void)
{
	return (get_cpus_online() > 0) ? get_cpus_online() : kt->cpus;
}

static ulong
loongarch64_get_page_size(void)
{
	return memory_page_size();
}

/*
 * Determine where vmalloc'd memory starts.
 */
static ulong
loongarch64_vmalloc_start(void)
{
	return first_vmalloc_address();
}

/*
 * Calculate and return the speed of the processor.
 */
static ulong
loongarch64_processor_speed(void)
{
	unsigned long cpu_hz = 0;

	if (machdep->mhz)
		return (machdep->mhz);

	if (symbol_exists("cpu_clock_freq")) {
		get_symbol_data("cpu_clock_freq", sizeof(int), &cpu_hz);
		if (cpu_hz)
			return(machdep->mhz = cpu_hz/1000000);
	}

	return 0;
}

/*
 * Checks whether given task is valid task address.
 */
static int
loongarch64_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);

	return (IS_KVADDR(task) && ALIGNED_STACK_OFFSET(task) == 0);
}

/*
 * 'help -m/M' command output
 */
void
loongarch64_dump_machdep_table(ulong arg)
{
	int others = 0;

	fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
	fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
	fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "        pgdir_shift: %d\n", PGDIR_SHIFT);
	fprintf(fp, "       ptrs_per_pgd: %lu\n", PTRS_PER_PGD);
	fprintf(fp, "       ptrs_per_pte: %ld\n", PTRS_PER_PTE);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "                 hz: %d\n", machdep->hz);
	fprintf(fp, "            memsize: %ld (0x%lx)\n",
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "         back_trace: loongarch64_back_trace_cmd()\n");
	fprintf(fp, "    processor_speed: loongarch64_processor_speed()\n");
	fprintf(fp, "              uvtop: loongarch64_uvtop()\n");
	fprintf(fp, "              kvtop: loongarch64_kvtop()\n");
	fprintf(fp, "    get_stack_frame: loongarch64_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: loongarch64_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: loongarch64_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: loongarch64_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: loongarch64_verify_symbol()\n");
	fprintf(fp, "         dis_filter: generic_dis_filter()\n");
	fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "           cmd_mach: loongarch64_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: loongarch64_get_smp_cpus()\n");
	fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
	fprintf(fp, "          is_uvaddr: generic_is_uvaddr()\n");
	fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "    init_kernel_pgd: NULL\n");
	fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
	fprintf(fp, "  line_number_hooks: NULL\n");
	fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
	fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
	fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
	fprintf(fp, "  sections_per_root: %ld\n", machdep->sections_per_root);
	fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
}

static void
pt_level_alloc(char **lvl, char *name)
{
	size_t sz = PAGESIZE();
	void *pointer = malloc(sz);

	if (!pointer)
	        error(FATAL, name);
	*lvl = pointer;
}

void
loongarch64_init(int when)
{
	char *string;

		switch (when) {
	case SETUP_ENV:
		machdep->process_elf_notes = process_elf64_notes;
		break;

	case PRE_SYMTAB:
		machdep->verify_symbol = loongarch64_verify_symbol;
		machdep->machspec = &loongarch64_machine_specific;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		break;

	case PRE_GDB:
		machdep->pagesize = loongarch64_get_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		if (machdep->pagesize >= 16384)
			machdep->stacksize = machdep->pagesize;
		else
			machdep->stacksize = machdep->pagesize * 2;

		pt_level_alloc(&machdep->pgd, "cannot malloc pgd space.");
		pt_level_alloc(&machdep->pmd, "cannot malloc pmd space.");
		pt_level_alloc(&machdep->ptbl, "cannot malloc ptbl space.");
		machdep->kvbase = 0x8000000000000000lu;
		machdep->identity_map_base = machdep->kvbase;
		machdep->is_kvaddr = generic_is_kvaddr;
		machdep->is_uvaddr = generic_is_uvaddr;
		machdep->uvtop = loongarch64_uvtop;
		machdep->kvtop = loongarch64_kvtop;
		machdep->cmd_mach = loongarch64_cmd_mach;
		machdep->back_trace = loongarch64_back_trace_cmd;
		machdep->eframe_search = loongarch64_eframe_search;
		machdep->get_stack_frame = loongarch64_get_stack_frame;
		machdep->vmalloc_start = loongarch64_vmalloc_start;
		machdep->processor_speed = loongarch64_processor_speed;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = loongarch64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = loongarch64_is_task_addr;
		machdep->get_smp_cpus = loongarch64_get_smp_cpus;
		machdep->dis_filter = generic_dis_filter;
		machdep->dump_irq = generic_dump_irq;
		machdep->show_interrupts = generic_show_interrupts;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = NULL;
		break;

	case POST_GDB:
		string = pc->read_vmcoreinfo("NUMBER(SECTION_SIZE_BITS)");
		if (string) {
			machdep->section_size_bits = strtoul(string, NULL, 10);
			free(string);
		} else
			machdep->section_size_bits = _SECTION_SIZE_BITS;


		string = pc->read_vmcoreinfo("NUMBER(MAX_PHYSMEM_BITS)");
		if (string) {
			machdep->max_physmem_bits = strtoul(string, NULL, 10);
			free(string);
		} else
			machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;

		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
					  "irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
					&machdep->nr_irqs);

		loongarch64_stackframe_init();
		loongarch64_ORC_init();

		if (!machdep->hz)
			machdep->hz = 250;
		break;

	case POST_VM:
		/*
		 * crash_notes contains machine specific information about the
		 * crash. In particular, it contains CPU registers at the time
		 * of the crash. We need this information to extract correct
		 * backtraces from the panic task.
		 */
		if (!ACTIVE() && !loongarch64_init_active_task_regs())
			error(WARNING,"cannot retrieve registers for active task%s\n\n",
				kt->cpus > 1 ? "s" : "");
		break;
	}
}

void
loongarch64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
	const struct machine_specific *ms = machdep->machspec;
	struct loongarch64_pt_regs *regs;

	if (!ms->crash_task_regs) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
		return;
	}

	regs = &ms->crash_task_regs[cpu];
	if (!regs->regs[LOONGARCH64_EF_SP] && !regs->csr_epc) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
		return;
	}

	fprintf(ofp,
		"     R0: %016lx   R1: %016lx   R2: %016lx\n"
		"     R3: %016lx   R4: %016lx   R5: %016lx\n"
		"     R6: %016lx   R7: %016lx   R8: %016lx\n"
		"     R9: %016lx  R10: %016lx  R11: %016lx\n"
		"    R12: %016lx  R13: %016lx  R14: %016lx\n"
		"    R15: %016lx  R16: %016lx  R17: %016lx\n"
		"    R18: %016lx  R19: %016lx  R20: %016lx\n"
		"    R21: %016lx  R22: %016lx  R23: %016lx\n"
		"    R24: %016lx  R25: %016lx  R26: %016lx\n"
		"    R27: %016lx  R28: %016lx  R29: %016lx\n"
		"    R30: %016lx  R31: %016lx\n"
		"    CSR era : %016lx    CSR badv: %016lx\n"
		"    CSR crmd: %08lx            CSR prmd: %08lx\n"
		"    CSR ecfg: %08lx           CSR estat: %08lx\n"
		"    CSR euen: %08lx",
		regs->regs[LOONGARCH64_EF_R0],
		regs->regs[LOONGARCH64_EF_R0 + 1],
		regs->regs[LOONGARCH64_EF_R0 + 2],
		regs->regs[LOONGARCH64_EF_R0 + 3],
		regs->regs[LOONGARCH64_EF_R0 + 4],
		regs->regs[LOONGARCH64_EF_R0 + 5],
		regs->regs[LOONGARCH64_EF_R0 + 6],
		regs->regs[LOONGARCH64_EF_R0 + 7],
		regs->regs[LOONGARCH64_EF_R0 + 8],
		regs->regs[LOONGARCH64_EF_R0 + 9],
		regs->regs[LOONGARCH64_EF_R0 + 10],
		regs->regs[LOONGARCH64_EF_R0 + 11],
		regs->regs[LOONGARCH64_EF_R0 + 12],
		regs->regs[LOONGARCH64_EF_R0 + 13],
		regs->regs[LOONGARCH64_EF_R0 + 14],
		regs->regs[LOONGARCH64_EF_R0 + 15],
		regs->regs[LOONGARCH64_EF_R0 + 16],
		regs->regs[LOONGARCH64_EF_R0 + 17],
		regs->regs[LOONGARCH64_EF_R0 + 18],
		regs->regs[LOONGARCH64_EF_R0 + 19],
		regs->regs[LOONGARCH64_EF_R0 + 20],
		regs->regs[LOONGARCH64_EF_R0 + 21],
		regs->regs[LOONGARCH64_EF_R0 + 22],
		regs->regs[LOONGARCH64_EF_R0 + 23],
		regs->regs[LOONGARCH64_EF_R0 + 24],
		regs->regs[LOONGARCH64_EF_R0 + 25],
		regs->regs[LOONGARCH64_EF_R0 + 26],
		regs->regs[LOONGARCH64_EF_R0 + 27],
		regs->regs[LOONGARCH64_EF_R0 + 28],
		regs->regs[LOONGARCH64_EF_R0 + 29],
		regs->regs[LOONGARCH64_EF_R0 + 30],
		regs->regs[LOONGARCH64_EF_R0 + 31],
		regs->csr_epc,
		regs->csr_badvaddr,
		regs->csr_crmd,
		regs->csr_prmd,
		regs->csr_ecfg,
		regs->csr_estat,
		regs->csr_euen);
}

static int
loongarch64_eframe_search(struct bt_info *bt)
{
	return error(FATAL, "-e option not supported on this architecture\n");
}

#else /* !LOONGARCH64 */

#include "defs.h"

void
loongarch64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
       return;
}

#endif /* !LOONGARCH64 */

#ifndef CND_IOUSERETHERNET_KRW_LAYOUT_H
#define CND_IOUSERETHERNET_KRW_LAYOUT_H

#import <Foundation/Foundation.h>

#include "CNDLabKernelProtocol.h"

#include <stdbool.h>
#include <stdint.h>

/*
 * One static kernel layout cnd_iouserethernet_krw_trigger.m can run against.
 * Every element is a pre-slide static in that image's own address space;
 * main() adds the live slide.  The vPhone 23A341 layout is the original one
 * (the CNDStatic* constants at the top of the .m, which remain the default
 * and are selected for every EXPECTED_BASE in the vPhone static space).  The
 * iPhone17,2 23A341 layout (CNDStaticPhone*) is defined at the bottom of the
 * .m next to its derivation citations.
 *
 * This header exists only so the layout type and accessors are declared
 * before their first use without inserting lines into the .m: the shared
 * validator (cnd_iouserethernet_krw_trigger.py PRODUCER_CONSTANTS) pins .m
 * line numbers, so the .m is edited in place and extended only after
 * main().
 */
typedef struct {
    const char *name;
    uint64_t kernelBase;
    uint64_t allProc;
    uint64_t zoneMin;
    uint64_t zoneMax;
    uint64_t ioEthernetCheckMultiGOT;
    uint64_t etherCheckMulti;
    uint64_t ioEthernetInitIfnetParams;
    uint64_t ioEthernetCheckMultiSigner;
    uint64_t enoexecReturn;
    uint64_t loadW0FromX0;
    uint64_t ifnetX0Dispatcher;
    /* Only --ifnet-kcall1-pac-canary is ported to this layout. */
    bool kcall1Only;
} CNDKernelLayout;

typedef struct CNDOptions CNDOptions;

/*
 * Select the layout whose static space contains EXPECTED_BASE.  Returns
 * false for an address below every known static base (the original
 * `debuggerLoadAddress < CNDStaticKernelBase` refusal, unchanged).
 */
static bool CNDSelectLayoutForBase(uint64_t expectedBase);
static const CNDKernelLayout *CNDLayout(void);
/* Slide bound, layout completeness and the layout's permitted modes. */
static bool CNDLayoutAccepts(uint64_t slide, const CNDOptions *options);
static NSString *CNDLayoutRefusal(uint64_t slide, const CNDOptions *options);
static void CNDReportLayout(NSMutableDictionary<NSString *, id> *report,
    uint64_t slide);

/*
 * EXPECTED_BASE argument.  The positional slot is always present: an
 * explicit 16-hex-digit address keeps the original contract and the layout
 * is chosen from it up front; the literal `auto` (or `-`) sets CNDAutoBase,
 * and the base the provider reports through its own KBase operation is then
 * the authority — the probe resolves the layout and the slide from the
 * phone's live kernel state, the way the physical RX probe resolves
 * g_kernel_base/g_kernel_slide on-device
 * (cnd_physical_cs_allow_invalid_probe.m:385-386,420).  CNDResolveBaseArgument
 * substitutes the observed base and re-selects the layout; it is a no-op for
 * an explicitly supplied address, so the VM flow is unchanged.
 */
static bool CNDAutoBase;
static bool CNDParseBaseArgument(int argc, const char *argv[],
    uint64_t *base);
static void CNDResolveBaseArgument(uint64_t *base, uint64_t observedBase);

#endif /* CND_IOUSERETHERNET_KRW_LAYOUT_H */

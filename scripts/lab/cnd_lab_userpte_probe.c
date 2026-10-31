/*
 * Resident user-space probe for the SPTM retype experiment.
 *
 * Maps a buffer, stamps a unique 64-bit canary at the start of every page, and
 * then loops storing and loading a generation value through those same user
 * mappings.  An external observer finds the backing frames by scanning the
 * readable physical aperture for the canaries, retypes one frame, and reads
 * this log to see whether the user mapping still writes.
 *
 * Page faults are caught with siglongjmp, so a revoked or trapped mapping is
 * reported instead of killing the process.  Three outcomes are distinct:
 *   state=ok       the store landed and read back   (mapping still writable)
 *   state=fault    the store raised SIGSEGV/SIGBUS  (write revoked, fatal)
 *   state=mismatch the store completed but the load returned something else
 *                  (store silently dropped -- emulated by a higher EL)
 *
 * Output is line-oriented and flushed every generation:
 *   READY va=... pages=... page=... canary=...
 *   CHANGE gen=... page=... state=... w=... r=...
 *   gen=... ok=... fault=... mismatch=... first_fault=... first_mismatch=...
 */
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define CND_PROBE_PAGE 0x4000UL
#define CND_PROBE_CANARY 0xCAFEBABE00000000ULL
#define CND_PROBE_TEST_BASE 0x5A5A000000000000ULL
#define CND_PROBE_TEST_OFFSET 0x100UL
#define CND_PROBE_MAX_PAGES 32768UL

static sigjmp_buf gCNDProbeJump;
static volatile sig_atomic_t gCNDProbeFaulted;

static void cnd_probe_fault(int signal_number)
{
    (void)signal_number;
    gCNDProbeFaulted = 1;
    siglongjmp(gCNDProbeJump, 1);
}

int main(int argc, char **argv)
{
    unsigned long pages = argc > 1 ? strtoul(argv[1], NULL, 0) : 1024;
    if (pages == 0 || pages > CND_PROBE_MAX_PAGES) {
        fprintf(stderr, "page count must be 1..%lu\n", CND_PROBE_MAX_PAGES);
        return 64;
    }

    unsigned char *base = mmap(NULL, (size_t)pages * CND_PROBE_PAGE,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    struct sigaction action = {0};
    action.sa_handler = cnd_probe_fault;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &action, NULL);
    sigaction(SIGBUS, &action, NULL);

    for (unsigned long index = 0; index < pages; index++) {
        *(volatile uint64_t *)(base + index * CND_PROBE_PAGE) =
            CND_PROBE_CANARY + index;
    }
    printf("READY va=%p pages=%lu page=%#lx canary=%#llx\n", (void *)base,
           pages, CND_PROBE_PAGE, (unsigned long long)CND_PROBE_CANARY);
    fflush(stdout);

    unsigned char *state = calloc(pages, 1);
    if (state == NULL) return 1;

    for (unsigned generation = 0;; generation++) {
        unsigned long ok = 0, faults = 0, mismatches = 0;
        unsigned long first_fault = pages, first_mismatch = pages;

        for (unsigned long index = 0; index < pages; index++) {
            volatile uint64_t *slot = (volatile uint64_t *)
                (base + index * CND_PROBE_PAGE + CND_PROBE_TEST_OFFSET);
            uint64_t want = CND_PROBE_TEST_BASE |
                ((uint64_t)generation << 16) | index;
            uint64_t got = 0;
            unsigned char next = 0;

            gCNDProbeFaulted = 0;
            if (sigsetjmp(gCNDProbeJump, 1) == 0) {
                *slot = want;
                got = *slot;
                if (got != want) next = 2;
            } else {
                next = 1;
            }

            if (next != state[index]) {
                printf("CHANGE gen=%u page=%lu state=%s w=%s r=%#llx\n",
                       generation, index,
                       next == 0 ? "ok" : next == 1 ? "fault" : "mismatch",
                       gCNDProbeFaulted ? "FAULT" : "ok",
                       (unsigned long long)got);
                fflush(stdout);
                state[index] = next;
            }

            if (next == 1) {
                faults++;
                if (index < first_fault) first_fault = index;
            } else if (next == 2) {
                mismatches++;
                if (index < first_mismatch) first_mismatch = index;
            } else {
                ok++;
            }
        }

        printf("gen=%u ok=%lu fault=%lu mismatch=%lu first_fault=%lu "
               "first_mismatch=%lu\n", generation, ok, faults, mismatches,
               first_fault, first_mismatch);
        fflush(stdout);
        usleep(250000);
    }
}

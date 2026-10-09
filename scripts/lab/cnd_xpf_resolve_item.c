#include <inttypes.h>
#include <stdio.h>

#include "xpf.h"

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <kernelcache> <xpf-item>\n", argv[0]);
        return 64;
    }
    if (xpf_start_with_kernel_path(argv[1]) != 0) {
        fprintf(stderr, "xpf start failed: %s\n", xpf_get_error());
        return 1;
    }

    uint64_t value = xpf_item_resolve(argv[2]);
    const char *error = xpf_get_error();
    if (value == 0) {
        fprintf(stderr, "resolve failed for %s: %s\n", argv[2],
                error ? error : "no value");
        xpf_stop();
        return 2;
    }

    printf("%s=0x%016" PRIx64 "\n", argv[2], value);
    xpf_stop();
    return 0;
}

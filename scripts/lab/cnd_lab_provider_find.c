/*
 * Scan a kernel address range for a masked 64-bit value over a single provider
 * connection.  Reads up to CND_LAB_KRW_MAX_TRANSFER bytes per step -- a whole
 * 16 KB frame per request -- so a full sweep of the readable physical aperture
 * costs one request per frame instead of one per word.
 *
 *   cnd-lab-provider-find SOCKET EXPECTED_KERNEL_BASE START END STEP MASK VALUE
 *
 * Prints one HIT line per match and a final SCANNED summary:
 *   HIT addr=0x... offset=0x... value=0x...
 *   SCANNED reads=N skipped=N hits=N
 *
 * A read that the provider refuses (EIO) is counted as skipped, never fatal.
 */
#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int transfer_all(int fd, void *buffer, size_t size, int writing)
{
    unsigned char *cursor = buffer;
    while (size != 0) {
        ssize_t amount = writing
            ? write(fd, cursor, size) : read(fd, cursor, size);
        if (amount == 0) return ECONNRESET;
        if (amount < 0) {
            if (errno == EINTR) continue;
            return errno != 0 ? errno : EIO;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return 0;
}

static int request(int fd, uint32_t operation, uint64_t address,
                   void *buffer, size_t length, uint64_t *value)
{
    int sends_payload = operation == CNDLabKRWOperationWrite;
    int receives_payload = operation == CNDLabKRWOperationRead;
    CNDLabKRWRequest message = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = address,
    };
    int result = transfer_all(fd, &message, sizeof(message), 1);
    if (result == 0 && sends_payload && length != 0) {
        result = transfer_all(fd, buffer, length, 1);
    }
    CNDLabKRWResponse response = {0};
    if (result == 0) {
        result = transfer_all(fd, &response, sizeof(response), 0);
    }
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 ||
        (receives_payload && response.length != length) ||
        (!receives_payload && response.length != 0))) {
        result = response.status != 0 ? response.status : EPROTO;
    }
    if (result == 0 && receives_payload && length != 0) {
        result = transfer_all(fd, buffer, length, 0);
    }
    if (result == 0 && value != NULL) *value = response.value;
    return result;
}

static int parse_u64(const char *text, uint64_t *value)
{
    if (!text || !value || !text[0] || text[0] == '-') return EINVAL;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') return EINVAL;
    *value = (uint64_t)parsed;
    return 0;
}

static int connect_provider(const char *path)
{
    if (!path || strlen(path) >=
        sizeof(((struct sockaddr_un *)0)->sun_path)) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    if (argc != 8 && argc != 9) {
        fprintf(stderr, "usage: %s PROVIDER_SOCKET EXPECTED_KERNEL_BASE "
                "START END STEP MASK VALUE [safe]\n", argv[0]);
        return 64;
    }
    int safe = argc == 9 && strcmp(argv[8], "safe") == 0;

    uint64_t expected_base = 0, start = 0, end = 0, step = 0;
    uint64_t mask = 0, value = 0;
    if (parse_u64(argv[2], &expected_base) != 0 ||
        parse_u64(argv[3], &start) != 0 ||
        parse_u64(argv[4], &end) != 0 ||
        parse_u64(argv[5], &step) != 0 ||
        parse_u64(argv[6], &mask) != 0 ||
        parse_u64(argv[7], &value) != 0) {
        fprintf(stderr, "invalid numeric argument\n");
        return 64;
    }
    if (step == 0 || end <= start || start < (UINT64_C(1) << 63)) {
        fprintf(stderr, "invalid range\n");
        return 64;
    }

    int fd = connect_provider(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "provider connect failed: %s\n", strerror(errno));
        return 1;
    }

    uint64_t capabilities = 0, kernel_base = 0;
    int result = request(fd, CNDLabKRWOperationCapabilities, 0,
                         NULL, 0, &capabilities);
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationKBase, 0, NULL, 0,
                         &kernel_base);
    }
    if (result != 0 || kernel_base != expected_base ||
        (capabilities & CNDLabKRWCapabilityKernelReadWrite) == 0) {
        fprintf(stderr, "provider identity failed: result=%d base=%#" PRIx64
                " expected=%#" PRIx64 " capabilities=%#" PRIx64 "\n",
                result, kernel_base, expected_base, capabilities);
        close(fd);
        return 2;
    }

    unsigned char *buffer = malloc(CND_LAB_KRW_MAX_TRANSFER);
    if (buffer == NULL) {
        close(fd);
        return 1;
    }

    uint64_t reads = 0, skipped = 0, hits = 0;
    for (uint64_t address = start; address < end;) {
        size_t length = CND_LAB_KRW_MAX_TRANSFER;
        if (end - address < (uint64_t)length) {
            length = (size_t)(end - address);
        }
        result = request(fd, safe ? CNDLabKRWOperationSafeRead
                                  : CNDLabKRWOperationRead,
                         address, buffer, length, NULL);
        if (result != 0) {
            skipped++;
            address += step;
            continue;
        }
        reads++;
        for (size_t offset = 0; offset + 8 <= length; offset += 8) {
            uint64_t word = 0;
            memcpy(&word, buffer + offset, sizeof(word));
            if ((word & mask) == value) {
                printf("HIT addr=%#" PRIx64 " offset=%#zx value=%#" PRIx64
                       "\n", address, offset, word);
                fflush(stdout);
                hits++;
            }
        }
        address += step;
    }

    printf("SCANNED reads=%" PRIu64 " skipped=%" PRIu64 " hits=%" PRIu64
           "\n", reads, skipped, hits);
    fflush(stdout);
    free(buffer);
    close(fd);
    return 0;
}

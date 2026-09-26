#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fileport.h>
#include <unistd.h>

extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_register(
    mach_port_t bootstrap, const char *service_name, mach_port_t service_port);

typedef char *(*IssueMachFunction)(const char *, const char *, unsigned int);

static int valid_service_name(const char *value)
{
    if (!value || !value[0] || strlen(value) > 127) return 0;
    for (const unsigned char *cursor = (const unsigned char *)value;
         *cursor; cursor++) {
        if (!(('a' <= *cursor && *cursor <= 'z') ||
              ('A' <= *cursor && *cursor <= 'Z') ||
              ('0' <= *cursor && *cursor <= '9') ||
              *cursor == '.' || *cursor == '-' || *cursor == '_')) return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 4 || !valid_service_name(argv[1]) || argv[2][0] == '\0' ||
        strlen(argv[2]) > 255 || argv[3][0] != '/') return 64;
    int descriptor = open(argv[3], O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC,
                          0600);
    if (descriptor < 0) return 65;
    size_t marker_length = strlen(argv[2]);
    if (write(descriptor, argv[2], marker_length) != (ssize_t)marker_length ||
        fsync(descriptor) != 0 || lseek(descriptor, 0, SEEK_SET) != 0) {
        close(descriptor);
        return 66;
    }
    mach_port_t fileport = MACH_PORT_NULL;
    if (fileport_makeport(descriptor, &fileport) != 0 ||
        fileport == MACH_PORT_NULL) {
        close(descriptor);
        return 67;
    }
    kern_return_t registered = bootstrap_register(
        bootstrap_port, argv[1], fileport);
    if (registered != KERN_SUCCESS) {
        fprintf(stderr, "bootstrap_register=%d errno=%d\n", registered,
                errno);
        mach_port_deallocate(mach_task_self(), fileport);
        close(descriptor);
        return 68;
    }
    IssueMachFunction issue = (IssueMachFunction)dlsym(
        RTLD_DEFAULT, "sandbox_extension_issue_mach");
    char *token = issue ? issue(
        "com.apple.security.exception.mach-lookup.global-name", argv[1], 0)
        : NULL;
    if (!token || !token[0]) {
        mach_port_deallocate(mach_task_self(), fileport);
        close(descriptor);
        return 69;
    }
    puts(token);
    fflush(stdout);
    free(token);
    mach_port_deallocate(mach_task_self(), fileport);
    close(descriptor);
    return 0;
}

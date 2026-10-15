#include <notify.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *name = "com.zeroxjf.cyanide.lab.pm-cross-class";
    if (argc == 2 && strcmp(argv[1], "m68") == 0) {
        name = "com.zeroxjf.cyanide.lab.pm-m68";
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [m68]\n", argv[0]);
        return 64;
    }
    int result = notify_post(name);
    if (result != NOTIFY_STATUS_OK) {
        fprintf(stderr, "notify_post failed: %d\n", result);
        return 1;
    }
    printf("posted %s\n", name);
    return 0;
}

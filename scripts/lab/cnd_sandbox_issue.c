#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef char *(*IssueFileFunction)(const char *, const char *, unsigned int);

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1][0] != '/') return 64;
    IssueFileFunction issue = (IssueFileFunction)dlsym(
        RTLD_DEFAULT, "sandbox_extension_issue_file");
    if (!issue) return 69;
    char *token = issue("com.apple.app-sandbox.read-write", argv[1], 0);
    if (!token) return 77;
    puts(token);
    free(token);
    return 0;
}

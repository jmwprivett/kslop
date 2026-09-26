#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void *cnd_remotecall_probe_server(void *unused)
{
    (void)unused;
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    snprintf(path, sizeof(path),
             "/var/tmp/cyanide-remotecall-probe-%d.sock", getpid());

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) return NULL;

    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(server);
        return NULL;
    }
    strcpy(address.sun_path, path);
    (void)unlink(path);
    if (bind(server, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(path, 0666) != 0 || listen(server, 1) != 0) {
        close(server);
        (void)unlink(path);
        return NULL;
    }

    static const char response[] = "CND_RC_PROBE\n";
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        (void)write(client, response, sizeof(response) - 1);
        close(client);
    }
    close(server);
    (void)unlink(path);
    return NULL;
}

__attribute__((constructor))
static void cnd_remotecall_probe_start(void)
{
    pthread_t thread = 0;
    if (pthread_create(&thread, NULL, cnd_remotecall_probe_server, NULL) == 0) {
        (void)pthread_detach(thread);
    }
}

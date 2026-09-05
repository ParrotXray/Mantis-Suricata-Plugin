/* Standalone end-to-end test: creates the two ring memfds, spawns suricata
 * with --capture-plugin mantis-capture, keeps pushing a known test frame
 * into the ingress ring, then tears suricata down and lets the caller
 * check eve.json/fast.log for the alert. Not part of the plugin itself --
 * scratch test harness only. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>

#include "mantis_ring.h"

#define CAPACITY 64
#define SLOT_SIZE 2048

/* Same DNS request for suricata.io used by Suricata's own ci-capture
 * example -- a real, valid Ethernet+IP+UDP+DNS frame. */
static const unsigned char DNS_REQUEST[94] = {
    0xa0, 0x36, 0x9f, 0x4c, 0x4c, 0x28, 0x50, 0xeb,
    0xf6, 0x7d, 0xea, 0x54, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x50, 0x19, 0xae, 0x00, 0x00, 0x40, 0x11,
    0x4a, 0xc4, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10,
    0x01, 0x01, 0x95, 0x97, 0x00, 0x35, 0x00, 0x3c,
    0x90, 0x6e, 0xdb, 0x12, 0x01, 0x20, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x73,
    0x75, 0x72, 0x69, 0x63, 0x61, 0x74, 0x61, 0x02,
    0x69, 0x6f, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x88, 0x51,
    0x20, 0xaf, 0x46, 0xc5, 0xdc, 0xce
};

static MantisRingHeader *make_ring(int *out_fd) {
    int fd = memfd_create("mantis-ring-test", 0);
    if (fd < 0) {
        perror("memfd_create");
        exit(1);
    }
    uint64_t total = MantisRingTotalSize(CAPACITY, SLOT_SIZE);
    if (ftruncate(fd, (off_t)total) != 0) {
        perror("ftruncate");
        exit(1);
    }
    void *map = mmap(NULL, (size_t)total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    MantisRingHeader *hdr = (MantisRingHeader *)map;
    hdr->magic = MANTIS_RING_MAGIC;
    hdr->capacity = CAPACITY;
    hdr->slot_size = SLOT_SIZE;
    hdr->head = 0;
    hdr->tail = 0;
    *out_fd = fd;
    return hdr;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <suricata-binary> <config.yaml>\n", argv[0]);
        return 1;
    }
    const char *suricata_bin = argv[1];
    const char *config_path = argv[2];

    int ig_fd, eg_fd;
    MantisRingHeader *ig = make_ring(&ig_fd);
    MantisRingHeader *eg = make_ring(&eg_fd);
    (void)eg;

    char args[128];
    snprintf(args, sizeof(args), "ig_fd=%d,eg_fd=%d", ig_fd, eg_fd);
    fprintf(stderr, "[producer] ig_fd=%d eg_fd=%d\n", ig_fd, eg_fd);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        execl(suricata_bin, suricata_bin, "-c", config_path, "--capture-plugin", "mantis-capture",
                "--capture-plugin-args", args, (char *)NULL);
        perror("execl");
        _exit(127);
    }

    /* Give suricata time to start up and dlopen the plugin. */
    sleep(2);

    for (int i = 0; i < 30; i++) {
        int ok = MantisRingPush(ig, DNS_REQUEST, sizeof(DNS_REQUEST));
        fprintf(stderr, "[producer] push #%d -> %s\n", i, ok ? "ok" : "FULL");
        usleep(100000);
    }

    sleep(2);
    fprintf(stderr, "[producer] sending SIGTERM to suricata (pid=%d)\n", pid);
    kill(pid, SIGTERM);

    int status = 0;
    waitpid(pid, &status, 0);
    fprintf(stderr, "[producer] suricata exited, status=%d\n", status);
    return 0;
}

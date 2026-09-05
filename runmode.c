/*
 * Runmode glue for the mantis-capture plugin.
 *
 * Two-phase startup, same pattern as Suricata's own
 * examples/plugins/ci-capture/runmode.c (verbatim-read from a suricata-8.0.5
 * checkout, the exact version the target deployment runs):
 *
 *   1. SCPluginsLoad() calls plugin->Init() (a static function in
 *      plugin.c) once during startup. That calls MantisRunModeSetArgs()
 *      to parse --capture-plugin-args into the statics below, then
 *      MantisRunModeRegister() to register a "single" runmode via
 *      RunModeRegisterNewRunMode(). No threads exist yet at this point.
 *   2. Later, Suricata's normal runmode dispatch (same code path used for
 *      every other capture method) calls the function just registered --
 *      RunModeSingle() -- which is where TmThreadCreatePacketHandler
 *      actually spawns the receive/decode/flow-worker chains.
 *
 * Deviation from the ci-capture example worth flagging: that example's
 * GetDefaultMode() returns "autofp" while it only ever registers a
 * "single" runmode -- looks like a latent inconsistency in the example
 * (relying on Suricata to fall back somehow). We register "single" and
 * return "single" from GetDefaultMode so this plugin's default mode is
 * guaranteed to resolve to something we actually registered.
 *
 * Args format (ours, not a Suricata convention): a comma-separated
 * key=value list, e.g. "ig_fd=12,eg_fd=13" -- the memfd numbers for the
 * ingress/egress rings, inherited by the suricata child process the same
 * way engine.rs already inherits config_fd/suppress_fd into it today.
 */

#include "suricata-common.h"
#include "runmodes.h"
#include "tm-threads.h"
#include "util-affinity.h"
#include "util-debug.h"
#include "util-device.h"

#include "runmode.h"
#include "source.h"

static MantisThreadInitData g_ingress = { .ring_fd = -1, .direction = MANTIS_DIR_INGRESS };
static MantisThreadInitData g_egress = { .ring_fd = -1, .direction = MANTIS_DIR_EGRESS };

int MantisRunModeSetArgs(const char *args)
{
    if (args == NULL) {
        SCLogError("mantis-capture: --capture-plugin-args is required (expected \"ig_fd=N,eg_fd=N\")");
        return -1;
    }

    char buf[256];
    strlcpy(buf, args, sizeof(buf));

    char *saveptr = NULL;
    for (char *tok = strtok_r(buf, ",", &saveptr); tok != NULL; tok = strtok_r(NULL, ",", &saveptr)) {
        char *eq = strchr(tok, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        const char *key = tok;
        int value = atoi(eq + 1);

        if (strcmp(key, "ig_fd") == 0) {
            g_ingress.ring_fd = value;
        } else if (strcmp(key, "eg_fd") == 0) {
            g_egress.ring_fd = value;
        }
    }

    if (g_ingress.ring_fd < 0 || g_egress.ring_fd < 0) {
        SCLogError("mantis-capture: missing ig_fd/eg_fd in --capture-plugin-args=\"%s\"", args);
        return -1;
    }
    return 0;
}

static int SpawnMantisThread(const char *thread_name, MantisThreadInitData *initdata)
{
    ThreadVars *tv = TmThreadCreatePacketHandler(
            thread_name, "packetpool", "packetpool", "packetpool", "packetpool", "pktacqloop");
    if (tv == NULL) {
        SCLogError("mantis-capture: TmThreadCreatePacketHandler failed for %s", thread_name);
        return -1;
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveMantis");
    if (tm_module == NULL) {
        FatalError("mantis-capture: TmModuleGetByName failed for ReceiveMantis");
    }
    TmSlotSetFuncAppend(tv, tm_module, initdata);

    tm_module = TmModuleGetByName("DecodeMantis");
    if (tm_module == NULL) {
        FatalError("mantis-capture: TmModuleGetByName failed for DecodeMantis");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        FatalError("mantis-capture: TmModuleGetByName failed for FlowWorker");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadSetCPU(tv, WORKER_CPU_SET);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        SCLogError("mantis-capture: TmThreadSpawn failed for %s", thread_name);
        return -1;
    }
    return 0;
}

static int RunModeSingle(void)
{
    if (SpawnMantisThread("RxMantisIngress", &g_ingress) != 0) {
        return -1;
    }
    if (SpawnMantisThread("RxMantisEgress", &g_egress) != 0) {
        return -1;
    }
    return 0;
}

void MantisRunModeRegister(int plugin_slot)
{
    /* Must happen before any thread's ReceiveMantisThreadInit calls
     * LiveGetDevice() -- both names are #defined once in source.h so this
     * can't drift from what source.c looks up. */
    LiveRegisterDevice(MANTIS_LIVEDEV_INGRESS);
    LiveRegisterDevice(MANTIS_LIVEDEV_EGRESS);

    RunModeRegisterNewRunMode(plugin_slot, "single", "Single threaded mantis-capture", RunModeSingle, NULL);
}

const char *MantisCaptureGetDefaultRunMode(void)
{
    return "single";
}

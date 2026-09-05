#ifndef MANTIS_RUNMODE_H
#define MANTIS_RUNMODE_H

/* Parses --capture-plugin-args ("ig_fd=N,eg_fd=N") and stashes the result
 * for RunModeSingle (called later, with no args, by Suricata's runmode
 * dispatch) to pick up. Returns 0 on success. Must be called before
 * MantisRunModeRegister. */
int MantisRunModeSetArgs(const char *args);

/* Mirrors CiCaptureIdsRegister from Suricata's own
 * examples/plugins/ci-capture/runmode.h (suricata-8.0.5): registers the
 * "single" runmode under plugin_slot. */
void MantisRunModeRegister(int plugin_slot);

/* Mirrors CiCaptureIdsGetDefaultRunMode. */
const char *MantisCaptureGetDefaultRunMode(void);

#endif /* MANTIS_RUNMODE_H */

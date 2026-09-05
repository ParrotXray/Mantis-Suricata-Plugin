#ifndef MANTIS_RUNMODE_H
#define MANTIS_RUNMODE_H

/* Parses --capture-plugin-args ("ig_fd=N,eg_fd=N"). Must be called before
 * MantisRunModeRegister. Returns 0 on success. */
int MantisRunModeSetArgs(const char *args);

/* Registers the "single" runmode under plugin_slot. */
void MantisRunModeRegister(int plugin_slot);

const char *MantisCaptureGetDefaultRunMode(void);

#endif /* MANTIS_RUNMODE_H */

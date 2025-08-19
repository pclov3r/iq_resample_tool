// include/input_sdrplay.h

#ifndef INPUT_SDRPLAY_H_
#define INPUT_SDRPLAY_H_

#include "input_source.h"
#include "argparse.h"
#include <stdint.h> // For uint8_t in get_sdrplay_device_name

/**
 * @brief Returns a pointer to the InputSourceOps struct that implements
 *        the input source interface for SDRplay device input.
 */
InputSourceOps* get_sdrplay_input_ops(void);

/**
 * @brief Returns the command-line options specific to the SDRplay module.
 */
const struct argparse_option* sdrplay_get_cli_options(int* count);

/**
 * @brief Sets the default configuration values for the SDRplay module.
 */
void sdrplay_set_default_config(AppConfig* config);

/**
 * @brief Helper function to get a human-readable device name from its hardware version ID.
 *        This is kept public as it can be useful for display purposes outside the module.
 */
const char* get_sdrplay_device_name(uint8_t hwVer);

#endif // INPUT_SDRPLAY_H_

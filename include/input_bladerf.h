// include/input_bladerf.h

#ifndef INPUT_BLADERF_H_
#define INPUT_BLADERF_H_

#include "input_source.h"
#include "argparse.h"

/**
 * @brief Returns a pointer to the InputSourceOps struct that implements
 *        the input source interface for BladeRF device input.
 */
InputSourceOps* get_bladerf_input_ops(void);

/**
 * @brief Returns the command-line options specific to the BladeRF module.
 */
const struct argparse_option* bladerf_get_cli_options(int* count);

/**
 * @brief Sets the default configuration values for the BladeRF module.
 */
void bladerf_set_default_config(AppConfig* config);

#endif // INPUT_BLADERF_H_

// include/input_wav.h

#ifndef INPUT_WAV_H_
#define INPUT_WAV_H_

#include "input_source.h"
#include "argparse.h"

/**
 * @brief Returns a pointer to the InputSourceOps struct that implements
 *        the input source interface for WAV file input.
 */
InputSourceOps* get_wav_input_ops(void);

/**
 * @brief Returns the command-line options specific to the WAV module.
 */
const struct argparse_option* wav_get_cli_options(int* count);

#endif // INPUT_WAV_H_

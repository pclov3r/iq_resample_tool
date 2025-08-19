// include/input_rawfile.h

#ifndef INPUT_RAWFILE_H_
#define INPUT_RAWFILE_H_

#include "input_source.h"
#include "argparse.h"

/**
 * @brief Returns a pointer to the InputSourceOps struct that implements
 *        the input source interface for raw file input.
 */
InputSourceOps* get_raw_file_input_ops(void);

/**
 * @brief Returns the command-line options specific to the Raw File module.
 */
const struct argparse_option* rawfile_get_cli_options(int* count);

#endif // INPUT_RAWFILE_H_

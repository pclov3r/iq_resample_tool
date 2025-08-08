// sample_convert.h

#ifndef SAMPLE_CONVERT_H_
#define SAMPLE_CONVERT_H_

#include "types.h" // For format_t, complex_float_t

/**
 * @brief Gets the number of bytes for a single sample of the given format.
 *        For complex formats, this is the size of the I/Q pair.
 * @param format The sample format.
 * @return The size in bytes, or 0 for unknown formats.
 */
size_t get_bytes_per_sample(format_t format);

/**
 * @brief Converts a block of raw input samples into normalized, gain-adjusted complex floats.
 *
 * This function handles all integer and float input formats, normalizes them to the
 * standard [-1.0, 1.0] range, and applies the specified linear gain multiplier in a
 * single pass.
 *
 * @param input_buffer Pointer to the raw input data.
 * @param output_buffer Pointer to the destination buffer for complex float data.
 * @param num_frames The number of frames (I/Q pairs) to convert.
 * @param input_format The format of the raw input data.
 * @param gain The linear gain multiplier to apply.
 * @return true on success, false if the input format is unhandled.
 */
bool convert_raw_to_cf32(const void* input_buffer, complex_float_t* output_buffer, size_t num_frames, format_t input_format, float gain);

/**
 * @brief Converts a block of normalized complex floats into the specified output byte format.
 *
 * @param input_buffer Pointer to the source complex float data.
 * @param output_buffer Pointer to the destination buffer for raw output data.
 * @param num_frames The number of frames (I/Q pairs) to convert.
 * @param output_format The target format for the raw output data.
 * @return true on success, false if the output format is unhandled.
 */
bool convert_cf32_to_block(const complex_float_t* input_buffer, void* output_buffer, size_t num_frames, format_t output_format);

#endif // SAMPLE_CONVERT_H_

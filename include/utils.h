// utils.h
#ifndef UTILS_H_
#define UTILS_H_

#include <stdint.h>
#include <stddef.h>
#include "types.h" // For AppConfig, SdrSoftwareType, AppResources, etc.

/**
 * @brief Gets a high-resolution monotonic time in seconds.
 * @return The time in seconds as a double.
 */
double get_monotonic_time_sec(void);

/**
 * @brief Clears the standard input buffer up to the next newline or EOF.
 */
void clear_stdin_buffer(void);

/**
 * @brief Formats a file size in bytes into a human-readable string (B, KB, MB, GB).
 */
const char* format_file_size(long long size_bytes, char* buffer, size_t buffer_size);

/**
 * @brief Platform-independent helper to get the base filename from a path.
 */
const char* get_basename_for_parsing(const AppConfig *config, char* buffer, size_t buffer_size);

/**
 * @brief Converts an SdrSoftwareType enum value to a human-readable string.
 */
const char* sdr_software_type_to_string(SdrSoftwareType type);

/**
 * @brief A helper to safely add a new key-value pair to the summary info struct.
 */
void add_summary_item(InputSummaryInfo* info, const char* label, const char* value_fmt, ...);

/**
 * @brief Helper function to trim leading/trailing whitespace from a string in-place.
 */
char* trim_whitespace(char* str);

/**
 * @brief Formats a duration in seconds into a human-readable HH:MM:SS string.
 */
void format_duration(double total_seconds, char* buffer, size_t buffer_size);

/**
 * @brief Converts a sample format name string to its corresponding format_t enum.
 */
format_t utils_get_format_from_string(const char *name);

/**
 * @brief Converts a format_t enum value to its full, human-readable description.
 */
const char* utils_get_format_description_string(format_t format);

/**
 * @brief Checks if a given frequency exceeds the Nyquist frequency for a sample rate and warns the user.
 */
bool utils_check_nyquist_warning(double freq_to_check_hz, double sample_rate_hz, const char* context_str);

/**
 * @brief Checks if a file exists at the given path and is accessible for reading.
 * @param full_path The full path to the file.
 * @return true if the file exists and can be opened for reading, false otherwise.
 */
bool utils_check_file_exists(const char* full_path);

#endif // UTILS_H_

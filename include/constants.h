#ifndef CONSTANTS_H_
#define CONSTANTS_H_

/**
 * @file constants.h
 * @brief Central configuration for application resource usage and performance tuning.
 *
 * This file defines the key parameters that govern the memory footprint, latency,
 * and processing quality of the iq_resample_tool. Values here represent a balance
 * between performance, memory usage, and stability. Adjust these values to tune
 * the application for specific hardware or use cases.
 */

// =============================================================================
// == Tier 1: High-Level Application Behavior
// =============================================================================

#define APP_NAME "iq_resample_tool"
#define PRESETS_FILENAME "iq_resample_tool_presets.conf"

// Defines the interval in seconds for printing progress updates to the console.
// Set to 0 to disable progress updates entirely.
#define PROGRESS_UPDATE_INTERVAL_SECONDS 1


// =============================================================================
// == Tier 2: Core Memory & Pipeline Architecture
// =============================================================================
// These are the most critical parameters for controlling the application's
// memory footprint and real-time performance.

/**
 * @def MEM_ARENA_SIZE_BYTES
 * @brief The size of the single memory arena for all startup allocations.
 *
 * Purpose: To hold all DSP objects, configuration strings, and other setup data,
 * eliminating hundreds of small `malloc` calls at startup.
 *
 * Trade-off: Must be large enough to hold all initialization data. 16MB is
 * a very safe starting point.
 */
#define MEM_ARENA_SIZE_BYTES (16 * 1024 * 1024) // 16 MB

/**
 * @def IO_SDR_INPUT_BUFFER_BYTES
 * @brief The size of the ring buffer between the SDR capture thread and the reader thread.
 *
 * Purpose: To absorb latency spikes from the OS or SDR driver and prevent sample
 * drops during heavy processing. This is critical for stability in buffered SDR mode.
 *
 * Trade-off: Larger values provide more stability against system stalls at the
 * cost of higher memory usage.
 */
#define IO_SDR_INPUT_BUFFER_BYTES (256 * 1024 * 1024) // 256 MB

/**
 * @def IO_FILE_WRITER_BUFFER_BYTES
 * @brief The size of the ring buffer between the post-processor thread and the writer thread.
 *
 * Purpose: A large size is critical for absorbing I/O latency spikes from the
 * filesystem (e.g., from antivirus scans or other disk activity), preventing the
 * real-time pipeline from stalling.
 *
 * Trade-off: Larger values provide more stability against I/O stalls at the
 * cost of higher memory usage. 1 GB is recommended for Windows systems.
 */
#define IO_FILE_WRITER_BUFFER_BYTES (1024 * 1024 * 1024) // 1 GB

/**
 * @def IO_FILE_WRITER_CHUNK_SIZE
 * @brief The size of the local buffer in the writer thread for disk writes.
 */
#define IO_FILE_WRITER_CHUNK_SIZE (1024 * 1024) // 1 MB

/**
 * @def PIPELINE_NUM_CHUNKS
 * @brief The number of "work trays" (SampleChunks) in the processing pipeline.
 *
 * Purpose: Defines the depth of the pipeline.
 *
 * Trade-off: More chunks increase overall pipeline latency but can improve
 * throughput by keeping all CPU cores busy. Fewer chunks reduce latency but
 * may lead to thread starvation if one stage is a bottleneck.
 */
#define PIPELINE_NUM_CHUNKS 512

/**
 * @def PIPELINE_CHUNK_BASE_SAMPLES
 * @brief The base number of samples to read from the source in each chunk.
 *
 * Note: This is NOT the full processing buffer size per chunk, which is
 * calculated dynamically at runtime to be larger if resampling or FFT
 * filtering requires it.
 *
 * Trade-off: Larger chunks have higher processing latency but lower per-chunk
 * overhead. Smaller chunks have lower latency but more overhead.
 */
#define PIPELINE_CHUNK_BASE_SAMPLES 16384

/**
 * @def RESAMPLER_OUTPUT_SAFETY_MARGIN
 * @brief A safety margin for the resampler's output buffer calculation.
 */
#define RESAMPLER_OUTPUT_SAFETY_MARGIN  128


// =============================================================================
// == Tier 3: DSP Algorithm Quality & Tuning
// =============================================================================

// The default stop-band attenuation for the liquid-dsp resampler, in dB.
// Higher values create a higher-quality, steeper filter at the cost of more CPU.
#define RESAMPLER_QUALITY_ATTENUATION_DB 60.0f

// Defines the default sharpness of user-defined FIR filters. The transition width will be
// this fraction of the filter's characteristic frequency (e.g., cutoff).
// A smaller value results in a sharper, higher-quality (but more CPU-intensive) filter.
#define DEFAULT_FILTER_TRANSITION_FACTOR 0.25f

// The cutoff frequency for the DC blocking high-pass filter.
#define DC_BLOCK_CUTOFF_HZ 10.0f

// --- Filter Design & Analysis Tuning ---
#define FILTER_MINIMUM_TAPS 21
#define FILTER_GAIN_ZERO_THRESHOLD 1e-9f
#define FILTER_FREQ_RESPONSE_POINTS 2048

// --- I/Q Correction Algorithm Tuning ---
#define IQ_CORRECTION_FFT_SIZE           1024
#define IQ_CORRECTION_DEFAULT_PERIOD     2000000 // Samples between optimization runs
#define IQ_BASE_INCREMENT                0.0001f // Step size for the optimizer
#define IQ_MAX_PASSES                    25      // Iterations per optimization run
#define IQ_CORRECTION_PEAK_THRESHOLD_DB -60.0f   // Signal power threshold to trigger optimization
#define IQ_CORRECTION_SMOOTHING_FACTOR   0.05f   // Smoothing factor for updating correction params


// =============================================================================
// == Tier 4: SDR Hardware Interaction & Tuning
// =============================================================================
// Default values and tuning parameters specific to each SDR device.

#if defined(WITH_RTLSDR)
#define RTLSDR_DEFAULT_SAMPLE_RATE 2400000.0
#endif

#if defined(WITH_SDRPLAY)
#define SDRPLAY_DEFAULT_SAMPLE_RATE_HZ 2000000.0
#define SDRPLAY_DEFAULT_BANDWIDTH_HZ   1536000.0
#endif

#if defined(WITH_HACKRF)
#define HACKRF_DEFAULT_SAMPLE_RATE 8000000.0
#define HACKRF_DEFAULT_LNA_GAIN    16
#define HACKRF_DEFAULT_VGA_GAIN    0
#endif

#if defined(WITH_BLADERF)
#define BLADERF_DEFAULT_SAMPLE_RATE_HZ 2000000
#define BLADERF_DEFAULT_BANDWIDTH_HZ   1500000
// --- BladeRF Stream Tuning ---
#define BLADERF_SYNC_CONFIG_TIMEOUT_MS   3500
#define BLADERF_SYNC_RX_TIMEOUT_MS       5000
#define BLADERF_TRANSFER_SIZE_SECONDS    0.25

// --- BladeRF Adaptive Streaming Profiles ---
// These profiles are designed to be safe and reliable on both Windows and a default
// Linux system (with a 16MB usbfs memory limit). They prioritize stability over
// aggressive optimization that may fail on un-tuned systems.

// Tier 1: Low Latency (< 1 MSPS)
// Memory Footprint: 32 * 16384 = 0.5 MB
#define BLADERF_PROFILE_LOWLATENCY_NUM_BUFFERS        32
#define BLADERF_PROFILE_LOWLATENCY_BUFFER_SIZE        16384
#define BLADERF_PROFILE_LOWLATENCY_NUM_TRANSFERS      16

// Tier 2: Balanced (1 to 5 MSPS)
// Memory Footprint: 64 * 32768 = 2 MB
#define BLADERF_PROFILE_BALANCED_NUM_BUFFERS          64
#define BLADERF_PROFILE_BALANCED_BUFFER_SIZE          32768
#define BLADERF_PROFILE_BALANCED_NUM_TRANSFERS        32

// Tier 3: High-Throughput (>= 5 MSPS)
// Memory Footprint: 64 * 65536 = 4 MB
// This is the most robust profile for all high-speed rates on a default system.
// Advanced Linux users can increase system usbfs memory for even better performance.
// Example: `sudo sh -c 'echo 128 > /sys/module/usbcore/parameters/usbfs_memory_mb'`
#define BLADERF_PROFILE_HIGHTHROUGHPUT_NUM_BUFFERS    64
#define BLADERF_PROFILE_HIGHTHROUGHPUT_BUFFER_SIZE    65536
#define BLADERF_PROFILE_HIGHTHROUGHPUT_NUM_TRANSFERS  32
#endif // defined(WITH_BLADERF)


// =============================================================================
// == Tier 5: Sanity Checks & Hard Limits
// =============================================================================
// These values are not for performance tuning but act as safety rails to
// prevent crashes from invalid input or extreme configurations.

#define MIN_ACCEPTABLE_RATIO      0.001f
#define MAX_ACCEPTABLE_RATIO      1000.0f
#define SHIFT_FACTOR_LIMIT        5.0
#define MAX_FILTER_CHAIN          5
#define MAX_PRESETS               128
#define MAX_LINE_LENGTH           1024
#define MAX_SUMMARY_ITEMS         16

// A hard upper limit on buffer sizes to prevent unreasonable memory allocation
// if filter parameters result in a huge number of taps.
#define MAX_ALLOWED_FFT_BLOCK_SIZE (1024 * 1024) // 1M samples
#define MAX_PATH_BUFFER           4096

#endif // CONSTANTS_H_

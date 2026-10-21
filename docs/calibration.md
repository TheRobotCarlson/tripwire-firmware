# Calibration

When an alarm is active, serial output prints:

```
cal: f0=XXX.X Hz h2=X.XX h3=X.XX snr=XX.X nf=X.XXeXX conf_ema=X.XX rms=X.XXXXX
```

Record these values with and without a drone present (or play rotor audio through a speaker).

## Tuning Parameters

Key parameters in `main/audio_task.c` and `main/audio_processor.c`:

| Symbol | Default | File | Description |
|:---|:---|:---|:---|
| `SAMPLE_RATE_HZ` | `16000` | `audio_processor.h` | Sample rate (Hz) |
| `FRAME_SAMPLES` | `1024` | `audio_processor.h` | FFT size (samples per frame) |
| `HOP_MS` | `100` | `audio_task.c` | Frame hop interval (ms) |
| `HARM_F0_MIN_HZ` | `180` | `audio_task.c` | Fundamental search lower bound (Hz) |
| `HARM_F0_MAX_HZ` | `2400` | `audio_task.c` | Fundamental search upper bound (Hz); 3×f₀ must stay < Nyquist |
| `CONF_ON` | `0.30` | `audio_task.c` | Smoothed confidence threshold to trigger alarm |
| `CONF_OFF` | `0.18` | `audio_task.c` | Smoothed confidence threshold to clear alarm |
| `SUSTAIN_FRAMES_ON` | `2` | `audio_task.c` | Consecutive frames above CONF_ON to trigger |
| `SUSTAIN_FRAMES_OFF` | `8` | `audio_task.c` | Consecutive frames below CONF_OFF to clear |
| `RMS_MIN` | `0.00003` | `audio_task.c` | Minimum windowed RMS — frames below this are skipped. About 37 dB SPL at the mic, just above the mic's own hiss. Batear's `0.0004` was about 57 dB SPL, louder than a quiet field |
| `LEVEL_DB_AT_WIN_RMS1` | `127.3` | `audio_task.c` | dB SPL for a windowed RMS of 1.0 (INMP441 / ICS-43434 at -26 dBFS for 94 dB SPL). Sets the once-a-second `level: LAeq=` log line |
| `EMA_ALPHA` | `0.25` | `audio_task.c` | Exponential moving average factor for confidence |
| `AUDIO_PROC_HARM_PEAK_MIN_SNR` | `4.0` | `audio_processor.c` | Minimum f₀ peak SNR vs noise floor |
| `AUDIO_PROC_HARM_MIN_H2` | `0.07` | `audio_processor.c` | Minimum P(2f₀)/P(f₀) ratio |
| `AUDIO_PROC_HARM_MIN_H3` | `0.035` | `audio_processor.c` | Minimum P(3f₀)/P(f₀) ratio |

!!! tip
    Enable `BATEAR_AUDIO_PERF_LOG` in menuconfig for per-frame DSP timing.

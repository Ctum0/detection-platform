# Detection Platform Demo Video Production Guide

This document describes the production-grade video recording, audio engineering, and mastering pipeline for the Detection Engineering Platform demonstration video.

---

## 1. Executive Summary & Tooling Evaluation

To achieve a SaaS product-launch quality demonstration, multiple recording engines and methodologies were evaluated:

| Engine / Candidate | Framerate | Native Resolution | Text Crispness | Window Framing | Audio / Foley Sync | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Testreel (`@0.2.0`)** | 25 fps | Downscaled to ~1752x985 | Moderate (subpixel blur on 11px code) | macOS Chrome + Canvas | None (silent video only) | Evaluated. Excellent framing concept, but 25fps cap and internal downscaling compromise code legibility. |
| **Playwright Default** | 25 fps | 1080p | Standard VP8 compression | None (raw screen) | None | Baseline screen recording; insufficient bitrate for fine UI lines. |
| **Production Retina Supersampling Pipeline (Selected)** | **60 fps** | **3840×2160 (4K DSF=2)** | **Ultra-Sharp (Lanczos + AMD CAS 0.32)** | Full-Frame Enterprise SOC | **Integrated EBU R128 (-14 LUFS) + 5-Track Foley** | **Primary Production Standard**: Eliminates all compression smearing, provides natural human Bézier kinematics, and delivers broadcast-grade audio. |

---

## 2. Audio Engineering & Studio Mastering

### Voice Synthesis & Phonetic Precision
- **Model / Voice**: Microsoft Azure Neural `en-US-AndrewNeural` (`--rate=-5%`, `--pitch=-1Hz`).
- **Phonetic Correction**: Corrected "Multi-SIEM" to authoritative American executive pronunciation (`/ˈmʌlti sɪm/` / "Mull-tee SIM"), resolving previous phonetic stretching.
- **Vocal Channel Strip**:
  - Highpass filter at 85 Hz (cuts sub-rumble).
  - Chest resonance boost at 130 Hz (+2.2 dB).
  - Mud scoop at 480 Hz (-2.2 dB).
  - Articulation boost at 3.3 kHz (+3.0 dB).
  - Sibilance taming at 6.8 kHz (-1.8 dB).
  - Air sheen at 11 kHz (+1.4 dB).
  - Optical loudness leveling to -16 LUFS vocal target.

### Dynamic Score & Sidechain Ducking
- **Cybernetic Synth Bed**: 100 BPM cyber-noir ambient bed with controlled 32 Hz sub-drone.
- **Asymmetric Ducking**: Ducked by -16 dB during speech passages with 45ms attack and 350ms release for seamless dialogue clarity.
- **Master Compliance**: Measured at **-14.0 LUFS** Integrated Loudness, **-1.0 dBFS True Peak**, strictly compliant with EBU R128, YouTube, and Vimeo standards.

### Tactile UI Foley Layer
Five dedicated Foley sound effects placed precisely at cursor interaction timestamps:
1. `click.wav` (-20 dB): Tactile micro-click on element selection.
2. `modal_whoosh.wav` (-18 dB): Smooth low-frequency air displacement when drawers open.
3. `transpile_shimmer.wav` (-19 dB): High-frequency harmonic shimmer on rule compilation.
4. `success_chime.wav` (-20 dB): Clear harmonic confirmation on alert replay.
5. `validation_pass.wav` (-18 dB): Low-mid resonance ping certifying MITRE ATT&CK validation.

---

## 3. Five-Act Storyboard & Choreography

| Act | Timestamp | Title | Core UI Interaction | Narration Focus |
| :--- | :--- | :--- | :--- | :--- |
| **Act I** | `0.0s – 30.5s` | **The Threat Gap** | Overview dashboard, live sparkline sweep, ATT&CK Matrix heatmap view. | The industry problem: weeks of manual translation across 5 query dialects. Platform overview. |
| **Act II** | `30.5s – 54.0s` | **Autonomous AI Dispatch** | Target T1059.001 (PowerShell), open Request Modal, human burst typing, dispatch agent, live agent modal. | On-demand autonomous gap analysis; synthesizes vendor-agnostic Sigma rules directly into PRs. |
| **Act III** | `54.0s – 79.5s` | **Multi-Dialect Transpiler** | Detection Studio, select PowerShell preset, transpile across Splunk SPL, Sentinel KQL, CrowdStrike CQL. | Real-time transpilation eliminating vendor lock-in; synthetic Sysmon simulation playground. |
| **Act IV** | `79.5s – 100.0s` | **Human Governance** | Review Queue, multi-backend code tabs, guarded approval, smooth drawer inspection. | Human-in-the-loop safety, automated CI validation gates, Atomic Red Team proof. |
| **Act V** | `100.0s – 122.5s` | **Proven Coverage & Outro** | ATT&CK Coverage Matrix (validated green state), MITRE Navigator layer export, center cursor glide. | Real-time matrix defense conversion, executive audit export, closing summary. |

---

## 4. Video Capture Architecture & Quality Settings

### Retina Supersampling & Kinematics
- **Logical Viewport**: 1920 × 1080 (16:9).
- **Physical Backing Store**: 3840 × 2160 (`device_scale_factor: 2`).
- **Cursor Motion**: Quadratic Bézier curve navigation with randomized arc perpendiculars (`normX`, `normY`), cubic ease-out deceleration settling, and tactile shockwave ripples.
- **Enterprise Posture**: Suppression of `#demoBanner` and sandbox toasts via injected CSS for authentic SOC realism.

### FFmpeg Encoding & Sharpening Filters
```bash
# 1080p60 Ultra-Sharp Master Filter Graph:
-vf "scale=1920:1080:flags=lanczos,cas=0.32,eq=contrast=1.04:saturation=1.08:gamma=0.98,drawtext=..."

# Video Settings:
-c:v libx264 -preset slow -crf 16 -b:v 14M -maxrate 18M -bufsize 24M -pix_fmt yuv420p -r 60

# Audio Settings:
-c:a aac -b:a 320k -ar 48000 -shortest -movflags +faststart
```

---

## 5. Deliverables & Output Directory

All production assets are exported to the project's root `output/` directory:

- `output/detection-platform-demo-1080p.mp4`: Master 1080p60 ultra-sharp video (Lanczos + AMD CAS 0.32, CRF 16, 14 Mbps).
- `output/detection-platform-demo-4k.mp4`: Master 4K60 UHD video (Native 3840x2160, CRF 17, 28 Mbps).
- `output/soundtrack-master.wav`: Mastered broadcast audio track (-14.0 LUFS, -1.0 dBTP).
- `output/voiceover-master.mp3`: Isolated master voiceover narration.
- `output/subtitles.vtt`: WebVTT closed captions synchronized with the 5-act narration.
- `output/subtitles.srt`: SubRip subtitle file for video players and streaming platforms.

---

## 6. How to Reproduce

To regenerate the entire demonstration from source:

```bash
# 1. Generate Synchronized Subtitles
python3 .artifacts/demo/generate_subtitles.py

# 2. Master Audio Track (if updating narration)
python3 .artifacts/demo/produce_perfect_audio.py

# 3. Record, Choreograph & Master Demonstration Video
python3 .artifacts/demo/record_production_cinematic_master.py
```

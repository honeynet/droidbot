# DroidBot Wikipedia compatibility report

Date: 2026-07-27

## Decision

Conditional go for dataset development on Android APIs 29, 31, 34, and 35.
All four emulators completed short Wikipedia exploration runs and produced
native screenshots, accessibility-derived states, events, and `utg.js`.
API 31 and newer emit repeated reconnect warnings from DroidBot's legacy
accessibility helper, so multi-hour production collection is not approved
until a soak run confirms that the helper recovers indefinitely.

## Environment

- Host: Windows
- DroidBot runtime: Python 3.12.13
- APK parser: Androguard 4.1.4
- App: locally built Wikipedia `prodDebug`, package `org.wikipedia`
- Emulator size: 432 x 768 at 160 dpi
- Policy: DroidBot `dfs_greedy`
- Event stabilization: existing fixed event interval, one second

The current Wikipedia debug APK exposes both Wikipedia and LeakCanary launcher
aliases. DroidBot now deterministically prefers a launcher owned by the target
package, selecting `org.wikipedia.DefaultIcon`.

## Results

| API | Android | Events | Observations | Result | Notes |
| --- | --- | ---: | ---: | --- | --- |
| 29 | 10 | 10 | 11 | Pass | Touch, Back, screenshots, view trees and UTG verified; 2 ineffective transitions retained. |
| 31 | 12 | 8 | 9 | Pass with warning | Accessibility helper reconnected repeatedly during startup. |
| 34 | 14 | 6 | 7 | Pass with warning | Scroll and touch events succeeded; helper reconnect warnings continued. |
| 35 | 15 | 6 | 7 | Pass after retry | First attempt encountered a transient offline ADB device; immediate retry completed. |

Every completed dataset passed referential-integrity and N+1 trajectory
validation. Every saved screenshot was 432 x 768, so no screenshot downscaling
is required.

## Compatibility changes

The exploration policy, event implementations, `DeviceState` hashing, and UTG
construction remain unchanged. Runtime compatibility required:

- use the Androguard 4 import path;
- use standard `pathlib` resource paths instead of deprecated
  `pkg_resources`;
- use Python 3.12 because Python 3.13 removed `telnetlib`, which DroidBot's
  QEMU adapter still imports;
- prefer a package-owned launcher when an APK contains launchers from debug
  dependencies;
- make cleanup best-effort so a temporary ADB disconnect does not mask the
  original failure.

## Stabilization decision

Screenshot-difference stabilization is intentionally not implemented in the
initial collector. Observations are captured after DroidBot's existing event
interval. The pilot dataset should be manually audited for premature captures.
Add image-difference stabilization only if more than 5 percent of observations
are visibly transient or misaligned with their view trees.

## Remaining go/no-go check

Run at least one four-hour soak on API 29 and one on API 35. Record helper
reconnect count, incomplete transitions, ADB disconnects, missing view trees,
and process exit status. A run is accepted only if it exits cleanly or can
continue through helper reconnections without losing trajectory integrity.

## Run locations

Smoke artifacts are under `compatibility_runs/`:

- `api29_smoke_20260727`
- `api29_collector_20260727`
- `api31_collector_20260727`
- `api34_collector_20260727`
- `api35_collector_retry_20260727`

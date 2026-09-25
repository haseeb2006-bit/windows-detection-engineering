# First End-to-End Detection Test

**Date:** 26 Sep 2026

## Purpose
Prove the full pipeline works before starting Case 1: VM generates telemetry (Sysmon)
→ export to EVTX → Hayabusa scans it against Sigma rules → results saved.

## Method
1. Exported Sysmon Operational log from `lab-win11` (Save All Events As → sysmon-export.evtx)
2. Moved file from VM to host via a temporary VirtualBox shared folder (`D:\lab\exports`)
3. Ran Hayabusa's `dfir-timeline` command using the bundled "Core" rule set (2,211 rules,
   stable + test status, high/critical severity)

Command used:

hayabusa-4.1.0-win-x64.exe dfir-timeline -d D:\lab\exports -o D:\lab\exports\first-scan-results.csv


## Result
- Total events scanned: 27,665
- Events with hits: 29 (0.10%)
- Unique detections: 1 rule ("Proc Exec (Sysmon Alert)", high severity)
- No critical/emergency detections (expected, no adversarial activity was performed yet)

## Interpretation
This confirms the pipeline works end-to-end using only Hayabusa's bundled rules and
normal, non-adversarial VM background activity. No custom Sigma rules have been written
yet. Case 1 (PowerShell detection) starts next, with hypotheses and variants written
and committed before any testing.

## Note on shared folder
A temporary VirtualBox shared folder was used to move the exported EVTX out of the
isolated VM. This is a controlled, single-purpose channel (only `D:\lab\exports` is
shared), separate from general clipboard/drag-and-drop, which remain disabled.
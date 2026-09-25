# Versions and Environment

Tracking software versions for reproducibility.

## Host machine
- OS: Windows 11 (build 26200)
- CPU: Intel Core i7-8650U (4 cores / 8 threads)
- RAM: 16 GB

## Host software
- VirtualBox: 7.2.20
- Git, VS Code, GitHub Desktop: already installed

## VM
- Name: lab-win11
- Windows 11 Home, installed via unattended install
- ISO: Win11_25H2_English_x64_v2.iso (Microsoft official, downloaded 22 Sep 2026)
- Allocated: 6144 MB RAM, 2 CPUs, 35 GB disk
- Snapshot taken: clean-install (before any lab configuration)

## Telemetry
- Sysmon: installed via Sysmon64.exe
- Sysmon config: "balanced" profile from olafhartong/sysmon-modular
  (https://github.com/olafhartong/sysmon-modular)
- Verified working: Event Viewer confirms events logging under
  Applications and Services Logs > Microsoft > Windows > Sysmon > Operational

## Tools
- Hayabusa: v4.1.0 (Suzumushi Release), downloaded from
  https://github.com/Yamato-Security/hayabusa/releases
  Installed at D:\lab\tools\hayabusa (kept outside the repo)
- Python version:

_Last updated: 26 Sep 2026_
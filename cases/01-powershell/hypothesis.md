# Case 1: PowerShell / Command Execution

## Hypothesis 1: Encoded PowerShell commands

**Claim:** When PowerShell runs a command using the `-EncodedCommand` flag (or its
abbreviations `-enc` / `-e`), the full command is hidden as Base64 text, invisible
to simple keyword-based detection. This flag itself is unusual in normal, everyday
PowerShell use and should be detectable directly, regardless of what the encoded
command actually does.

**Expected evidence:** Sysmon Event ID 1 (process creation), specifically the
`CommandLine` field, should contain the `-EncodedCommand` flag (or an abbreviation)
followed by a long Base64 string.

**ATT&CK reference:** T1027.010 (Command Obfuscation), T1059.001 (PowerShell)

## Test variants

| # | Variant                                             | Purpose                                                                                |
| - | --------------------------------------------------- | -------------------------------------------------------------------------------------- |
| 1 | `powershell.exe -EncodedCommand <base64>`           | Baseline: full flag name                                                               |
| 2 | `powershell.exe -enc <base64>`                      | Abbreviated flag                                                                       |
| 3 | `powershell.exe -e <base64>`                        | Minimal abbreviation                                                                   |
| 4 | Variant 1, launched via `cmd.exe` as parent         | Tests whether parent process affects detection                                         |
| 5 | `powershell.exe -EnCoDedCoMmAnD <base64>`           | Mixed-case flag (Windows commands are case-insensitive)                                |
| 6 | `powershell.exe -Command "Invoke-Expression (...)"` | Negative test: different obfuscation technique, NOT expected to be caught by this rule |
| 7 | `powershell.exe -Command "Write-Host Hello"`        | Benign baseline: must NOT be flagged                                                   |

All variants use harmless payloads (printing text only). No real obfuscated
malicious commands are used.

**Status:** Hypothesis and variants committed before any testing.

Date: 27 Sep 2026

## Test Results

### Variant 1 — Baseline: Full `-EncodedCommand` flag

**Execution result:** Successful

The test was executed using `powershell.exe -EncodedCommand` with a harmless Base64-encoded command. PowerShell successfully decoded and executed the payload, producing:

`Hello from Case 1 testing`

**Sysmon evidence:**

* **Event ID:** 1 — Process Create
* **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **CommandLine:** `powershell.exe -EncodedCommand <Base64 payload>`
* **RuleName:** `technique_id=T1059.001,technique_name=PowerShell`
* **ParentImage:** `C:\Windows\System32\cmd.exe`
* **EventRecordID:** `580`
* **Event time:** `2026-10-05 17:57:05 UTC`

**Observation:** Sysmon successfully captured the `-EncodedCommand` flag and the Base64 payload in the Event ID 1 `CommandLine` field. This matches the expected evidence defined in the hypothesis.

**Evidence collected:**

* `case1-run1.evtx` — full Sysmon log from the test session
* `case1-variant1-powershell.evtx` — saved Event ID 1 evidence for Variant 1

**Variant 1 status:** Confirmed.

### Variant 2 — Abbreviated `-enc` flag

**Execution result:** Successful

Command run:
`powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVgBhAHIAaQBhAG4AdAAgADIAIAB0AGUAcwB0ACAAbwBrACcA`
(decodes to `Write-Host 'Variant 2 test ok'`)

The Base64 payload was generated independently on the host using PowerShell's
`[System.Text.Encoding]::Unicode.GetBytes()` + `[Convert]::ToBase64String()`, confirming
understanding of the encoding process rather than reusing a pre-made string.

PowerShell output:
`Variant 2 test ok`

**Sysmon evidence:**

* **Event ID:** 1 — Process Create
* **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **CommandLine:** `"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVgBhAHIAaQBhAG4AdAAgADIAIAB0AGUAcwB0ACAAbwBrACcA`
* **RuleName:** `technique_id=T1059.001,technique_name=PowerShell`
* **ParentImage:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **Event time:** `2026-10-05 18:50:10 UTC`

**Observation:** Sysmon captured the abbreviated `-enc` flag just as reliably as the
full `-EncodedCommand` flag in Variant 1. Confirms the hypothesis holds for this
abbreviation as well.

**Method note:** This event was located using `Get-WinEvent` in an elevated
PowerShell session (`Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
-MaxEvents 50 | Where-Object { $_.Id -eq 1 }`) rather than manually scrolling
Event Viewer's GUI. This proved faster and more reliable for pinpointing a specific
recent event among hundreds of background entries. `Get-WinEvent` requires an
elevated (Administrator) PowerShell session to read the Sysmon log.

**Variant 2 status:** Confirmed.

### Variant 3 — Minimal `-e` abbreviation

**Execution result:** Successful

Command run:
`powershell.exe -e VwByAGkAdABlAC0ASABvAHMAdAAgACcAVgBhAHIAaQBhAG4AdAAgADMAIAB0AGUAcwB0ACAAbwBrACcA`
(decodes to `Write-Host 'Variant 3 test ok'`)

PowerShell output:
`Variant 3 test ok`

**Sysmon evidence:**

* **Event ID:** 1 — Process Create
* **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **CommandLine:** `"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -e VwByAGkAdABlAC0ASABvAHMAdAAgACcAVgBhAHIAaQBhAG4AdAAgADMAIAB0AGUAcwB0ACAAbwBrACcA`
* **RuleName:** `technique_id=T1059.001,technique_name=PowerShell`
* **ParentImage:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **Event time:** `2026-10-05 18:57:03 UTC`

**Observation:** The minimal single-letter `-e` abbreviation is captured identically
to `-enc` and `-EncodedCommand`. Confirms the hypothesis holds across all three
flag forms tested so far.

**Variant 3 status:** Confirmed.

### Variant 4 — Launched via `cmd.exe` as parent

**Execution result:** Successful

Command run (from a Command Prompt / cmd.exe window, not PowerShell):
`powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAVgBhAHIAaQBhAG4AdAAgADQAIAB0AGUAcwB0ACAAbwBrACcA`
(decodes to `Write-Host 'Variant 4 test ok'`)

PowerShell output:
`Variant 4 test ok`

**Sysmon evidence:**

* **Event ID:** 1 — Process Create
* **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **CommandLine:** `powershell.exe  -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAVgBhAHIAaQBhAG4AdAAgADQAIAB0AGUAcwB0ACAAbwBrACcA`
* **RuleName:** `technique_id=T1059.001,technique_name=PowerShell`
* **ParentImage:** `C:\Windows\System32\cmd.exe`
* **ParentCommandLine:** `"C:\WINDOWS\system32\cmd.exe"`
* **Event time:** `2026-10-05 19:12:17 UTC`

**Observation:** Confirms the hypothesis holds regardless of parent process.
Sysmon correctly recorded `cmd.exe` as the parent (unlike Variants 1–3, which
were launched from an already-open PowerShell session and showed PowerShell as
the parent). This matters because real attacks often chain `cmd.exe → powershell.exe`,
and this test shows detection doesn't depend on a specific launch pattern.

**Note:** an initial attempt accidentally ran from a PowerShell window instead of
cmd.exe, which would have incorrectly shown PowerShell as the parent. This was
caught by checking the `ParentImage` field and re-run correctly from genuine
Command Prompt.

**Variant 4 status:** Confirmed.

### Variant 5 — Mixed-case flag `-EnCoDedCoMmAnD`

**Execution result:** Successful

Command run:
`powershell.exe -EnCoDedCoMmAnD VwByAGkAdABlAC0ASABvAHMAdAAgACcAVgBhAHIAaQBhAG4AdAAgADUAIAB0AGUAcwB0ACAAbwBrACcA`
(decodes to `Write-Host 'Variant 5 test ok'`)

**Sysmon evidence:**

* **Event ID:** 1 — Process Create
* **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **CommandLine:** `"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -EnCoDedCoMmAnD VwByAGkAdABlAC0ASABvAHMAdAAgACcAVgBhAHIAaQBhAG4AdAAgADUAIAB0AGUAcwB0ACAAbwBrACcA`
* **RuleName:** `technique_id=T1059.001,technique_name=PowerShell`
* **ParentImage:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **Event time:** `2026-10-05 19:17:07 UTC`

**Observation:** Mixed-case flag spelling (`-EnCoDedCoMmAnD`) is captured
identically to the standard-case flag. Confirms a detection rule matching on
the flag text must be written case-insensitively, since Windows command-line
parsing itself is case-insensitive and an attacker could use any casing to
attempt evasion of a naive, case-sensitive text match.

**Variant 5 status:** Confirmed.

**Overall Case 1 status:** Testing in progress. Variants 6–7 remain to be tested.

Date: 05 Oct 2026
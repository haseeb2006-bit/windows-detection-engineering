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

**Overall Case 1 status:** Testing in progress. Variants 2–7 remain to be tested.

Date: 05 Oct 2026

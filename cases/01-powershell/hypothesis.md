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

| # | Variant | Purpose |
|---|---|---|
| 1 | `powershell.exe -EncodedCommand <base64>` | Baseline: full flag name |
| 2 | `powershell.exe -enc <base64>` | Abbreviated flag |
| 3 | `powershell.exe -e <base64>` | Minimal abbreviation |
| 4 | Variant 1, launched via `cmd.exe` as parent | Tests whether parent process affects detection |
| 5 | `powershell.exe -EnCoDedCoMmAnD <base64>` | Mixed-case flag (Windows commands are case-insensitive) |
| 6 | `powershell.exe -Command "Invoke-Expression (...)"` | Negative test: different obfuscation technique, NOT expected to be caught by this rule |
| 7 | `powershell.exe -Command "Write-Host Hello"` | Benign baseline: must NOT be flagged |

All variants use harmless payloads (printing text only). No real obfuscated
malicious commands are used.

**Status:** Hypothesis and variants committed before any testing.
Date: 27 Sep 2026
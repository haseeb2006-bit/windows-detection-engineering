# Windows Detection Engineering & Evaluation Lab

A controlled Windows 11 lab where I write my own detection rules, then actually
test whether they work, instead of just assuming they do.

**Status: Case 1 (PowerShell) is done. Starting Case 2 (Persistence) next.**

## What this is

I run harmless, attacker-style activity inside an isolated Windows 11 VM, look
at the telemetry it leaves behind (Sysmon, Windows auditing, PowerShell
logging), and write my own Sigma rules based on what I actually see. Then I run
those rules through Hayabusa against exported logs to find out what they catch,
what they miss, and what normal, boring activity they wrongly flag.

## How I'm approaching it

1. Write down what I expect to happen and the exact variants I'll test, and
   commit that before running anything.
2. Run it, then actually measure what got detected, what got missed, and what
   false positives showed up.
3. Figure out *why* something was missed or wrongly flagged, then tune the
   rule (a few rounds, not endlessly).
4. Freeze the rule and test it against something new I didn't use while
   tuning.
5. Write up the real numbers, including the misses and the limitations, not
   just the parts that make it look good.

## Cases

| Case | Status | What happened |
|---|---|---|
| [01 — PowerShell / command execution](cases/01-powershell/) | Done | Tested 7 variants, wrote a Sigma rule, ran it through Hayabusa: caught 5/5 malicious variants, 0 false positives on the 2 benign ones |
| 02 — Persistence (Run keys, Scheduled Tasks, Startup folder) | Not started yet | |
| 03 — LOLBin execution / ingress tool transfer | Not started yet | |
| 04 — Defense evasion / security-control tampering | Not started yet | |

## Something I found interesting

My rule for catching encoded PowerShell commands (`-EncodedCommand`, `-enc`,
`-e`) held up even when I changed the casing or launched it from a different
parent process, and it correctly ignored a totally different obfuscation
technique (`Invoke-Expression`) and plain, everyday PowerShell use. What
actually surprised me: it still fired correctly even when I typo'd a payload
by accident, and even when I accidentally launched it from the wrong parent
process during testing. Turns out that's because the rule matches on the flag
itself, not on a working payload or a specific process chain, which is exactly
what you'd want. Full breakdown in
[`cases/01-powershell/results.md`](cases/01-powershell/results.md).

## Keeping it safe

Everything happens inside an isolated VM with harmless test commands only,
no real malware, nothing aimed at anything outside the lab. I don't commit
full raw event logs or the VM itself, the only exception is a small, specific
set of evidence files per case that I've actually reviewed, kept in each
case's `evidence/` folder.

## License

MIT
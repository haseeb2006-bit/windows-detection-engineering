# Windows Detection Engineering & Evaluation Lab

A controlled Windows 11 lab for writing, testing, and honestly measuring detection rules.

**Status: work in progress. No results yet.**

## What this project is

I run harmless, adversary-like activity inside an isolated Windows 11 VM, study the telemetry it produces (Sysmon, Windows auditing, PowerShell logging), and write my own Sigma rules. I then run those rules with Hayabusa against exported event logs to see what they catch, what they miss, and what benign activity they wrongly flag.

## Method

1. Write hypotheses and test variants first, and commit them before testing.
2. Run the rule, then measure detected, missed, and false-positive results.
3. Find the root cause of each miss and false positive, then tune (up to about three rounds).
4. Freeze the rule and run a holdout test that was never used for tuning.
5. Report the results with raw counts, limitations, and negative results.

## Planned cases

1. PowerShell / command execution
2. Persistence (Run keys, scheduled tasks, startup folder)
3. LOLBin execution and ingress tool transfer
4. Defense evasion / security-control tampering

## Safety

All activity happens inside an isolated VM using harmless test behavior only. No real malware, no external targets. Raw event logs and VM images are never committed.

## License

MIT
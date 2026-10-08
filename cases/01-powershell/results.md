# Case 1: PowerShell / Command Execution — Testing My Sigma Rule

## What I was trying to find out

I'd already proven by hand (in Event Viewer) that Sysmon picks up encoded
PowerShell commands. The next question was whether a *rule* built from that
evidence would actually work when run through a real detection tool, not just
when I'm eyeballing logs myself. So I wrote a Sigma rule based on what I'd
seen across the 7 variants, and ran it through Hayabusa against the full
session log to see if it held up.

## How I ran it

hayabusa-4.1.0-win-x64.exe dfir-timeline --no-wizard -d D:\lab\exports -o case1-custom-rule-results.csv -r <custom rule folder> -C


I pointed this at 4 exported EVTX files from `lab-win11` (about 30,700 events
total), covering the whole session where I ran all 7 variants.

## What actually happened

The rule found **10 unique matching events**, and nothing else. Zero false
positives, 6 and 7 (the ones that were *supposed* to be missed) stayed silent.

| Variant | Should it fire? | Did it fire? |
|---|---|---|
| 1 — `-EncodedCommand` | Yes | Yes |
| 2 — `-enc` | Yes | Yes |
| 3 — `-e` | Yes | Yes |
| 4 — launched via `cmd.exe` | Yes | Yes |
| 5 — mixed case flag | Yes | Yes |
| 6 — `Invoke-Expression` (different technique) | No | Correctly didn't fire |
| 7 — plain command, no encoding | No | Correctly didn't fire |

## A thing I found interesting

The rule actually caught a couple of my mistakes too, in a good way. Early on
I typo'd a payload for Variant 1 (it decoded to "Write-Hoct" instead of
"Write-Host" and errored out), and I also accidentally ran Variant 4 from a
PowerShell window instead of cmd.exe the first time. Both of those showed up
in the results anyway, because the rule is watching for the `-EncodedCommand`
flag itself, not for a specific working payload or a specific parent process.
That's actually reassuring, it means the rule isn't fragile or overly tied to
exactly how I happened to type things.

## Where this rule is weak, honestly

This was tested on the same 7 variants I used to write the rule in the first
place, so I haven't really proven it generalizes. A proper test would be
running it against a variant I *didn't* think about while writing the regex,
a holdout test. I haven't done that yet. I also only have one operator (me),
one machine, and a handful of examples, so "0 false positives" here doesn't
mean much at real-world scale, just that it didn't trip over my own benign
test commands.

## What's next

Before I'd trust this rule for anything beyond this lab, I'd want to:
- Run a holdout variant I haven't planned for yet
- Test it against a day of normal, unscripted PowerShell use to check for
  false positives in realistic noise
- Maybe compare it against Hayabusa's own built-in PowerShell rules to see
  how mine stacks up

## Files

- The rule itself: `detections/sigma/encoded-powershell.yml`
- Raw CSV output isn't committed (it's derived EVTX data, excluded by
  `.gitignore`)

Date: 09 Oct 2026
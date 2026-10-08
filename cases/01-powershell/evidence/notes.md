# Case 1 Evidence Files

Real evidence backing the claims in `../hypothesis.md` and `../results.md`.

## Files

- **`case1-variant1-powershell.evtx`** — the specific Sysmon Event ID 1
  entry for Variant 1 (full `-EncodedCommand` flag), saved directly from
  Event Viewer ("Save Selected Events..."). Open with Windows Event Viewer.

- **`case1-custom-rule-results.csv`** — raw Hayabusa output from running
  the custom Sigma rule (`../../../detections/sigma/encoded-powershell.yml`)
  against the full session's exported Sysmon log. Shows the actual 10
  detections referenced in `results.md`.

## Note on scope

These are the only raw evidence files committed to this public repo. Larger,
full-session EVTX exports (tens of MB, mostly background noise) are kept
locally and excluded via `.gitignore`, only specific, directly-relevant
evidence is committed here.
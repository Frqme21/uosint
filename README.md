# Ultimate OSINT Suite

One command that fans a **username** or **email** out across ten OSINT engines,
cross-references every result by site, re-verifies it live, and reports only what
actually holds up.

It is built around one rule: **raw hits are not findings.** A "hit" from any
single scraper is just a claim. Claims get merged by registrable domain, checked
against each other, re-fetched live, and only then given a verdict.

```
ultimate-osint -u torvalds
ultimate-osint -e someone@example.com
```

---

## What it aggregates

| Source | Kind | Coverage | What it contributes | License |
|---|---|---|---|---|
| **DarkCurl** | library | 295+ modules (192 username / 111 email) | Profile metadata extraction (bios, IDs, counts) | upstream |
| **Maigret** | library | 3,187 sites | Broadest username sweep | MIT |
| **Sherlock** | native + DB | 413 sites | Fast username detection rules | MIT |
| **WhatsMyName** | native + DB | 692 sites | Community site DB with string markers | CC BY-SA 4.0 |
| **Holehe** | library | 149 modules | Email registration via forgot-password flows | MIT |
| **socialscan** | library | signup APIs | "Is this taken?" answered by the site itself | MIT |
| **EmailRep** | API | — | Email reputation / suspicious activity | API ToS |
| **Have I Been Pwned** | API | — | Breach exposure (needs API key) | API ToS |
| **Hudson Rock** | API | — | Infostealer infection intel (opt-in) | API ToS |
| **DNS** | local | — | MX / SPF / DMARC, disposable & role domains | — |

Sherlock and WhatsMyName detection logic is **reimplemented natively** against
their vendored databases so there is one code path, it works offline, and it
avoids fragile cross-venv imports. Maigret, Holehe, socialscan and DarkCurl are
used as real library imports.

---

## How a finding becomes a finding

1. **Collect** — every enabled source runs in parallel and emits *claims*
   (`EXISTS` / `NOT_EXISTS` / `UNKNOWN` / `SKIPPED`). `UNKNOWN` and `SKIPPED`
   are never findings; they only feed the stats line.
2. **Merge** — claims are grouped by registrable domain, so
   `gist.github.com` and `github.com` collapse into one site, and
   `twitter.com` folds into `x.com`.
3. **Proof check** — claims that carry their own proof skip the network:
   - a signup-API answer (socialscan),
   - a source that queries the target's own backend (holehe / EmailRep / HIBP),
   - extracted profile metadata (DarkCurl metadata, etc.).
4. **Re-verify live** — everything else is re-fetched once per site and judged
   by the best available rule: WhatsMyName string markers → Sherlock
   `errorType` rules → a strict generic check.
5. **Verdict** — assign one of four states.

### Verdicts

| Verdict | Meaning | Shown by default |
|---|---|---|
| `CONFIRMED` | Provable: signup-API / metadata proof, or multi-engine consensus with a passing live re-check, or a content-bound spec match. | ✅ |
| `LIKELY` | Single weak source, live re-check did not contradict it but could not corroborate it either. Worth a look. | ✅ |
| `REFUTED` | A live check contradicted the claim. | ❌ (`--show-unconfirmed`) |
| `UNVERIFIED` | Claimed but unconfirmable (blocked, rate-limited, no URL, conflict). | ❌ (`--show-unconfirmed`) |

Only `CONFIRMED` and `LIKELY` are reported as findings.

### Precision guards

Aggregation is easy; not lying is hard. The verification pass is deliberately
hostile to false positives:

- **Content, not status codes.** A page only counts as a match if the handle is
  actually visible in the body — a bare `200` (or `202`, or a JS shell) proves
  nothing.
- **Soft-404 detection.** Error pages served with `200` are caught by absence
  markers ("user not found", "doesn't exist", …).
- **Interstitial / redirect guard.** If a fetch is bounced to a consent, login,
  captcha, bot-wall or a different domain (`consent.youtube.com`,
  `threads.net` → `threads.com`), it is inconclusive — never a confirmation.
- **Lookup-URL guard.** A handle echoed back from a search or `?username=`
  endpoint is not a profile.
- **Consensus must be corroborated.** Two scrapers agreeing on an *inconclusive*
  page yields `LIKELY`, not `CONFIRMED`. `CONFIRMED` needs proof, a passing live
  re-check, or both.

The result is that a nonexistent handle comes back essentially empty, while real
accounts carry the metadata and cross-source agreement needed to be labeled
`CONFIRMED`.

---

## Install

Requires Python ≥ 3.10. On externally-managed distros (Arch, recent Debian) use
`--break-system-packages` or a venv.

```bash
git clone https://github.com/<you>/ultimate-osint
cd ultimate-osint
pip install --break-system-packages -e .
```

Provides two equivalent commands: `ultimate-osint` and `uosint`.

---

## Usage

```
ultimate-osint -u <username>          # username sweep
ultimate-osint -e <email>             # email sweep (auto-pivots to usernames)
ultimate-osint -uf users.txt          # batch usernames
ultimate-osint -ef emails.txt         # batch emails
ultimate-osint --list-sources         # list engines
```

### Common options

| Flag | Effect |
|---|---|
| `--fast` | Top 150 Maigret + 350 WhatsMyName sites, tighter timeout |
| `--deep` | All sites, all pivots |
| `-s darkcurl,sherlock` | Run only these sources |
| `--sites github.com,reddit` | Restrict every source to these sites |
| `--show-unconfirmed` | Also print refuted / unverified claims |
| `-v` | Verbose: full evidence per claim |
| `-o report.json` / `-o report.csv` | Export (`-f` to force a format) |
| `--no-nsfw` | Skip adult sites |
| `--no-pivot` | Email mode: don't sweep discovered usernames |
| `--hudson` | Opt in to Hudson Rock (sends the identifier to a third party) |
| `--no-emailrep` | Disable EmailRep (`EMAILREP_API_KEY` raises the quota) |
| `--hibp-key KEY` | HIBP lookup (or `HIBP_API_KEY`) |
| `--max-concurrent N` / `--timeout S` | Tune throughput |

### Email mode pivots

Email scans return far more when they pivot: any username found in a profile
(or the email local-part) is swept through the username engines automatically.
`--no-pivot` turns this off.

```bash
ultimate-osint -e jane.doe@example.com -o jane.json
```

---

## Example output

```
✔ CONFIRMED ACCOUNTS (2 sites)
  [✓] GitHub (darkcurl, maigret, sherlock, wmn) x4
      https://github.com/torvalds
      profile metadata extracted from live page
  [✓] Keybase (darkcurl, sherlock, wmn) x3
      https://keybase.io/torvalds
      live re-check passed (message markers)

◌ LIKELY (single source, worth a look)
  [~] YouTube (darkcurl)
      https://youtube.com/@torvalds

◆ SOURCE STATS
  [-] darkcurl:    3/5   found, 2 errors, 5.7s
  [-] sherlock:    3/4   found, 1 error,  1.9s
  ...
```

Each finding carries its sources, the URL the sources agree on, and the reason
for its verdict.

---

## Architecture

```
ultimate_osint/
├── __main__.py            # CLI: parse, config, per-target loop, export
├── core/
│   ├── result.py          # ClaimStatus, Verdict, UnifiedResult, ScanReport
│   ├── normalize.py       # site_key / registrable-domain + --sites matching
│   ├── orchestrator.py    # source registry, pivot discovery, run_scan
│   ├── confirm.py         # cross-reference + live verification (the verdicts)
│   └── report.py          # console + JSON/CSV rendering
├── integrations/
│   ├── darkcurl_src.py    # DarkCurl (thread-bridged; it owns its event loop)
│   ├── maigret_src.py     # Maigret ranked-sites sweep
│   ├── sherlock_src.py    # native Sherlock engine + vendored DB
│   ├── wmn_src.py         # native WhatsMyName engine + vendored DB
│   ├── holehe_src.py      # Holehe module discovery
│   ├── socialscan_src.py  # socialscan platform checks
│   ├── pagecheck.py       # shared spec engine + all decision functions
│   └── intel_src.py       # Hudson Rock / EmailRep / HIBP / DNS
└── data/                  # vendored wmn-data.json + sherlock-data.json
```

The decision functions in `pagecheck.py` (`decide_wmn`, `decide_sherlock`,
`decide_generic`, `is_interstitial`, `looks_like_search`) are pure
`(status, text, spec) → verdict` functions, so the whole logic is unit-testable
offline.

---

## Tests

```bash
pytest
```

~80 tests, all offline (network is faked) — covering site normalization, every
detection decision, the interstitial / lookup guards, the full verdict matrix,
pivot discovery, and JSON/CSV export.

---

## Privacy & ethics

- Running a scan makes the target's identifier visible to many third parties.
  Email sources may hit "forgot password" endpoints — `--allow-loud` enables
  DarkCurl's loudest modules and is off by default.
- Hudson Rock is opt-in because it sends the identifier to a public API.
- **Use only on identifiers you are authorized to investigate.** This is a
  research/recon tool, not a warrant.

## License

This project is licensed under **Creative Commons Attribution-NonCommercial
4.0 International (CC BY-NC 4.0)** — see [LICENSE](LICENSE). You may share and
adapt it for non-commercial purposes with attribution; **commercial use is not
permitted**.

> ⚠️ CC licenses are written for creative works, not software: they don't
> address patents or ship the warranty/disclaimer language a software license
> does. If you need a software-native license, MIT / Apache-2.0 / GPL are the
> usual choices instead.

### Third-party notices

This project stands on other people's work. Their terms still apply to their
parts, and those parts are **not** relicensed by the CC BY-NC 4.0 above:

| Component | Where | License |
| --- | --- | --- |
| [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) site DB | vendored `ultimate_osint/data/wmn-data.json` | **CC BY-SA 4.0** |
| [Sherlock](https://github.com/sherlock-project/sherlock) site DB | vendored `ultimate_osint/data/sherlock-data.json` | MIT |
| Sherlock detection logic / WAF fingerprints | adapted in `integrations/pagecheck.py` | MIT (notice retained) |
| [DarkCurl](https://github.com/) | runtime dependency | upstream terms |
| [Maigret](https://github.com/soxoj/maigret), [Holehe](https://github.com/megadose/holehe), [socialscan](https://github.com/iojw/socialscan) | runtime dependencies | MIT |

Because the vendored WhatsMyName data is **CC BY-SA 4.0**, that file — and any
distribution that bundles it — must keep the CC BY-SA 4.0 terms and
attribution. Redistribute it accordingly.

The rest of this tool is provided as-is for authorized security research.

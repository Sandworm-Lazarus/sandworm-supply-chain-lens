# Sandworm Supply Chain Lens

![Sandworm project cover](docs/cover.svg)

Normalize SBOMs, review package/version changes, and compare Grype vulnerability evidence. Built by Sandworm-Lazarus on the documented Syft/Grype interfaces; the engines remain Anchore projects. Original code is MIT. Both upstream engines are Apache-2.0.

เครื่องมือดูส่วนประกอบซอฟต์แวร์และเปรียบเทียบก่อน–หลังอัปเดตของเรา รองรับ Syft JSON, CycloneDX และ SPDX พร้อมผล Grype แยกชัดเจนระหว่าง “ยังไม่สแกน” กับ “สแกนแล้วไม่พบรายการ” กรณีระบุตัวแพ็กเกจซ้ำกำกวมจะหยุดแทนการเดา

## Quick start — import reports without engines

Python 3.11+ on Linux. Runtime has no Python third-party dependencies.

```sh
python -m sandworm_lens import-report examples/sbom.cdx.json --grype-report examples/grype-report.json --out report.json
python -m sandworm_lens import-report examples/sbom.cdx.json --out sbom-only.json
python -m sandworm_lens diff report.json sbom-only.json --out comparison.json
python scripts/validate.py
```

Open `web/index.html` for the Sandworm-themed report viewer; load the synthetic example or import a generated report. If local-file restrictions apply, serve it with `python -m http.server 8080 --directory web`. The viewer does not execute scans or upload reports. All example vulnerabilities are invented.

## Actual local Syft and Grype integration

`upstream-lock.json` pins **Syft 1.57.1** and **Grype 0.121.3**, with official Linux/amd64 release asset SHA-256 checks. No binaries or vulnerability DBs are committed.

```sh
python scripts/install_upstream.py
mkdir -p .runtime/grype-db
# Explicitly fetch the upstream Grype vulnerability database, without scanning a project:
GRYPE_DB_CACHE_DIR="$PWD/.runtime/grype-db" .tools/grype db update
# Generate SBOM and scan against that local DB; updates are disabled during scanning:
python -m sandworm_lens scan ./YOUR_PROJECT --syft "$PWD/.tools/syft" --grype "$PWD/.tools/grype" --db-cache .runtime/grype-db --out report.json
```

Omit `--db-cache` to run only Syft: the report explicitly says `vulnerability_scan: not-run`; it never claims a completed clean scan. Syft receives a `dir:` local source, not a registry URL or Docker socket. The adapter supplies an empty config file to avoid ambient config discovery, a minimal credential-free environment, and disables update checks. Grype auto-update is disabled. Missing/stale/unusable offline DBs fail according to the engine's validation.

## Identity, ambiguity and diffs

Package identity uses a package URL with the version removed, qualifier keys sorted and their UTF-8 percent-encoded values decoded (literal `+` remains `+`). Duplicate/invalid qualifier keys are rejected. The base and subpath otherwise remain exact strings; this is not a full PURL canonicalization library. Qualifiers/subpath remain part of identity; packages without purl fall back to type+name. Identical duplicates collapse. Conflicting identities, including multiple versions of the same identity, are rejected so a version change is not guessed. This conservative v0.1 limitation means some legitimate multi-version SBOMs need preprocessing or a future location-aware identity policy.

Grype findings must correspond to the same package identity/version in the supplied SBOM. Conflicting duplicate vulnerability records fail. Package diffs show added, removed and version-changed entries. Vulnerability diffs show new/resolved only when *both* reports contain completed Grype results; otherwise their status is incomplete and no resolution is inferred. Database version/build date are reported when present in upstream JSON, never invented.

รายงานอาจมีชื่อแพ็กเกจและรุ่นภายในองค์กร จึงควรตรวจทานก่อนแชร์ SHA-256 ยืนยันว่าใช้ข้อมูลชุดเดิม ไม่ใช่ใบรับรองความปลอดภัย และรายการที่หายอาจเกิดจากฐานข้อมูลหรือขอบเขตการสแกนเปลี่ยน

## Validation and operations

`python scripts/validate.py` writes the exact source/fixture hash manifest in `reports/validation.json`. `python scripts/smoke.py --db-cache .runtime/grype-db` runs the pinned real Syft and Grype against the synthetic local project. No registry is queried with project contents. `reports/live-smoke.json` records observed results and DB provenance; the fixture has no expected real vulnerability.

Deploy the CLI in a disposable Linux worker/container with read-only source and bounded resources. This repository does not provision an always-on worker or hosted service. Use your own scheduler/CI. See [SECURITY.md](SECURITY.md), [development notes](docs/DEVELOPMENT.md), and [upstream notices](THIRD_PARTY_NOTICES.md).

Outputs must use a new file name. Creation is atomic and exclusive: existing reports, scanned files and symlinks are never overwritten. JSON file inputs must be regular files; FIFOs, devices and symlinks are rejected before reading.

## Sandworm report workspace

The original Sandworm navy/coral theme is included in `web/`. Read [the viewer guide](docs/WEB_VIEWER.md) for local serving, normalized JSON import and export, and [verification scope](docs/BROWSER_QA.md) for the browser QA limit. Run `node --test tests/web.test.cjs` alongside the engine checks above. No worker or scheduler is deployed by opening this static viewer.

The cloud development and upstream smoke checks are reproducible from this repository. A continuously running service needs your own worker/server, authentication, job limits and operational setup. Public source contains synthetic fixtures; local dependencies, secrets, scan targets, model caches and databases are excluded.

Original Sandworm code is MIT-licensed. Upstream engines retain their respective licenses and credit; embedded fonts use OFL with notices in `web/fonts/`.

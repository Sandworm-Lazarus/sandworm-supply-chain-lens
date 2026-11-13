# Sandworm report viewer / หน้าอ่านรายงาน

The `web/` folder is a static, browser-local report viewer. Actual engines run through the CLI documented in README; this page never executes scanners, model calls or document converters.

```sh
python -m http.server 8787 --bind 127.0.0.1 --directory web
```

Open `http://127.0.0.1:8787`. Load the bundled synthetic report or import the normalized `report.json` produced by this project's CLI. Raw upstream reports need their documented importer first. The fixture badge identifies demo data even where an actual upstream engine generated that synthetic example. Live engine evidence is recorded separately under `reports/`.

รายงานนำเข้าต้องเป็น UTF-8 JSON ไม่มี BOM ขนาดไม่เกิน 2 MiB และเป็น envelope ของโปรเจกต์นี้ (`schema_version: 1` (legacy display) หรือ `2` (versioned occurrences), `project`, `mode`, `summary`) ไม่รับ key ซ้ำ ตัวเลขเกินขอบเขต หรือโครงสร้างลึกเกิน 40 ชั้น

The viewer shows at most 300 matching finding cards at once; full validated report JSON remains available. Imported text is rendered using textContent, never HTML. It does not upload or store reports. Export preserves the imported report fields and requires the review checkbox; it is not another redaction layer. A hash detects changed text, not trustworthiness or authenticity.

The cover SVG is an original illustration, not a browser screenshot. Embedded fonts are Chakra Petch, Anuphan and JetBrains Mono under OFL; license texts are in `web/fonts/`. Theme graphics and layout are original Sandworm work.

```sh
node --test tests/web.test.cjs
```

Schema 2 validates occurrence/finding structure, identifier syntax, source-reference uniqueness, links and counts before displaying package, vulnerability and comparison cards. This browser check does not recompute Python identity hashes, authenticate the producer or replace engine baseline validation. The card limit remains 10,000 combined rows; only the first 300 matches are rendered. Schema-1 files are display-only for migration purposes; engine comparisons require regenerated schema-2 inputs. A native reference represents an upstream record, not necessarily one filesystem installation.

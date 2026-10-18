# The Quiet Callback

A Week 10 CYB240 network investigation lab. Students observe synthetic telemetry, compare explanations, document uncertainty, and choose a proportionate response. The application provides **no correct/incorrect feedback or automated grading**.

## Run locally

Open `index.html` in a current desktop browser. All assets are relative, and the app uses ordinary deferred scripts rather than modules, so no build step is needed. Browser saving under `file://` varies; use a local HTTP server for consistent storage. With Node.js installed:

```sh
node tests/serve.cjs
```

Open `http://127.0.0.1:4173`. Stop the server with Ctrl+C. The app itself needs no Node.js or dependencies. Browser JavaScript must be enabled.

## Deploy to GitHub Pages

1. Extract the ZIP. Create a GitHub repository (for example, `quiet-callback`).
2. Upload the **contents** of the extracted `quiet-callback` folder to the repository root. `index.html`, `styles.css`, `scenario.js`, and `app.js` must be together at the top level. Include `.nojekyll` if your upload method supports hidden files; plain HTML also works without it.
3. Commit the files to `main`.
4. Open repository **Settings → Pages**. Under **Build and deployment**, select **Deploy from a branch**, choose **main** and **/(root)**, then save.
5. Wait for the Pages deployment to finish. Open the URL shown in Settings, normally `https://YOUR-ACCOUNT.github.io/quiet-callback/`.
6. Confirm the brief opens, enter a test student ID, run the clock, and download a draft export. Put the deployed link in Moodle.

Do not upload the ZIP itself as the website. No custom domain, package install, server backend, API key, database, or GitHub Actions workflow is required. The app works at a repository subpath. Repository Pages availability can depend on account and repository visibility; see [GitHub’s Pages publishing source instructions](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

## Student workflow

1. Read the brief and enter `lastname + first initial + year`, lowercase ASCII (example: `chenowetht2026`). Omit punctuation, spaces, and diacritics. Format validation checks letters followed by four digits; it cannot verify a real name or enrollment.
2. Begin the 12-minute simulated shift. Select 1×, 2×, or 4× speed. Pause freezes simulated time and keeps every released record. Switching away from the browser tab pauses automatically to avoid missing the shift. Reload resumes the saved case in a paused state.
3. Inspect Live, DNS, NetFlow, Firewall, IDS, TLS, and Assets. Filters combine; a sensor host filter also matches records observed by that sensor. The time range is inclusive and uses simulated UTC. Inventory uses only the host filter.
4. Click evidence IDs to cite them in a notebook draft. Save observations separately from interpretations, record confidence, and select evidence types. Saved observations can be edited or deleted.
5. Respond to checkpoints at 02:00, 05:00, 08:00, and 12:00 elapsed. Prompts unlock; they do not certify reasoning.
6. Starting at 04:00, request additional context with a reason. Each source can be requested once. Responses arrive after 20 simulated seconds and appear in the request panel, not the event table. Requests close after 11:40; an unmet request can be documented as a limitation. Endpoint triage is a documented collection gap, not fabricated endpoint telemetry.
7. Use the interval calculator on a comparable set of flows. It sorts timestamps and reports intervals, mean, median, range, population standard deviation, coefficient of variation, and duplicate count. It **never labels traffic C2**. Duplicate timestamps are retained as zero-second intervals. Do not mix timestamps and elapsed seconds, cross midnight, or silently mix unrelated series.
8. Choose one of the three decisions and write 300–400 words across all seven assessment sections. The word count splits on whitespace, excludes headings, and is advisory.
9. Export JSON and HTML. Drafts are permitted. HTML is a standalone, printable report with the released evidence appendix. JSON contains structured writing, context, calculator output, and released event objects. No future telemetry or unreleased request responses are exported.

Restart rewinds the same scenario while preserving writing and requests. Previously recorded notes may reference evidence not yet re-released. New student / clear removes the browser’s saved case after confirmation. Export before clearing. There is no import, server submission, or account synchronization; submit downloaded files to Moodle.

## Persistence and privacy

One case is saved per browser/origin using localStorage key `quiet-callback-v1`. The student ID identifies reports; it does not seed answers. Draft text saves while typing. If browser storage fails, the UI tells the student to export. Use downloaded reports as the durable record. Shared-computer users should export, submit, then use New student / clear. No analytics, remote fonts, third-party libraries, or outbound application requests are present. A Content Security Policy blocks application connections. GitHub Pages still serves the initial static files through normal HTTPS.

## Instructor notes — scenario design (spoilers)

**Keep this section and the source code out of the student instructions if you want discovery.** A static site cannot conceal its scenario: source and future events are inspectable. This is a reasoning assessment, not an anti-cheating system or a hidden-flag challenge. For a student-facing repository, you may omit this README, the tests, and instructor rubric notes from the hosted files and distribute them privately.

The fictional observation window is **2026-10-19 10:14:00–10:26:00 UTC**. All IP addresses are RFC 5737 documentation addresses externally and private addresses internally; domains are under `.example`. Nothing is resolved or contacted. Events are modeled synthetic session records, not a packet capture; timestamps represent session starts, and byte counts are total bidirectional session bytes.

| Asset | Intended comparison |
| --- | --- |
| FIN-WS34 | Sessions recur at approximately 30 seconds (27–33 second intervals), about 3.8–4.1 KB per session, with DNS and TLS metadata. A behavioral alert appears after five minutes. DNS changes at 07:30 elapsed from 203.0.113.84 to 203.0.113.117; the host, domain, TLS fingerprint, and timing pattern persist. |
| HR-WS18 | Legitimate endpoint-management polling every 60 seconds; the service register corroborates the configuration. |
| BACKUP-02 | Large cloud transfers during an approved backup window; documented ticket and asset context provide a volume red herring. |
| ENG-WS22 | Irregular interactive browsing provides an additional baseline. |
| DNS-01 / FW-01 / IDS-01 | Resolver, firewall, and passive sensor provide independent metadata; none proves process ownership or decrypts payloads. |

A well-supported escalation of FIN-WS34 for endpoint investigation is defensible. It is not a claim of confirmed compromise. Monitoring can earn substantial credit if the student documents a bounded monitoring plan, limitations, and escalation criteria. Closing the case requires a credible evidence-based reconciliation of the unexplained activity. Grade reasoning and source use, not simply selection of a preferred button. The delayed IDS alert is a corroborating signal, not an answer key; firewall ALLOW is policy enforcement, and encryption is not proof of maliciousness.

The request responses supply service records, seven-day local DNS context, owner recollection, and endpoint collection limitations. Encourage comparison of source reliability and alternative hypotheses such as an undocumented legitimate agent. Students should propose process attribution, software inventory, persistence checks, and relevant endpoint artifacts rather than claiming a payload was observed.

Use `MOODLE_ASSIGNMENT.md` for copy-ready student directions and a 60-point rubric. Suggested class time is 45–60 minutes, including analysis and writing. The fastest playback takes three minutes, but pausing is encouraged.

## Files and maintenance

- `index.html`: case brief and accessible form structure.
- `styles.css`: responsive console and print styling; no external assets.
- `scenario.js`: deterministic assets, timeline, checkpoints, responses, and statistics.
- `app.js`: playback, filters, writing, storage, and safe HTML/JSON export.
- `MOODLE_ASSIGNMENT.md`: assignment and rubric.
- `tests/`: optional dependency-free Node.js server and validation tools.
- `VALIDATION.md`: checks performed on this build.

To change the scenario, edit `scenario.js`; update the UI duration, documentation, and tests if changing the 720-second window. Bump the app version/storage key for incompatible schema changes. The application does not rely on minification or generated bundles.

## Validate

```sh
node tests/scenario.test.cjs
node tests/browser.test.cjs
```

Browser tests require a recent Chromium-based browser. On Windows the script discovers Chrome/Edge in standard paths; elsewhere set `CHROME_PATH` to the executable. It starts a loopback server and a temporary headless browser profile, exercises the UI through the browser’s debugging protocol, and saves a console screenshot and two exports in `test-output/` (ignored by Git). Node.js 22+ is needed for its built-in WebSocket. There are no npm dependencies.

In restricted test environments, `CAPTURE_EXPORTS=1` intercepts the download handoff and reads the exact generated browser Blobs, verifying filenames and report contents without requiring browser download permission. `CHROME_TEST_COMPAT=1` enables compatibility flags including `--no-sandbox` for the temporary headless test browser; use it only for this trusted local test fixture. Neither setting changes the application. See `VALIDATION.md` for the mode used on this build.

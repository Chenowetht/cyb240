# Local validation

Validated October 18, 2026, using Node.js and a headless Google Chrome browser on Windows. No application dependencies were installed.

## Passed

- JavaScript syntax checks for `app.js` and `scenario.js`.
- Scenario assertions: seven assets; 171 uniquely identified, ordered events within the observation window; FIN-WS34 low-volume 27–33 second intervals; destination change with stable domain; exact HR 60-second intervals; large backup sessions; delayed IDS and DNS evidence; statistics edge cases.
- Actual browser loading through a loopback HTTP server and direct `file://` launch.
- Invalid and valid student ID formats; case brief to investigation transition.
- Pause/resume and 1×, 2×, and 4× playback using the real timer with an injected test clock offset.
- Checkpoint and request availability before and after their release times, delayed request response, and completion state at 12:00. Time snapshots were seeded through localStorage for stage tests; the speed controls were exercised directly.
- All seven tabs, combined host/destination/type/time filters, empty views, and filter reset.
- Visible-flow timestamp capture, interval mean, invalid timestamp rejection, and mixed-format rejection.
- Evidence citations, notebook creation/editing, escaped user text, checkpoint persistence, reload recovery in paused state, and retained notes on restart.
- Seven-section assessment word counting and administrative completeness checks.
- Draft and complete JSON and HTML export Blob generation, expected filenames, structured content, released-only evidence, HTML escaping, and evidence appendix. Complete test export contained all 171 events and a 315-word placeholder assessment used only to test counting.
- New-student clear and restart behavior.
- No application JavaScript exceptions and no external HTTP(S) application requests during the exercised workflow.
- Desktop (1440 × 1000) and mobile (390 × 844) screenshots visually inspected. No page-wide horizontal overflow; evidence tables and tabs scroll within their containers.

## Environment limitation

This managed environment allowed export generation but canceled Chromium's native download writes, including attempts in a temporary download directory. Final export checks therefore used `CAPTURE_EXPORTS=1` to capture the exact JSON and HTML Blobs at the download-link handoff and write them via the test runner. **Native browser download completion was not verified here.** Test outputs are deliberately excluded from the distribution ZIP. The normal application uses standard Blob URLs and `<a download>` links; verify one download in the browser used by students before class.

Chrome required `CHROME_TEST_COMPAT=1` in this restricted runtime. Normal tests do not enable those compatibility flags. No GitHub deployment was performed; the ZIP is prepared for upload. Screen-reader behavior and Safari/Firefox were not tested.

## Commands used

```powershell
node --check app.js
node --check scenario.js
node tests/scenario.test.cjs
$env:CAPTURE_EXPORTS='1'
$env:CHROME_TEST_COMPAT='1'
node tests/browser.test.cjs
```

The exported test reports use filler text and are not example student answers or grading guidance. Instructor reasoning guidance is in README.md; the 60-point rubric is in MOODLE_ASSIGNMENT.md.

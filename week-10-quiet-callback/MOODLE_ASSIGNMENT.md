# Week 10 CYB240: The Quiet Callback

## Student assignment — paste into Moodle

**Points:** 60  
**Submission:** Two files: the app’s HTML report and JSON investigation export  
**Suggested time:** 45–60 minutes  
**Lab link:** [Insert your deployed GitHub Pages URL]  
**Due date:** [Set in Moodle]

### Your role

You are monitoring a simulated enterprise network. Unusual outbound communication has been reported, but no system has been confirmed compromised. Several assets generate legitimate automated traffic. Determine whether the observed behavior warrants additional monitoring, endpoint investigation, or closure as expected activity.

This lab generates synthetic metadata in your browser. Do not probe, resolve, contact, or investigate the displayed addresses on the real Internet. All the evidence you need for this assignment is in the lab. You are assessing uncertainty, not finding a hidden flag.

### Learning objectives

- Correlate DNS, NetFlow, firewall, IDS, TLS, and asset context using stable evidence IDs.
- Distinguish direct observations from interpretations and test alternative explanations.
- Compare timing and traffic volume without treating periodicity, encryption, or volume alone as proof.
- Identify collection gaps and recommend proportionate investigative next steps.
- Produce a concise, evidence-supported analyst assessment.

### Procedure

1. Read the opening brief. Enter your student ID as lowercase **lastname + first initial + year**, such as `chenowetht2026`. Omit spaces, punctuation, and diacritics.
2. Observe the entire 12-minute simulated shift. Use pause/resume and 1×/2×/4× speed as needed. The simulation pauses when you leave the tab. Released evidence remains available.
3. Inspect the evidence tabs and use host, destination, evidence-type, and time filters. Compare activity from multiple hosts. Asset inventory is static and uses only the host filter.
4. Save **at least four notebook observations**. Each must distinguish observation from interpretation, state confidence, identify evidence types, and cite relevant evidence IDs. Include at least one plausible alternative explanation and one comparison with legitimate activity across your notes.
5. Answer all four staged checkpoints as they become available. Preserve the development of your reasoning; do not rewrite every early hypothesis as though you knew the later evidence.
6. Calculate intervals for at least one comparable NetFlow series with at least six timestamps. Record the input series, key results, and limitations in your notebook. The calculator supplies statistics, not a verdict.
7. Request at least one additional evidence source after 04:00 elapsed. Explain the question it tests. Wait for the response and discuss how it changes or fails to change your confidence. Requests need 20 simulated seconds and must be made by 11:40. Treat unavailable endpoint collection as a limitation.
8. Select one final decision: **Continue Monitoring**, **Escalate for Endpoint Investigation**, or **Close as Expected Activity**.
9. Write **300–400 words total**, using every assessment section below. Cite evidence IDs in the prose. The headings do not count toward the word limit.
10. Run the completeness check and review your report. The check flags missing fields; it does not grade evidence quality and does not enforce every rubric requirement. Export both HTML and JSON and upload them to Moodle. Open the HTML export to confirm it contains your work and correct ID.

### Required assessment sections

| Section | What to address |
| --- | --- |
| Scope | Hosts, observation window, and available evidence sources. |
| Observations | Specific, measurable facts supported by evidence IDs. |
| Correlation | Connections across sources and comparisons among hosts; changes over time. |
| Assessment | Your interpretation, competing explanations, and chosen decision. |
| Confidence | Your confidence level and why the evidence supports that level. |
| Limitations | What network metadata cannot establish and what collection is missing. |
| Recommended Next Steps | Concrete, prioritized actions; include collection targets or monitoring criteria. |

No correct/incorrect feedback appears during the investigation. Your grade reflects the quality of your analysis and communication. An alert, an allowed connection, or a timing pattern is not by itself a compromise verdict.

### Submission checklist

- Correct student ID and full simulated shift observed.
- Four or more saved observations with evidence IDs and confidence.
- All checkpoints answered, interval calculation documented, and additional evidence considered.
- One final decision and all seven assessment sections, 300–400 words total.
- Both `quiet-callback-YOURID-complete.html` and `.json` uploaded. If the export is marked draft, resolve missing items or explain the limitation to your instructor.

Your browser stores one local case. Export before clearing the case, changing browsers, or leaving a shared computer. Exports are downloads, not automatic Moodle submissions. There is no import function; do not rely on the browser as your only copy.

## 60-point analytic rubric

Use the point ranges below within each criterion. Award credit for accurate reasoning even when a student's final choice differs from the instructor's preferred action.

| Criterion | Strong | Developing | Limited / missing | Maximum |
| --- | --- | --- | --- | ---: |
| Evidence collection and citation | **10–12:** Four or more precise notes distinguish observation and interpretation, use identifiable IDs, and cover multiple hosts and sources. | **6–9:** Mostly accurate notes but incomplete source diversity, citation precision, or distinction between fact and interpretation. | **0–5:** Sparse notes, unsupported claims, missing citations, or major factual errors. | 12 |
| Cross-source correlation and alternatives | **10–12:** Connects DNS, flows, TLS, policy/alerts, and asset context as applicable; explains temporal change and tests plausible alternatives against legitimate activity. | **6–9:** Some useful correlations and comparisons, with gaps or underdeveloped alternatives. | **0–5:** Treats a single indicator as conclusive or fails to compare explanations and hosts. | 12 |
| Timing analysis | **7–8:** Uses at least six comparable timestamps, interprets statistics accurately, documents the series, and explains sampling/mixing limits without declaring a timing-based verdict. | **4–6:** Appropriate calculation but weak interpretation, documentation, or limitations. | **0–3:** Missing calculation, unsuitable mixed series, or major interpretation errors. | 8 |
| Investigative process and additional evidence | **7–8:** All checkpoints show evolving reasoning; a justified request and its response meaningfully inform the analysis. | **4–6:** Most checkpoints and a request present, but hypothesis testing or response integration is weak. | **0–3:** Missing checkpoints or request, or little evidence of investigative reasoning. | 8 |
| Decision, confidence, limitations, and next steps | **10–12:** Decision is proportional to evidence; confidence is calibrated; limits are explicit; next steps are specific and actionable. | **6–9:** Decision broadly supported but confidence, uncertainty, or actions lack detail. | **0–5:** Unsupported certainty, inappropriate action, or missing confidence/limitations/next steps. | 12 |
| Analyst communication and submission | **7–8:** Clear 300–400 word assessment using all seven sections; correct ID; readable HTML and matching JSON submitted. | **4–6:** Generally understandable but some structure, length, clarity, or submission issues. | **0–3:** Substantially incomplete, unclear, or missing report/export. | 8 |
| **Total** | | | | **60** |

## Instructor setup — do not paste into the student brief

Deploy the app, replace the lab URL and due-date placeholders, and configure a Moodle file-submission assignment accepting `.html` and `.json`, maximum two files and at least 5 MB per file. If your Moodle site blocks HTML attachments, allow ZIP submissions containing the two exports and adjust the directions. Students can view HTML locally; Moodle may force download for security.

Use the rubric rows as six Moodle advanced-grading criteria, with maximums 12, 12, 8, 8, 12, and 8. The ranges support analytic judgment; create point levels that suit your Moodle rubric configuration. The app's completion check requires only one note and does not check the six-timestamp requirement or reasoning quality; apply the rubric manually.

Read the scenario notes in README.md before teaching. FIN-WS34 is designed to merit further endpoint investigation without proving compromise; HR management and the approved backup are comparison cases. Do not award or remove points solely for choosing a particular decision. Never infer process execution, payload content, or confirmed compromise from this synthetic network metadata alone.

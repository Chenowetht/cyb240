/* ============================================================================
   case.js  —  PRACTICE / DEMO CASE  (Cochise College Network Security Team)
   A tiny 3-step warm-up to show the class how the midterm works before they
   start. Same engine and same per-examiner-tag scheme as the real case, but a
   throwaway secret and its own case id, so it reveals nothing about the midterm.

   It previews the three mechanics students most often stumble on:
     1. where tags live and their exact CCNST{...} format        (intake)
     2. a tempting-but-wrong line that nudges instead of scoring (login decoy)
     3. a tag that isn't in plain text and must be decoded        (Base32)
   ============================================================================ */
(function (root) {
  "use strict";
  var H = (typeof require === "function") ? require("./shared_hash.js") : root.CCHash;

  // Throwaway practice secret — intentionally public; NOT the midterm secret.
  var CONFIG = {
    SECRET: "demo-practice-key-public-ok",
    FLAG_PREFIX: "CCNST",
    CASE_ID: "CCNST-DEMO-00",
    COURSE: "Network Forensics",
    TEAM: "Cochise College Network Security Team",
    INCIDENT_DATE: "2026-09-26"
  };

  function norm(id) { return String(id || "").trim().toLowerCase().replace(/\s+/g, ""); }

  function flagFor(studentId, stepId) {
    var h = H.hmacSha256Hex(CONFIG.SECRET, norm(studentId) + "|" + stepId);
    return CONFIG.FLAG_PREFIX + "{" + stepId + "_" + h.slice(0, 12) + "}";
  }

  // RFC 4648 Base32 (used to hide the decode-step tag, exactly like the real tunnel)
  function base32(str) {
    var A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bytes = new TextEncoder().encode(str);
    var bits = 0, val = 0, out = "";
    for (var i = 0; i < bytes.length; i++) {
      val = (val << 8) | bytes[i]; bits += 8;
      while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += A[(val << (5 - bits)) & 31];
    return out;
  }

  function fingerprint() {
    return H.sha256Hex(CONFIG.SECRET + "|" + STEPS.map(function (s) { return s.id; }).join(",")).slice(0, 8);
  }

  var STEPS = [
    { id:"intake", week:1, points:1, skill:"Evidence handling & scope",
      title:"Open the practice case",
      file:"/case/brief.txt",
      hint:"Every case starts with scope, not packets. Read the brief in /case/brief.txt and record the case evidence tag exactly as written — that's your first flag, and it confirms you're on the right case. Notice the CCNST{...} format; that's what every tag looks like.",
      next:"Now look at who logged in." },

    { id:"login", week:3, points:1, skill:"Authentication logs",
      title:"Find the after-hours login",
      file:"/logs/auth.log",
      hint:"Open /logs/auth.log. One admin login happened during scheduled lab hours — that's expected. Another succeeded late at night, when no class was on the calendar. The flag is on that off-hours success. The daytime line is a decoy; submitting it just nudges you.",
      next:"One more: the analyst hid a note so it wouldn't sit in plain text." },

    { id:"decode", week:7, points:1, skill:"Encoding & decoding",
      title:"Decode the analyst's note",
      file:"/notes/scratch.txt",
      hint:"The tag isn't always sitting in the clear. In /notes/scratch.txt the analyst left a Base32 string (RFC 4648). Decode it — paste it into CyberChef, or run `echo <string> | base32 -d` — and the decoded text IS your flag. The real midterm hides a tag in DNS the same way.",
      next:"That's the whole loop. Export your submission to finish." }
  ];

  var DECOYS = {
    login: { "CCNST{login_daytimeok0}":
      "That's the scheduled daytime admin session — expected lab activity, not the incident. Find the successful login at an hour with no class on the calendar." }
  };

  var D = CONFIG.INCIDENT_DATE;
  function F(id, step) { return flagFor(id, step); }

  var EVIDENCE = {
    "/case/brief.txt": function (id) {
      return [
"PRACTICE CASE BRIEF  —  WARM-UP (not graded)",
"============================================================",
"Case ID        : " + CONFIG.CASE_ID,
"Opened         : " + D + " 09:00 MST",
"Assigned team  : " + CONFIG.TEAM,
"Reporting lead : analyst on duty (you)",
"",
"SUMMARY",
"  A short demo scenario to learn the interface before the midterm.",
"  During a lab exercise, training-room workstation TRAIN-WS-02",
"  (10.20.9.14) did two things worth a look after hours. Work the",
"  three steps in order; each hint points to the next file.",
"",
"HOW TO ANSWER",
"  Find the CCNST{...} tag the evidence leads you to and paste it",
"  into the submit box at the bottom. Correct tags get stamped;",
"  tempting-but-wrong lines just nudge you.",
"",
"CASE EVIDENCE TAG (record this as your first flag):",
"  " + F(id, "intake"),
"============================================================"
      ].join("\n");
    },

    "/logs/auth.log": function (id) {
      return [
"# /logs/auth.log  —  TRAIN-WS-02 practice server      (times in MST)",
"# scheduled lab block today: 12:00–14:00",
"-------------------------------------------------------------------",
D + " 13:02:11  sshd[1122]: Accepted password for labadmin from 10.20.9.10 port 51110   session=scheduled-lab   tag=" + "CCNST{login_daytimeok0}",
D + " 13:41:05  sshd[1140]: Accepted publickey   for student01 from 10.20.9.21 port 51822   session=scheduled-lab",
D + " 14:05:22  sshd[1140]: Disconnected          from 10.20.9.21 port 51822",
D + " 23:47:30  sshd[2203]: Failed password       for labadmin from 10.20.9.14 port 49771",
D + " 23:47:49  sshd[2203]: Failed password       for labadmin from 10.20.9.14 port 49773",
D + " 23:48:02  sshd[2203]: Accepted password     for labadmin from 10.20.9.14 port 49775   session=AFTER-HOURS     tag=" + F(id, "login"),
"-------------------------------------------------------------------",
"# note: 23:48 is well outside the scheduled lab block."
      ].join("\n");
    },

    "/notes/scratch.txt": function (id) {
      return [
"analyst scratch pad — practice case",
"===================================",
"Reminder to self, Base32'd (RFC 4648) so it isn't sitting in the clear:",
"",
"    " + base32(F(id, "decode")),
"",
"(decode that string and it's the final practice tag.)",
"Tip: CyberChef 'From Base32', or:   echo '<string>' | base32 -d"
      ].join("\n");
    }
  };

  var TREE = [
    { dir:"/case",  files:["/case/brief.txt"] },
    { dir:"/logs",  files:["/logs/auth.log"] },
    { dir:"/notes", files:["/notes/scratch.txt"] }
  ];

  var API = {
    CONFIG: CONFIG, STEPS: STEPS, DECOYS: DECOYS, EVIDENCE: EVIDENCE, TREE: TREE,
    norm: norm, flagFor: flagFor, fingerprint: fingerprint, base32: base32,
    renderFile: function (path, id) { return EVIDENCE[path] ? EVIDENCE[path](id) : "(file not found)"; },
    allFlags: function (id) { var o = {}; STEPS.forEach(function (s) { o[s.id] = flagFor(id, s.id); }); return o; }
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  root.CASE = API;
})(typeof self !== "undefined" ? self : this);

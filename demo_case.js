/* ============================================================================
   case.js  —  PRACTICE / DEMO CASE  (Cochise College Network Security Team)
   A tiny 3-step warm-up to show the class how the midterm works before they
   start. Same engine and same answer-gated model as the real case, but a
   throwaway secret and its own case id, so it reveals nothing about the midterm.

   It previews the three mechanics students most often stumble on:
     1. submitting a finding (not copying a tag)      (intake: the case id)
     2. a tempting-but-wrong line that nudges you      (login: a daytime decoy)
     3. evidence that must be decoded before you can    (Base32 decode)
        read the finding
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

  /* ---- answer normalization + checking (same scheme as the real case) ---- */
  function normAns(kind, v) {
    v = String(v == null ? "" : v).trim().toLowerCase();
    switch (kind) {
      case "ip":   return v.replace(/\s+/g, "").replace(/:\d+$/, "");
      case "time": return v.split(/[^0-9]+/).filter(Boolean)
                            .map(function (x) { return x.length < 2 ? ("0" + x) : x; }).join("");
      default:     return v.replace(/\s+/g, " ").trim();
    }
  }
  function matchList(list, input) {
    for (var i = 0; i < (list || []).length; i++) {
      var k = list[i][0], val = list[i][1];
      if (normAns(k, input) === normAns(k, val) && normAns(k, input) !== "") return list[i];
    }
    return null;
  }
  function check(stepId, input) {
    var s = null;
    for (var i = 0; i < STEPS.length; i++) if (STEPS[i].id === stepId) s = STEPS[i];
    if (!s) return { status: "wrong" };
    if (matchList(s.accept, input)) return { status: "correct" };
    var d = matchList(s.decoys, input);
    if (d) return { status: "decoy", msg: d[2] };
    return { status: "wrong" };
  }

  var DECODE_TEXT = "demo-decode-ok";   // what the Base32 string decodes to

  var STEPS = [
    { id:"intake", week:1, points:1, skill:"Evidence handling & scope",
      title:"Open the practice case", guided:true, file:"/case/brief.txt",
      hint:"Every case starts with scope, not packets. Read the brief in /case/brief.txt. You don't copy a hidden tag — you submit a finding. Here the finding is the Case ID, which confirms you're on the right case.",
      prompt:"Enter the Case ID from the brief.",
      accept:[["text","CCNST-DEMO-00"]], decoys:[] },

    { id:"login", week:3, points:1, skill:"Authentication logs",
      title:"Find the after-hours login", guided:true, file:"/logs/auth.log",
      hint:"Open /logs/auth.log. One admin login happened during scheduled lab hours (expected). Another succeeded late at night, with no class on the calendar. Enter the SOURCE IP of that off-hours success. The daytime line is a decoy — submitting it just nudges you.",
      prompt:"Enter the source IP of the after-hours login.",
      accept:[["ip","10.20.9.14"]],
      decoys:[["ip","10.20.9.10","That's the scheduled daytime admin session — expected lab activity, not the incident. Find the login at an hour with no class on the calendar."]] },

    { id:"decode", week:7, points:1, skill:"Encoding & decoding",
      title:"Decode the analyst's note", guided:true, file:"/notes/scratch.txt",
      hint:"Findings aren't always in the clear. In /notes/scratch.txt the analyst left a Base32 string (RFC 4648). Decode it — paste it into CyberChef's 'From Base32', or run `echo <string> | base32 -d` — and enter the recovered text. The real midterm hides data in DNS the same way.",
      prompt:"Decode the Base32 string and enter the recovered text.",
      accept:[["text","demo-decode-ok"]], decoys:[] }
  ];

  var D = CONFIG.INCIDENT_DATE;

  var EVIDENCE = {
    "/case/brief.txt": function () {
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
"  Each objective asks for one finding you recover from the evidence.",
"  Type it into the box at the bottom; correct findings get stamped,",
"  and tempting-but-wrong lines just nudge you. Nothing to copy.",
"",
"CASE ID (your first finding — confirms you're on the right case):",
"  " + CONFIG.CASE_ID,
"============================================================"
      ].join("\n");
    },

    "/logs/auth.log": function () {
      return [
"# /logs/auth.log  —  TRAIN-WS-02 practice server      (times in MST)",
"# scheduled lab block today: 12:00-14:00",
"-------------------------------------------------------------------",
D + " 13:02:11  sshd[1122]: Accepted password for labadmin from 10.20.9.10 port 51110   session=scheduled-lab",
D + " 13:41:05  sshd[1140]: Accepted publickey   for student01 from 10.20.9.21 port 51822   session=scheduled-lab",
D + " 14:05:22  sshd[1140]: Disconnected          from 10.20.9.21 port 51822",
D + " 23:47:30  sshd[2203]: Failed password       for labadmin from 10.20.9.14 port 49771",
D + " 23:47:49  sshd[2203]: Failed password       for labadmin from 10.20.9.14 port 49773",
D + " 23:48:02  sshd[2203]: Accepted password     for labadmin from 10.20.9.14 port 49775   session=AFTER-HOURS",
"-------------------------------------------------------------------",
"# note: 23:48 is well outside the scheduled lab block."
      ].join("\n");
    },

    "/notes/scratch.txt": function () {
      return [
"analyst scratch pad — practice case",
"===================================",
"Reminder to self, Base32'd (RFC 4648) so it isn't sitting in the clear:",
"",
"    " + base32(DECODE_TEXT),
"",
"(decode that string and enter the recovered text as your finding.)",
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
    CONFIG: CONFIG, STEPS: STEPS, EVIDENCE: EVIDENCE, TREE: TREE,
    norm: norm, flagFor: flagFor, fingerprint: fingerprint, base32: base32, check: check,
    renderFile: function (path, id) { return EVIDENCE[path] ? EVIDENCE[path](id) : "(file not found)"; },
    allFlags: function (id) { var o = {}; STEPS.forEach(function (s) { o[s.id] = flagFor(id, s.id); }); return o; }
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  root.CASE = API;
})(typeof self !== "undefined" ? self : this);

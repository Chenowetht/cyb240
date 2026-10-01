/* ============================================================================
   case.js  —  Cochise College Network Security Team : Midterm Investigation
   SINGLE SOURCE OF TRUTH for the web app. The grader reads grader/config.json,
   which MUST carry the same SECRET, FLAG_PREFIX and step ids (verify via the
   fingerprint shown in the app footer / printed by grade.py).

   ANSWER-GATED MODEL:
     Students do NOT see or submit flags. Each step asks for a FINDING (an IP, a
     username, a domain, a decoded string, ...). The app validates that finding
     against the accepted answers below (format-tolerant) and, only when it is
     correct, records that student's per-step flag
         flag(studentId, stepId) = CCNST{ stepId _ HMAC-SHA256(SECRET, id|stepId)[:12] }
     into the export. The grader just recomputes those 15 values and compares —
     so grading and collusion detection are unchanged, but there is no flag text
     sitting in the evidence for anyone to copy.

   NOTE ON HIDING ANSWERS: accepted answers are in plaintext here. Because
   case.js ships to the browser, a student who opens it can read them (the same
   limitation as the SECRET). This stops casual copy-paste; it is not proof
   against a determined reverse-engineer.
   ============================================================================ */
(function (root) {
  "use strict";
  var H = (typeof require === "function") ? require("./shared_hash.js") : root.CCHash;

  /* ---- EDIT BEFORE DEPLOYING -------------------------------------------- */
  var CONFIG = {
    SECRET: "CHANGE-ME-before-you-deploy-2f9c",   // must match grader/config.json
    FLAG_PREFIX: "CCNST",
    CASE_ID: "CCNST-2026-0928",
    COURSE: "Network Forensics",
    TEAM: "Cochise College Network Security Team",
    INCIDENT_DATE: "2026-09-28"
  };
  /* ----------------------------------------------------------------------- */

  function norm(id) { return String(id || "").trim().toLowerCase().replace(/\s+/g, ""); }

  function flagFor(studentId, stepId) {
    var h = H.hmacSha256Hex(CONFIG.SECRET, norm(studentId) + "|" + stepId);
    return CONFIG.FLAG_PREFIX + "{" + stepId + "_" + h.slice(0, 12) + "}";
  }

  // short per-student label so the C2 / tunnel domains differ per student (realism only)
  function label(studentId, salt, n) {
    return H.hmacSha256Hex(CONFIG.SECRET, norm(studentId) + "|" + salt).slice(0, n || 8);
  }

  // RFC 4648 base32 (used to "exfiltrate" a finding into DNS query labels)
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

  /* ---- answer normalization + checking --------------------------------- *
     Each step carries accept:[[kind,value],...] and decoys:[[kind,value,msg]].
     A submission is normalized under each entry's kind and compared.          */
  function normAns(kind, v) {
    v = String(v == null ? "" : v).trim().toLowerCase();
    switch (kind) {
      case "ip":   return v.replace(/\s+/g, "").replace(/:\d+$/, "");
      case "mac":  return v.replace(/[^0-9a-f]/g, "");
      case "domain": {
        v = v.replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/\.+$/, "");
        var p = v.split("."); return p.slice(-2).join(".");
      }
      case "user": return v.replace(/^.*\\/, "").replace(/\s+/g, "");
      case "host": return v.replace(/\s+/g, "");
      case "int":  return v.replace(/[^0-9]/g, "");
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
  // returns {status:"correct"} | {status:"decoy", msg} | {status:"wrong"}
  function check(stepId, input) {
    var s = null;
    for (var i = 0; i < STEPS.length; i++) if (STEPS[i].id === stepId) s = STEPS[i];
    if (!s) return { status: "wrong" };
    if (matchList(s.accept, input)) return { status: "correct" };
    var d = matchList(s.decoys, input);
    if (d) return { status: "decoy", msg: d[2] };
    return { status: "wrong" };
  }

  /* ---- THE 15 STEPS ---------------------------------------------------- *
     guided:true  -> show a "start here" link to the file (on-ramp steps only)
     prompt       -> the concrete finding the student must enter
     accept/decoys-> format-tolerant answers and nudges                        */
  var STEPS = [
    { id:"intake", week:1, points:1, skill:"Evidence handling, scope & case intake",
      title:"Open the case", guided:true, file:"/case/brief.txt",
      hint:"Every investigation starts with scope, not packets. Read the case brief in /case/. Confirm you're working the right case by recording its identifier.",
      prompt:"Enter the Case ID from the brief (e.g., CCNST-YYYY-NNNN).",
      accept:[["text","CCNST-2026-0928"]], decoys:[] },

    { id:"capture", week:2, points:1, skill:"Packet capture & evidence integrity",
      title:"Verify the capture", guided:true, file:"/evidence/manifest.txt",
      hint:"Before trusting a capture, confirm it was handled properly. In the manifest, one acquisition's hash still matches on intake (integrity: VERIFIED); the others don't. Only a verified capture is admissible.",
      prompt:"Enter the filename of the VERIFIED capture.",
      accept:[["text","libvlan7_0145-0215.pcap"],["text","E-02"]],
      decoys:[["text","libvlan7_0130-0145.pcap","That capture failed verification (hash MISMATCH) — it's inadmissible. Use the one marked VERIFIED."],
              ["text","E-01","That's the rejected capture (integrity MISMATCH). Find the VERIFIED item."]] },

    { id:"dhcp", week:3, points:1, skill:"DHCP logs & asset identification",
      title:"Find the host that doesn't belong",
      hint:"A device that isn't one of your managed library workstations turned up on the subnet. You run the DHCP server for that VLAN, so every host that joined has a lease on record. Managed machines use vendor OUI 00:1b:44 and LIBR-WS-xx names — find the one that doesn't, by its hardware address and hostname, not just its IP. That host is your pivot.",
      prompt:"Identify the rogue host — enter its IP, MAC, or hostname.",
      accept:[["ip","10.14.7.88"],["mac","52:54:00:a1:7c:9e"],["host","DESKTOP-7F3A9C"]],
      decoys:[["host","LIBR-WS-07","That's a managed library workstation (OUI 00:1b:44). The rogue host uses a locally-administered MAC (52:54:00) and an unmanaged hostname."],
              ["ip","10.14.7.52","That lease belongs to a managed LIBR-WS workstation. Find the device that isn't in the managed inventory."]] },

    { id:"auth", week:3, points:1, skill:"Authentication logs",
      title:"Trace the stolen account",
      hint:"You have the rogue host's address. Getting on the network is rarely the goal — the next question is what it signed into. Where does your environment record login attempts? Find where that address authenticated successfully at an hour that doesn't fit normal operations.",
      prompt:"Enter the username of the compromised account.",
      accept:[["user","jturner"]],
      decoys:[["user","svc-backup","That's a normal service login from 10.14.3.9 at 21:14 — not the pivot. Find the account the rogue host (10.14.7.88) used off-hours."],
              ["user","mrivera","That's a normal daytime login. Find the off-hours ACCEPTED login from 10.14.7.88."],
              ["user","admin","That attempt failed (nouser). Find the account that actually succeeded."]] },

    { id:"dns", week:3, points:1, skill:"DNS logs & resolution evidence",
      title:"Spot the first call-out",
      hint:"Before a host can reach a server by name it has to resolve it, and your resolver logs every lookup. Separate ordinary campus traffic (CDNs, update servers) from the pivot's first request for a domain that has no business being contacted — newly registered, low reputation.",
      prompt:"Enter the malicious domain the rogue host resolved (the registered domain is enough).",
      accept:[["domain","sync-metrics.net"]],
      decoys:[["domain","cloudflarecdn.com","That's ordinary CDN traffic from a managed host (10.14.7.52). Find the pivot's first lookup of a newly-registered domain."],
              ["domain","microsoft.com","Benign update traffic. Look for the pivot's call-out to an unfamiliar domain."],
              ["domain","ntp.org","Benign time sync. Find the C2 domain."]] },

    { id:"firewall", week:3, points:1, skill:"Firewall logs",
      title:"Confirm the outbound connection",
      hint:"Resolving a name isn't the same as reaching the host — something has to permit the traffic out. Your perimeter records allow/deny decisions. Among the blocked noise, find where an outbound session from the pivot to that external address was actually allowed. (Note the timezone your perimeter logs in — you'll need it later.)",
      prompt:"Enter the external IP the firewall ALLOWED the host to reach.",
      accept:[["ip","203.0.113.66"]],
      decoys:[["ip","198.51.100.24","That's the bulk-transfer destination (a later step). This step wants the C2 address the firewall first ALLOWED outbound."]] },

    { id:"ids", week:4, points:1, skill:"IDS alerts",
      title:"Read the sensor's verdict",
      hint:"Your detection sensor had an opinion about this session. Find where it alerted on traffic between the pivot and that external host, and read which signature fired. (Note the time it fired; its clock and your perimeter's may not match.)",
      prompt:"Enter the IDS signature ID (SID) that fired on the C2 beacon.",
      accept:[["text","2027758"],["text","1:2027758:4"]],
      decoys:[["text","2010935","That's pre-incident SSH-scan noise from a different source. Find the alert on traffic between 10.14.7.88 and 203.0.113.66."],
              ["text","2024897","That's the large-transfer alert (the exfil). This step wants the C2 beacon signature."]] },

    { id:"dpi", week:4, points:1, skill:"Deep packet inspection",
      title:"Inspect the payload",
      hint:"An alert is a lead, not proof — look at the packets yourself. Early on, before the channel encrypted, one request went out in the clear. Reconstruct that exchange and read what the implant sent; it identifies itself in the request.",
      prompt:"Enter the implant's User-Agent (name/version) from the cleartext request.",
      accept:[["text","syncagent/1.4"],["text","syncagent"]],
      decoys:[["text","nginx","That's the C2 server's banner (the Server header), not the implant. The implant named itself in the request's User-Agent."]] },

    { id:"beacon", week:5, points:1, skill:"Flow analysis — beaconing",
      title:"Detect the beacon",
      hint:"One request is an anecdote; a control channel leaves a rhythm. Summarized flow records are enough. Malware checking in looks like small, near-identical transfers repeating on a fixed interval between the pivot and the external host. Find that periodic pattern — not the single big transfer.",
      prompt:"Enter the beacon interval in seconds.",
      accept:[["int","30"]],
      decoys:[["ip","198.51.100.24","That's the bulk transfer, not the beacon. The beacon is the small, periodic flow — find its interval."],
              ["int","48","48MB is the exfil volume, not the beacon interval. The beacon repeats on a fixed number of seconds."]] },

    { id:"exfil", week:5, points:1, skill:"Flow analysis — exfiltration",
      title:"Measure the exfiltration",
      hint:"The beacon is the heartbeat; the theft is the payload leaving. In the same flow data, the exfiltration is the outlier by volume — a single large outbound transfer, to a different external host than the beacon. Find it by byte count, not by eye.",
      prompt:"Enter the IP the ~48MB bulk transfer went to.",
      accept:[["ip","198.51.100.24"]],
      decoys:[["ip","203.0.113.66","That's the beacon/C2 host. The exfil is the single large (~48MB) transfer to a DIFFERENT host — find it by byte count."]] },

    { id:"timeline", week:6, points:1, skill:"Correlation & timestamp normalization",
      title:"Reconcile the clocks",
      hint:"Your evidence came from systems that don't keep the same clock — one source stamps local time and another stamps UTC (Cochise is MST year-round, UTC-7). To line the sensor's beacon alert up against the matching perimeter record you must convert between them.",
      prompt:"Convert the IDS beacon-alert time to UTC and enter it as HH:MM:SS.",
      accept:[["time","09:06:12"]],
      decoys:[["time","02:06:12","That's the sensor's MST time. Convert to UTC (+7h) to match the firewall's clock."],
              ["time","09:05:30","That's the first allow (the firewall step). This step wants the firewall line matching the IDS beacon alert after you convert its time."]] },

    { id:"tls", week:7, points:1, skill:"TLS metadata (SNI) analysis",
      title:"See through the TLS",
      hint:"Once the channel encrypted you can't read the payload — but the handshake isn't encrypted. The client still announces, in the clear, which host it's reaching as the session opens. Use that handshake metadata to tie the bulk transfer to its destination.",
      prompt:"Enter the destination domain from the bulk transfer's TLS SNI (registered domain is enough).",
      accept:[["domain","store-sync.net"]],
      decoys:[["domain","sync-metrics.net","That SNI is the C2 channel (session s-1). This step wants the destination of the 48MB bulk transfer (session s-2)."]] },

    { id:"dnstunnel", week:7, points:1, skill:"DNS tunneling & decoding",
      title:"Decode the DNS tunnel",
      hint:"Not all exfiltration looks like a file transfer — data can ride inside DNS itself. Somewhere in the resolver log is a burst of long, high-entropy names queried under one parent domain; that's payload smuggled into the query labels. Pull the labels in order, concatenate them, and Base32-decode (RFC 4648).",
      prompt:"Decode the DNS-tunnel labels and enter the recovered text.",
      accept:[["text","records_export_2026-09-28.zip"],["text","records_export_2026-09-28"]],
      decoys:[] },

    { id:"sshtunnel", week:7, points:1, skill:"SSH tunneling / pivoting",
      title:"Follow the SSH tunnel",
      hint:"The attacker reached an internal system the library subnet has no direct route to. The technique is pivoting: a session to a reachable jump host with a port forwarded through it. Look at the session records — the giveaway is the forward through the bastion, and what you want is the internal system reached at the far end.",
      prompt:"Enter the internal system reached through the tunnel (name or IP).",
      accept:[["host","RECS-DB-02"],["ip","10.14.3.22"]],
      decoys:[["host","BAST-JMP-01","That's the bastion/jump host used as the pivot, not the final target. Name the database reached through the forward (10.14.3.22)."],
              ["ip","10.14.3.9","That's the bastion. The local-forward reached the records database at 10.14.3.22."]] },

    { id:"conclusion", week:7, points:1, skill:"Limits of network evidence & reporting",
      title:"Close the case",
      hint:"Write the closeout. Later in the incident the lookups moved to encrypted DNS, so you lose that visibility — yet the transfer volume and the handshake metadata you already recovered still establish where the data went. State that metadata-based conclusion, and be honest about its limit: network evidence shows which host and account were used, not who sat at the keyboard.",
      prompt:"After DoH hid DNS, enter the exfil destination the metadata still proves (domain or host).",
      accept:[["domain","store-sync.net"],["ip","198.51.100.24"],["host","RECS-DB-02"]],
      decoys:[["domain","sync-metrics.net","That's the C2 domain whose later lookups went dark under DoH. The point is what metadata STILL proves: the bulk-transfer destination (flow + TLS SNI)."]] }
  ];

  /* ======================= SIMULATED EVIDENCE ============================ *
     Files contain the facts and decoys the student must reason over. No flags
     are printed here — the finding is the answer.                            */
  var D = CONFIG.INCIDENT_DATE;
  var EXFIL_FILE = "records_export_2026-09-28.zip";   // smuggled via the DNS tunnel

  var EVIDENCE = {
    "/case/brief.txt": function () {
      return [
"CASE BRIEF — CONFIDENTIAL",
"============================================================",
"Case ID        : " + CONFIG.CASE_ID,
"Opened         : " + D + " 07:40 MST",
"Assigned team  : " + CONFIG.TEAM,
"Reporting lead : analyst on duty (you)",
"",
"SUMMARY",
"  The Help Desk escalated after the Student Records application",
"  (RECS-APP-01) logged an administrative export outside business",
"  hours. A full packet capture and supporting logs were pulled",
"  from the Library distribution switch (VLAN 7, 10.14.7.0/24).",
"",
"SCOPE",
"  In scope : 10.14.7.0/24 (Library), RECS-APP-01 (10.14.3.10),",
"             and any external hosts they contacted on " + D + ".",
"  Out of scope: user web browsing unrelated to the incident.",
"",
"HOW TO ANSWER",
"  Each objective asks for one finding you recover from the evidence —",
"  an address, an account, a domain, a decoded string. Type that finding",
"  into the answer box; the system checks it and records your progress.",
"  There are no answer tags hidden in the files to copy.",
"",
"CASE ID (your first finding — confirms you're on the right case):",
"  " + CONFIG.CASE_ID,
"============================================================"
      ].join("\n");
    },

    "/case/scope.txt": function () {
      return [
"AUTHORIZATION & SCOPE MEMO",
"Authorized by : Director of IT Security, Cochise College",
"Legal hold    : all " + D + " logs for VLAN 7 preserved read-only.",
"Handling      : work from copies only; originals hashed and sealed.",
"Note          : network evidence establishes WHAT crossed the wire.",
"                It does not, by itself, establish intent or identity",
"                of the person at the keyboard. State that limit in the",
"                closeout."
      ].join("\n");
    },

    "/evidence/manifest.txt": function () {
      return [
"EVIDENCE MANIFEST — acquisition integrity",
"Acquired from Library distribution switch SPAN port, " + D + ".",
"Each capture hashed at acquisition (acq) and re-hashed on intake.",
"",
"item  file                     acq-sha256(12)  intake-sha256(12)  integrity",
"----  -----------------------  --------------  -----------------  ----------",
"E-01  libvlan7_0130-0145.pcap  7a1c9f20b4e8    1f0092ccaa41       MISMATCH   (altered in transit — do NOT use)",
"E-02  libvlan7_0145-0215.pcap  c38e5b9d7a16    c38e5b9d7a16       VERIFIED",
"E-03  libvlan7_0215-0230.pcap  9b44aa1e73d0    9b44aa1e73d0       VERIFIED   (in scope, no relevant activity)",
"",
"Use only VERIFIED items. E-01 failed verification and is inadmissible.",
"The window of interest (01:45-02:15 MST) lives in E-02."
      ].join("\n");
    },

    "/logs/dhcp.log": function () {
      return [
"# dhcpd lease log  —  server time: MST (UTC-7)  —  VLAN 7 (10.14.7.0/24)",
D + " 18:22:07 DHCPACK on 10.14.7.51 to 00:1b:44:7c:0a:11 (LIBR-WS-01) lease 8h",
D + " 18:45:51 DHCPACK on 10.14.7.52 to 00:1b:44:11:3a:b7 (LIBR-WS-07) lease 8h",
D + " 19:03:12 DHCPACK on 10.14.7.55 to 00:1b:44:7c:0a:5a (LIBR-WS-05) lease 8h",
D + " 20:10:44 DHCPACK on 10.14.7.58 to 00:1b:44:7c:0a:7e (LIBR-WS-09) lease 8h",
D + " 23:58:02 DHCPRELEASE on 10.14.7.55 from 00:1b:44:7c:0a:5a (LIBR-WS-05)",
D + " 01:52:19 DHCPDISCOVER from 52:54:00:a1:7c:9e via eth1",
D + " 01:52:20 DHCPOFFER on 10.14.7.88 to 52:54:00:a1:7c:9e",
D + " 01:52:20 DHCPREQUEST for 10.14.7.88 (52:54:00:a1:7c:9e) hostname \"DESKTOP-7F3A9C\"",
D + " 01:52:20 DHCPACK on 10.14.7.88 to 52:54:00:a1:7c:9e (DESKTOP-7F3A9C) lease 1h",
D + " 02:00:05 DHCPACK on 10.14.7.51 to 00:1b:44:7c:0a:11 (LIBR-WS-01) renew",
"# managed hosts use OUI 00:1b:44 and LIBR-WS-xx names. 52:54:00 is a",
"# locally-administered OUI, and DESKTOP-7F3A9C is not in the inventory."
      ].join("\n");
    },

    "/logs/auth.log": function () {
      var ip = "10.14.7.88";
      return [
"# auth / RADIUS+app log  —  time: MST (UTC-7)",
D + " 21:14:03 sshd RECS-APP-01: Accepted password for svc-backup from 10.14.3.9 (service acct, normal)",
D + " 01:58:41 RECS-APP-01 webauth: FAILED login user=jturner src=" + ip + " reason=badpass",
D + " 01:59:10 RECS-APP-01 webauth: FAILED login user=jturner src=" + ip + " reason=badpass",
D + " 01:59:39 RECS-APP-01 webauth: FAILED login user=jturner src=" + ip + " reason=badpass",
D + " 02:00:02 RECS-APP-01 webauth: FAILED login user=admin   src=" + ip + " reason=nouser",
D + " 02:03:27 RECS-APP-01 webauth: ACCEPTED login user=jturner src=" + ip + " mfa=bypassed(legacy-token)",
D + " 02:03:31 RECS-APP-01 app: session opened user=jturner role=records_export",
D + " 07:35:12 RECS-APP-01 webauth: ACCEPTED login user=mrivera src=10.14.3.44 (normal, daytime)"
      ].join("\n");
    },

    "/logs/dns.log": function (id) {
      var c2 = label(id, "c2label", 8) + ".sync-metrics.net";
      var payload = base32(EXFIL_FILE);
      var chunks = [];
      for (var i = 0; i < payload.length; i += 10) chunks.push(payload.slice(i, i + 10).toLowerCase());
      var tun = chunks.map(function (c, i) {
        return D + " 02:08:" + String(12 + i).padStart(2, "0") +
               " 10.14.7.88 query TXT " + c + "." + (i + 1) + ".tunnel.sync-metrics.net";
      }).join("\n");
      return [
"# resolver query log  —  time: MST (UTC-7)  —  client 10.14.7.88 unless noted",
D + " 00:12:44 10.14.7.52 query A  cdn.cloudflarecdn.com -> 104.18.6.33",
D + " 00:31:09 10.14.7.52 query A  update.microsoft.com  -> 23.45.11.8",
D + " 02:04:58 10.14.7.88 query A  " + c2 + " -> 203.0.113.66",
D + " 02:05:33 10.14.7.88 query A  " + c2 + " -> 203.0.113.66   (cached)",
D + " 02:07:41 10.14.7.88 query A  pool.ntp.org -> 162.159.200.1",
"# --- burst of oversized subdomains under *.tunnel.sync-metrics.net (possible DNS tunnel) ---",
tun,
D + " 02:10:55 10.14.7.88 query HTTPS dns.doh-" + label(id,"doh",4) + ".net -> 203.0.113.153  (further lookups now via DoH — not visible here)"
      ].join("\n");
    },

    "/logs/firewall.log": function () {
      // UTC = MST + 7. First C2 allow 02:05:30 MST = 09:05:30 UTC (firewall step).
      // IDS beacon alert 02:06:12 MST = 09:06:12 UTC (timeline step).
      return [
"# perimeter firewall  —  time: UTC  (note: 7h ahead of the MST sensor logs)",
D + " 09:04:58 UTC DENY  10.14.7.88:50112 -> 203.0.113.66:443  rule=egress-default",
D + " 09:05:12 UTC DENY  10.14.7.88:50114 -> 203.0.113.66:8443 rule=egress-default",
D + " 09:05:30 UTC ALLOW 10.14.7.88:50120 -> 203.0.113.66:443  rule=allow-443-any",
D + " 09:05:31 UTC ALLOW 10.14.7.88:50121 -> 203.0.113.66:443  rule=allow-443-any",
D + " 09:06:12 UTC ALLOW 10.14.7.88:50140 -> 203.0.113.66:443  rule=allow-443-any",
D + " 09:11:03 UTC ALLOW 10.14.7.88:51022 -> 198.51.100.24:443 rule=allow-443-any  bytes=50312744",
D + " 15:02:50 UTC ALLOW 10.14.3.44:44210 -> 198.51.100.9:443  rule=allow-443-any  (daytime, normal)",
"# to line these up with the IDS, convert the MST alert times to UTC (+7h)."
      ].join("\n");
    },

    "/logs/ids.log": function () {
      return [
"# IDS (Suricata-style)  —  time: MST (UTC-7)  —  format: [gid:sid:rev]",
D + " 01:40:11 MST [1:2010935:3] ET SCAN Potential SSH Scan  src=198.51.100.7 dst=10.14.7.0/24 (low, pre-incident noise)",
D + " 02:06:12 MST [1:2027758:4] ET MALWARE Likely C2 Beacon (periodic TLS)  src=10.14.7.88 dst=203.0.113.66",
D + " 02:11:20 MST [1:2024897:2] ET POLICY Large Outbound Data Transfer  src=10.14.7.88 dst=198.51.100.24",
D + " 09:50:02 MST [1:2013028:5] ET INFO Dropbox Client Broadcast  src=10.14.7.60 (daytime, benign)"
      ].join("\n");
    },

    "/logs/proxy.log": function () {
      return [
"# web proxy  —  time: MST  —  (library general browsing, mostly benign)",
D + " 19:22:10 10.14.7.55 GET https://en.wikipedia.org/ 200",
D + " 20:05:41 10.14.7.58 GET https://scholar.google.com/ 200",
D + " 02:04:02 10.14.7.88 CONNECT 203.0.113.66:443 - (tunnelled, no content visible via proxy)",
"# note: the pivot used CONNECT; the proxy sees the destination but not the payload."
      ].join("\n");
    },

    "/evidence/http_stream.txt": function (id) {
      return [
"Follow TCP stream  —  E-02, stream 14  —  10.14.7.88:50120 -> 203.0.113.66:80",
"(the first check-in went out over cleartext HTTP before the channel upgraded to TLS)",
"",
"POST /ingest/checkin HTTP/1.1",
"Host: " + label(id, "c2label", 8) + ".sync-metrics.net",
"User-Agent: SyncAgent/1.4",
"Accept: */*",
"Content-Type: application/octet-stream",
"Content-Length: 128",
"",
"<128 bytes of encoded host-survey data omitted>",
"",
"HTTP/1.1 200 OK",
"Server: nginx",
"Set-Cookie: sid=" + label(id, "sid", 16) + "; HttpOnly",
"",
"# The implant identifies itself in the request. After this response all",
"# further C2 moved to TLS/443 (see tls_sessions.txt)."
      ].join("\n");
    },

    "/flow/netflow.csv": function () {
      return [
"# NetFlow v9 export  —  time: MST  —  columns:",
"start,end,src,dst,proto,sport,dport,packets,bytes,flows,note",
"02:04:58,02:05:00,10.14.7.88,203.0.113.66,TCP,50120,443,6,612,1,initial-contact",
"02:05:30,02:06:00,10.14.7.88,203.0.113.66,TCP,50121,443,6,604,1,",
"02:06:00,02:06:30,10.14.7.88,203.0.113.66,TCP,50140,443,6,598,1,",
"02:05:00,02:11:00,10.14.7.88,203.0.113.66,TCP,-,443,72,7208,12,periodic-small-30s-interval",
"02:11:03,02:12:40,10.14.7.88,198.51.100.24,TCP,51022,443,34120,50312744,1,single-large-outbound",
"02:05:10,02:05:12,10.14.7.60,157.240.1.35,UDP,51110,443,4,420,1,quic-normal-daytime-user",
"02:09:00,02:09:02,10.14.7.88,203.0.113.153,UDP,52001,443,8,900,1,doh-resolver-encrypted-dns",
"# One destination shows many small flows on a fixed interval; another shows a",
"# single very large transfer. Sort by bytes and compare — they are different hosts."
      ].join("\n");
    },

    "/evidence/tls_sessions.txt": function (id) {
      return [
"TLS ClientHello summary  —  E-02  —  payloads encrypted, handshakes are not",
"",
"session  src           dst              sni                                        ja3(12)",
"-------  ------------  ---------------  -----------------------------------------  ------------",
"s-1      10.14.7.88    203.0.113.66     " + label(id,"c2label",8) + ".sync-metrics.net                51a9f0c7d2b8  (C2 channel)",
"s-2      10.14.7.88    198.51.100.24    " + label(id,"blob",10) + ".blob.store-sync.net        7e22c1aa90ff  (bulk transfer)",
"s-3      10.14.7.60    157.240.1.35     edge-mqtt.facebook.com                     a0d1f9...     (benign, daytime)",
"",
"# The payload is encrypted, but the SNI in the ClientHello names the host each",
"# session reached. Match the session that carried the large transfer to its SNI."
      ].join("\n");
    },

    "/flow/ssh_sessions.txt": function () {
      return [
"SSH session notes  —  reconstructed from flow + bastion auth  —  time: MST",
"",
D + " 02:09:40  10.14.7.88 -> 10.14.3.9:22 (BAST-JMP-01)  auth=key  user=svc-backup",
"           channel 1: shell",
"           channel 2: direct-tcpip  local-forward 127.0.0.1:15432 -> 10.14.3.22:5432",
"           -> reached 10.14.3.22 (RECS-DB-02), the records database, which has",
"              NO direct route from VLAN 7.",
"",
"# The library subnet cannot talk to 10.14.3.22 directly; the SSH local-forward",
"# through the bastion (10.14.3.9) is how the pivot reached the database."
      ].join("\n");
    },

    "/notes/analyst_scratch.txt": function () {
      return [
"ANALYST SCRATCHPAD (method reminders — not findings)",
"- Managed VLAN7 hosts use OUI 00:1b:44 and names LIBR-WS-xx; anything else is suspect.",
"- CHECK CLOCKS before correlating: firewall = UTC, IDS/DHCP/DNS/flow = MST",
"  (Arizona, UTC-7, no DST). Convert one to the other.",
"- Beaconing is small + periodic; exfiltration is one large transfer. Sort flows",
"  by bytes rather than eyeballing, and watch that they go to different hosts.",
"- Encryption hides payload, not the handshake: SNI still names destinations.",
"- Separate what the wire PROVES from what it merely SUGGESTS."
      ].join("\n");
    },

    "/notes/REPORT_closeout.txt": function () {
      return [
"CASE CLOSEOUT — method & limits  (" + CONFIG.CASE_ID + ")",
"============================================================",
"REPORTING PRINCIPLE",
"  State conclusions only to the level the evidence supports, and record the",
"  limits alongside them.",
"",
"VISIBILITY NOTE",
"  Once name resolution moved to encrypted DNS (DoH), the CONTENT of later",
"  lookups is no longer in the resolver log. That does not erase the",
"  exfiltration: flow volume plus the unencrypted TLS handshake metadata (SNI)",
"  still establish the destination the bulk transfer reached.",
"",
"LIMITS OF NETWORK EVIDENCE",
"  The capture shows which host and which account were used. It does not, by",
"  itself, prove which person was at the keyboard — that needs endpoint or",
"  physical evidence. Keep that distinction in the final report.",
"============================================================"
      ].join("\n");
    }
  };

  // directory tree for the UI
  var TREE = [
    { dir: "/case",     files: ["/case/brief.txt", "/case/scope.txt"] },
    { dir: "/evidence", files: ["/evidence/manifest.txt", "/evidence/http_stream.txt", "/evidence/tls_sessions.txt"] },
    { dir: "/logs",     files: ["/logs/dhcp.log", "/logs/auth.log", "/logs/dns.log", "/logs/firewall.log", "/logs/ids.log", "/logs/proxy.log"] },
    { dir: "/flow",     files: ["/flow/netflow.csv", "/flow/ssh_sessions.txt"] },
    { dir: "/notes",    files: ["/notes/analyst_scratch.txt", "/notes/REPORT_closeout.txt"] }
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

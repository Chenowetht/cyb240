/* ============================================================================
   case.js  —  Cochise College Network Security Team : Midterm Investigation
   SINGLE SOURCE OF TRUTH for the web app. The grader reads grader/config.json,
   which MUST carry the same SECRET, FLAG_PREFIX and step ids (verify via the
   fingerprint shown in the app footer / printed by grade.py).

   How per-student flags work:
     flag(studentId, stepId) = CCNST{ stepId _ HMAC-SHA256(SECRET, id|stepId)[:12] }
   Every submitted flag is exactly this value. The evidence below hides each
   flag on the line a correct investigation leads to; the grader only recomputes
   the 15 values and compares — it never needs to parse the evidence.
   ============================================================================ */
(function (root) {
  "use strict";
  var H = (typeof require === "function") ? require("./shared_hash.js") : root.CCHash;

  /* ---- EDIT BEFORE DEPLOYING -------------------------------------------- */
  var CONFIG = {
    SECRET: "openssl rand -hex 24",   // must match grader/config.json
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

  // RFC 4648 base32 (used to "exfiltrate" the DNS-tunnel flag into query labels)
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

  /* ---- THE 15 STEPS: the guided investigation -------------------------- *
     Each step maps to a week/skill, tells the student where to look next,
     and names the file whose "correct" line carries their flag.            */
  var STEPS = [
    { id:"intake",    week:1, points:1, skill:"Evidence handling, scope & case intake",
      title:"Open the case",
      file:"/case/brief.txt",
      hint:"Every investigation starts with scope, not packets. Read the case brief in /case/. Record the case evidence tag exactly as written — that is your first flag, and it confirms you are working the right case.",
      next:"Now inventory what was actually collected." },

    { id:"capture",   week:2, points:1, skill:"Packet capture & evidence integrity",
      title:"Verify the capture",
      file:"/evidence/manifest.txt",
      hint:"Before trusting a capture, confirm it was handled properly. Open /evidence/manifest.txt and find the capture whose recorded hash still matches (integrity: VERIFIED). Its evidence tag is the flag — a capture that failed verification can't be your starting point.",
      next:"You have a trustworthy capture from the library subnet. Find out which host doesn't belong there." },

    { id:"dhcp",      week:3, points:1, skill:"DHCP logs & asset identification",
      title:"Find the host that doesn't belong",
      file:"/logs/dhcp.log",
      hint:"The library runs managed workstations (vendor OUI 00:1b:44, hostnames LIBR-WS-xx). In /logs/dhcp.log, one device pulled a lease after hours with a locally-administered MAC and an unmanaged hostname. That rogue device is your pivot — the flag is on its lease.",
      next:"Track that pivot's IP. What did it log into?" },

    { id:"auth",      week:3, points:1, skill:"Authentication logs",
      title:"Trace the stolen account",
      file:"/logs/auth.log",
      hint:"Follow the pivot's IP into /logs/auth.log. You'll see several failures then one success against a records server, at an hour no librarian is working. The flag is on that successful off-hours authentication.",
      next:"Once it was in, where did it try to call home?" },

    { id:"dns",       week:3, points:1, skill:"DNS logs & resolution evidence",
      title:"Spot the first call-out",
      file:"/logs/dns.log",
      hint:"In /logs/dns.log, separate normal campus lookups (CDNs, updates) from the first resolution of a freshly-registered, low-reputation domain made by the pivot. The flag is on that first C2 lookup — not on the ordinary content-delivery traffic around it.",
      next:"DNS only resolves a name. Did the firewall actually let the connection out?" },

    { id:"firewall",  week:3, points:1, skill:"Firewall logs",
      title:"Confirm the outbound connection",
      file:"/logs/firewall.log",
      hint:"The firewall log is in UTC — note that for later. Find the first ALLOWED outbound session from the pivot to the C2 address (surrounded by DENY noise). The flag is on that allow rule hit.",
      next:"Your sensors should have had an opinion about this traffic." },

    { id:"ids",       week:4, points:1, skill:"IDS alerts",
      title:"Read the sensor's verdict",
      file:"/logs/ids.log",
      hint:"The IDS (/logs/ids.log, local MST time) fired on this session. Find the alert whose source is the pivot and destination is the C2 host. The flag is attached to that signature hit.",
      next:"An alert is a lead, not proof. Open the packets and see it yourself." },

    { id:"dpi",       week:4, points:1, skill:"Deep packet inspection",
      title:"Inspect the payload",
      file:"/evidence/http_stream.txt",
      hint:"Before the channel went fully encrypted, one request went out in the clear. In /evidence/http_stream.txt, follow the stream and read the request the implant sent. Its tell-tale header carries the flag.",
      next:"One request is anecdote. Step back and look at the traffic pattern over time." },

    { id:"beacon",    week:5, points:1, skill:"Flow analysis — beaconing",
      title:"Detect the beacon",
      file:"/flow/netflow.csv",
      hint:"In /flow/netflow.csv, the pivot talks to the C2 host on a fixed, regular interval with nearly identical tiny byte counts — a beacon. Find the summarized beacon flow; the flag is in its note column. (Small and periodic: not the one big transfer.)",
      next:"Beacons are the heartbeat. Now find the payload leaving the building." },

    { id:"exfil",     week:5, points:1, skill:"Flow analysis — exfiltration",
      title:"Measure the exfiltration",
      file:"/flow/netflow.csv",
      hint:"Still in the NetFlow data, find the single outbound flow with a large byte count to a different external host than the beacon. That bulk transfer is the exfil; the flag is in its note. Sort by bytes, don't eyeball.",
      next:"You have events across several logs. They won't line up until you fix the clocks." },

    { id:"timeline",  week:6, points:1, skill:"Correlation & timestamp normalization",
      title:"Reconcile the clocks",
      file:"/logs/firewall.log",
      hint:"The IDS logs in MST; the firewall logs in UTC. Cochise is on MST year-round (UTC-7). Take the IDS beacon-alert time, convert it to UTC, and find the firewall line at that exact UTC second. Correlating across the offset lands you on one specific allow line — the flag is there.",
      next:"The channel is encrypted from here. Decide what you can still prove." },

    { id:"tls",       week:7, points:1, skill:"TLS metadata (SNI) analysis",
      title:"See through the TLS",
      file:"/evidence/tls_sessions.txt",
      hint:"Encryption hides the payload, not the handshake. In /evidence/tls_sessions.txt, the ClientHello for the bulk-transfer session leaks an SNI that names the exfil destination. The flag rides on that session's SNI line.",
      next:"Some traffic hid inside DNS itself. Decode it." },

    { id:"dnstunnel", week:7, points:1, skill:"DNS tunneling & decoding",
      title:"Decode the DNS tunnel",
      file:"/logs/dns.log",
      hint:"Return to /logs/dns.log and look at the burst of long, high-entropy subdomains under *.tunnel.* — that's data smuggled in query labels. Concatenate those labels in order and Base32-decode (RFC 4648). The decoded text IS your flag.",
      next:"One more evasion: a connection that reached a host it shouldn't have been able to." },

    { id:"sshtunnel", week:7, points:1, skill:"SSH tunneling / pivoting",
      title:"Follow the SSH tunnel",
      file:"/flow/ssh_sessions.txt",
      hint:"In /flow/ssh_sessions.txt, the pivot opened an SSH session to the bastion and set up a local port-forward to reach a host with no direct route from the library subnet. The flag is on the line naming the internal system reached through the tunnel.",
      next:"Write the closeout: state what the evidence proves and what it cannot." },

    { id:"conclusion",week:7, points:1, skill:"Limits of network evidence & reporting",
      title:"Close the case",
      file:"/notes/REPORT_closeout.txt",
      hint:"Read /notes/REPORT_closeout.txt. Later lookups switched to encrypted DNS (DoH), so name resolution went dark — yet flow volume and the TLS SNI still establish the exfil destination. The closeout tag that records this metadata-based conclusion is your final flag.",
      next:"Investigation complete. Export your submission." }
  ];

  /* ---- decoys: tempting-but-wrong lines carry these fixed, invalid tags.
     The app recognises them and nudges; the grader treats them as incorrect. */
  var DECOYS = {
    dhcp:  { "CCNST{dhcp_managedhost0}":  "That's a managed library workstation (approved OUI 00:1b:44). Look for a device whose MAC is locally-administered and whose hostname isn't LIBR-WS-xx." },
    dns:   { "CCNST{dns_cdnnoise0000}":   "That's an ordinary content-delivery lookup. Find the pivot's first resolution of the newly-registered, low-reputation domain." }
  };

  /* ======================= SIMULATED EVIDENCE ============================ *
     Each entry: path -> function(studentId) -> file text, with the flag for
     the relevant step(s) injected on the correct line(s).                   */
  var D = CONFIG.INCIDENT_DATE;           // 2026-09-28
  function F(id, step) { return flagFor(id, step); }

  var EVIDENCE = {
    "/case/brief.txt": function (id) {
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
"YOUR TASK",
"  Reconstruct what happened, in order, from the evidence provided.",
"  Keep observations separate from conclusions. Record each finding",
"  as the flag embedded beside it.",
"",
"CASE EVIDENCE TAG (record this as your first flag):",
"  " + F(id, "intake"),
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

    "/evidence/manifest.txt": function (id) {
      return [
"EVIDENCE MANIFEST — acquisition integrity",
"Acquired from Library distribution switch SPAN port, " + D + ".",
"Each capture hashed at acquisition (acq) and re-hashed on intake.",
"",
"item  file                     acq-sha256(12)  intake-sha256(12)  integrity   evidence-tag",
"----  -----------------------  --------------  -----------------  ----------  ------------",
"E-01  libvlan7_0130-0145.pcap  7a1c9f20b4e8    1f0092ccaa41       MISMATCH    (rejected: altered in transit — do NOT use)",
"E-02  libvlan7_0145-0215.pcap  c38e5b9d7a16    c38e5b9d7a16       VERIFIED    " + F(id, "capture"),
"E-03  libvlan7_0215-0230.pcap  9b44aa1e73d0    9b44aa1e73d0       VERIFIED    (in scope, no relevant activity)",
"",
"Use only VERIFIED items. E-01 failed verification and is inadmissible.",
"The window of interest (01:45–02:15 MST) lives in E-02."
      ].join("\n");
    },

    "/logs/dhcp.log": function (id) {
      // MST. Managed hosts 00:1b:44 / LIBR-WS-xx. Rogue = locally-administered 52:54:00.
      return [
"# dhcpd lease log  —  server time: MST (UTC-7)  —  VLAN 7 (10.14.7.0/24)",
D + " 18:22:07 DHCPACK on 10.14.7.51 to 00:1b:44:7c:0a:11 (LIBR-WS-01) lease 8h",
D + " 18:45:51 DHCPACK on 10.14.7.52 to 00:1b:44:11:3a:b7 (LIBR-WS-07) lease 8h   " + "CCNST{dhcp_managedhost0}",
D + " 19:03:12 DHCPACK on 10.14.7.55 to 00:1b:44:7c:0a:5a (LIBR-WS-05) lease 8h",
D + " 20:10:44 DHCPACK on 10.14.7.58 to 00:1b:44:7c:0a:7e (LIBR-WS-09) lease 8h",
D + " 23:58:02 DHCPRELEASE on 10.14.7.55 from 00:1b:44:7c:0a:5a (LIBR-WS-05)",
D + " 01:52:19 DHCPDISCOVER from 52:54:00:a1:7c:9e via eth1",
D + " 01:52:20 DHCPOFFER on 10.14.7.88 to 52:54:00:a1:7c:9e",
D + " 01:52:20 DHCPREQUEST for 10.14.7.88 (52:54:00:a1:7c:9e) hostname \"DESKTOP-7F3A9C\"",
D + " 01:52:20 DHCPACK on 10.14.7.88 to 52:54:00:a1:7c:9e (DESKTOP-7F3A9C) lease 1h   " + F(id, "dhcp"),
D + " 02:00:05 DHCPACK on 10.14.7.51 to 00:1b:44:7c:0a:11 (LIBR-WS-01) renew",
"# note: 52:54:00 is a locally-administered OUI; DESKTOP-7F3A9C is not in the managed inventory."
      ].join("\n");
    },

    "/logs/auth.log": function (id) {
      var ip = "10.14.7.88";
      return [
"# auth / RADIUS+app log  —  time: MST (UTC-7)",
D + " 21:14:03 sshd RECS-APP-01: Accepted password for svc-backup from 10.14.3.9",
D + " 01:58:41 RECS-APP-01 webauth: FAILED login user=jturner src=" + ip + " reason=badpass",
D + " 01:59:10 RECS-APP-01 webauth: FAILED login user=jturner src=" + ip + " reason=badpass",
D + " 01:59:39 RECS-APP-01 webauth: FAILED login user=jturner src=" + ip + " reason=badpass",
D + " 02:00:02 RECS-APP-01 webauth: FAILED login user=admin   src=" + ip + " reason=nouser",
D + " 02:03:27 RECS-APP-01 webauth: ACCEPTED login user=jturner src=" + ip + " mfa=bypassed(legacy-token)   " + F(id, "auth"),
D + " 02:03:31 RECS-APP-01 app: session opened user=jturner role=records_export",
D + " 07:35:12 RECS-APP-01 webauth: ACCEPTED login user=mrivera src=10.14.3.44 (normal, daytime)"
      ].join("\n");
    },

    "/logs/dns.log": function (id) {
      var c2 = label(id, "c2label", 8) + ".sync-metrics.net";
      // DNS-tunnel labels: base32 of the dnstunnel flag, chunked.
      var payload = base32(F(id, "dnstunnel"));
      var chunks = [];
      for (var i = 0; i < payload.length; i += 10) chunks.push(payload.slice(i, i + 10).toLowerCase());
      var tun = chunks.map(function (c, i) {
        return D + " 02:08:" + String(12 + i).padStart(2, "0") +
               " 10.14.7.88 query TXT " + c + "." + (i + 1) + ".tunnel.sync-metrics.net";
      }).join("\n");
      return [
"# resolver query log  —  time: MST (UTC-7)  —  client 10.14.7.88 unless noted",
D + " 00:12:44 10.14.7.52 query A  cdn.cloudflarecdn.com -> 104.18.6.33        CCNST{dns_cdnnoise0000}",
D + " 00:31:09 10.14.7.52 query A  update.microsoft.com  -> 23.45.11.8",
D + " 02:04:58 10.14.7.88 query A  " + c2 + " -> 203.0.113.66   " + F(id, "dns"),
D + " 02:05:33 10.14.7.88 query A  " + c2 + " -> 203.0.113.66   (cached)",
D + " 02:07:41 10.14.7.88 query A  pool.ntp.org -> 162.159.200.1",
"# --- burst of oversized subdomains to *.tunnel.sync-metrics.net (possible DNS tunnel) ---",
tun,
D + " 02:10:55 10.14.7.88 query HTTPS dns.doh-" + label(id,"doh",4) + ".net -> 203.0.113.153  (subsequent lookups now via DoH — not visible here)"
      ].join("\n");
    },

    "/logs/firewall.log": function (id) {
      // UTC. MST+7. First C2 allow 02:05:30 MST = 09:05:30 UTC (firewall step).
      // IDS beacon alert 02:06:12 MST = 09:06:12 UTC (timeline step).
      return [
"# perimeter firewall  —  time: UTC  (note: 7h ahead of MST sensor logs)",
D + " 09:04:58 UTC DENY  10.14.7.88:50112 -> 203.0.113.66:443  rule=egress-default",
D + " 09:05:12 UTC DENY  10.14.7.88:50114 -> 203.0.113.66:8443 rule=egress-default",
D + " 09:05:30 UTC ALLOW 10.14.7.88:50120 -> 203.0.113.66:443  rule=allow-443-any   " + F(id, "firewall"),
D + " 09:05:31 UTC ALLOW 10.14.7.88:50121 -> 203.0.113.66:443  rule=allow-443-any",
D + " 09:06:12 UTC ALLOW 10.14.7.88:50140 -> 203.0.113.66:443  rule=allow-443-any   " + F(id, "timeline"),
D + " 09:11:03 UTC ALLOW 10.14.7.88:51022 -> 198.51.100.24:443 rule=allow-443-any  bytes=50312744",
D + " 15:02:50 UTC ALLOW 10.14.3.44:44210 -> 198.51.100.9:443  rule=allow-443-any  (daytime, normal)",
"# reminder: to line these up with the IDS, convert MST alert times to UTC (+7h)."
      ].join("\n");
    },

    "/logs/ids.log": function (id) {
      return [
"# IDS (Suricata-style)  —  time: MST (UTC-7)",
D + " 01:40:11 MST [1:2010935:3] ET SCAN Potential SSH Scan  src=198.51.100.7 dst=10.14.7.0/24 (low, pre-incident noise)",
D + " 02:06:12 MST [1:2027758:4] ET MALWARE Likely C2 Beacon (periodic TLS)  src=10.14.7.88 dst=203.0.113.66  " + F(id, "ids"),
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
"(first check-in went out over cleartext HTTP before the channel upgraded to TLS)",
"",
"POST /ingest/checkin HTTP/1.1",
"Host: " + label(id, "c2label", 8) + ".sync-metrics.net",
"User-Agent: SyncAgent/1.4 (+tag:" + F(id, "dpi") + ")",
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
"# The implant stamped its build tag into the User-Agent. That tag is the flag.",
"# After this response, all further C2 moved to TLS/443 (see tls_sessions.txt)."
      ].join("\n");
    },

    "/flow/netflow.csv": function (id) {
      return [
"# NetFlow v9 export  —  time: MST  —  columns:",
"start,end,src,dst,proto,sport,dport,packets,bytes,flows,note",
"02:04:58,02:05:00,10.14.7.88,203.0.113.66,TCP,50120,443,6,612,1,initial-contact",
"02:05:30,02:06:00,10.14.7.88,203.0.113.66,TCP,50121,443,6,604,1,",
"02:06:00,02:06:30,10.14.7.88,203.0.113.66,TCP,50140,443,6,598,1,",
"02:05:00,02:11:00,10.14.7.88,203.0.113.66,TCP,-,443,72,7208,12,beacon-30s-interval-~600B  " + F(id, "beacon"),
"02:11:03,02:12:40,10.14.7.88,198.51.100.24,TCP,51022,443,34120,50312744,1,bulk-outbound-~48MB  " + F(id, "exfil"),
"02:05:10,02:05:12,10.14.7.60,157.240.1.35,UDP,51110,443,4,420,1,quic-normal-daytime-user",
"02:09:00,02:09:02,10.14.7.88,203.0.113.153,UDP,52001,443,8,900,1,doh-resolver-encrypted-dns",
"# Sort by bytes: the 48MB flow to 198.51.100.24 is the exfil; the 7KB/12-flow",
"# row is the periodic beacon. They go to DIFFERENT external hosts."
      ].join("\n");
    },

    "/evidence/tls_sessions.txt": function (id) {
      return [
"TLS ClientHello summary  —  E-02  —  payloads encrypted, handshakes are not",
"",
"session  src           dst              sni                                   ja3(12)",
"-------  ------------  ---------------  ------------------------------------  ------------",
"s-1      10.14.7.88    203.0.113.66     " + label(id,"c2label",8) + ".sync-metrics.net           51a9f0c7d2b8  (C2 channel)",
"s-2      10.14.7.88    198.51.100.24    " + label(id,"blob",10) + ".blob.store-sync.net   7e22c1aa90ff  (bulk transfer) " + F(id, "tls"),
"s-3      10.14.7.60    157.240.1.35     edge-mqtt.facebook.com                a0d1f9...     (benign, daytime)",
"",
"# The payload is encrypted, but the SNI in the ClientHello names the host the",
"# 48MB transfer went to. That destination is the flag."
      ].join("\n");
    },

    "/flow/ssh_sessions.txt": function (id) {
      return [
"SSH session notes  —  reconstructed from flow + bastion auth  —  time: MST",
"",
D + " 02:09:40  10.14.7.88 -> 10.14.3.9:22 (BAST-JMP-01)  auth=key  user=svc-backup",
"           channel 1: shell",
"           channel 2: direct-tcpip  local-forward 127.0.0.1:15432 -> 10.14.3.22:5432",
"           -> reached RECS-DB-02 (10.14.3.22), the records database, which has",
"              NO direct route from VLAN 7. Pivot via the bastion's port-forward.   " + F(id, "sshtunnel"),
"",
"# The library subnet cannot talk to 10.14.3.22 directly; the SSH local-forward",
"# through the bastion is how the pivot reached the database. Name that host."
      ].join("\n");
    },

    "/notes/analyst_scratch.txt": function () {
      return [
"ANALYST SCRATCHPAD (working notes — observations, not conclusions)",
"- VLAN7 managed hosts use OUI 00:1b:44 and names LIBR-WS-xx.",
"- CHECK CLOCKS: firewall = UTC, IDS/DHCP/DNS/flow = MST (Arizona, UTC-7, no DST).",
"- Two external hosts matter: 203.0.113.66 (beacon/C2) and 198.51.100.24 (bulk).",
"- Beacon ~30s / ~600B; one 48MB transfer. Different destinations.",
"- Later DNS went to a DoH resolver -> plaintext DNS visibility ends there.",
"- Separate what the wire PROVES from what it merely SUGGESTS."
      ].join("\n");
    },

    "/notes/REPORT_closeout.txt": function (id) {
      return [
"CASE CLOSEOUT — findings & limits  (" + CONFIG.CASE_ID + ")",
"============================================================",
"ESTABLISHED BY EVIDENCE:",
"  - A rogue device (10.14.7.88) authenticated as 'jturner' to RECS-APP-01",
"    off-hours, beaconed to 203.0.113.66, and transferred ~48MB to an external",
"    host whose TLS SNI resolves to a store-sync.net bucket.",
"  - It pivoted through the bastion to reach RECS-DB-02.",
"",
"LIMITS OF THIS EVIDENCE:",
"  - Once lookups moved to DoH, DNS contents are no longer visible; destination",
"    attribution for later traffic rests on FLOW VOLUME + TLS SNI metadata, not",
"    on decrypted payload.",
"  - Network data shows the host and account used; it does NOT by itself prove",
"    which person operated the keyboard. That requires endpoint/physical evidence.",
"",
"METADATA-BASED CONCLUSION TAG (final flag):",
"  " + F(id, "conclusion"),
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
    CONFIG: CONFIG, STEPS: STEPS, DECOYS: DECOYS, EVIDENCE: EVIDENCE, TREE: TREE,
    norm: norm, flagFor: flagFor, fingerprint: fingerprint, base32: base32,
    renderFile: function (path, id) { return EVIDENCE[path] ? EVIDENCE[path](id) : "(file not found)"; },
    allFlags: function (id) { var o = {}; STEPS.forEach(function (s) { o[s.id] = flagFor(id, s.id); }); return o; }
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  root.CASE = API;
})(typeof self !== "undefined" ? self : this);

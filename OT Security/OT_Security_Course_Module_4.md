# OT Security Course - Module 4/5
## Threat Detection, Hunting, and Incident Response in OT

**Estimated Time: 4 Hours**

### **Module Objective:**
Upon completion of this module, students will be able to develop OT-specific threat detection use cases, understand methodologies for threat hunting in industrial networks, and apply the unique phases and considerations of an OT incident response (IR) lifecycle to a real-world scenario.

---

### **Section 1: OT Threat Detection & SIEM Integration (1.5 Hours)**

#### **1.1 Limitations of a Standard IT SIEM**
*   **Lack of Context:** A standard Security Information and Event Management (SIEM) system doesn't understand OT protocols. An alert for "Anomalous traffic on port 102" is meaningless without knowing this is S7 communication and what the specific commands were.
*   **Alert Fatigue:** Without OT context, a SIEM can generate thousands of false positives, causing analysts to ignore real threats.
*   **The Solution: Enriched Data:** The OT Visibility Platforms discussed in Module 2 are essential. They act as the primary sensor grid, performing deep packet inspection and sending *context-rich, high-fidelity alerts* to the SIEM.
    *   **Poor Alert:** "High traffic volume from 10.10.1.102"
    *   **Enriched Alert:** "Engineering_WS_01 is attempting to upload a new configuration to Turbine_PLC_01 outside of a scheduled maintenance window."

#### **1.2 Developing OT-Specific Detection Use Cases**
This is the core of OT threat detection. You must move beyond simple malware signatures and look for behaviors that indicate a threat. A good framework is to categorize detections by type.

*   **1. Policy & Configuration Violations (The easiest to implement):**
    *   **New Device Detected:** A new MAC or IP address appears on the control network.
    *   **Unauthorized Remote Access:** A remote session is initiated from an unknown source IP or outside of business hours.
    *   **PLC/Controller Mode Change:** A PLC is changed from `RUN` to `PROGRAM` mode outside of a maintenance window. This is a primary indicator of an attempt to modify logic.
    *   **Firmware/Logic Change:** The configuration or firmware of a PLC, RTU, or controller has been modified.
*   **2. Protocol & Behavioral Anomalies (Requires a baseline):**
    *   **Anomalous Function Codes:** A dangerous or unusual command is used (e.g., Modbus `Stop_CPU` command, DNP3 `cold_restart`).
    *   **New Communication Pathways:** A device starts communicating with another device for the first time.
    *   **Unusual Traffic Patterns:** Spikes in traffic volume (potential exfiltration/DDoS), or network beacons (a device "calling home" to a C2 server at regular intervals).
*   **3. Known Adversary TTPs (Threat-Informed Defense):**
    *   Use the **MITRE ATT&CK for ICS** framework as a guide.
    *   **Reconnaissance:** Detect network or port scans within the OT network.
    *   **Lateral Movement:** Detect use of RDP, PSExec, or stolen credentials to move between HMIs and servers.
    *   **Inhibit Response Function:** Detect malware specifically designed to interfere with safety or control functions (leads into our case study).

#### **1.3 Case Study: TRITON / TRISIS (2017)**
*   **Target:** A foreign petrochemical facility.
*   **Attacked Asset:** The Schneider Electric **Triconex Safety Instrumented System (SIS)**. The SIS is the last line of automated defense to prevent a catastrophic failure.
*   **Objective:** To reprogram the SIS controllers, likely to prevent them from functioning during a separate attack on the main control system, which could lead to a disastrous physical event (e.g., an explosion).
*   **Attack Vector:** The attackers gained access to an engineering workstation and used the legitimate Triconex programming software to inject their malicious logic into the SIS controllers.
*   **How it was Detected:** The attack was discovered by **accident**. The malware contained a bug that, on some controllers, triggered a fault condition, safely shutting the plant down. This tripped alarm was the only reason the attack was discovered before it could be used.
*   **Lessons Learned:**
    *   Adversaries are actively and specifically targeting safety systems.
    *   Relying on accidents for detection is not a strategy. Proactive detection for PLC/SIS programming activity is essential.
    *   Living-off-the-land attacks (using legitimate software for malicious ends) are very difficult to detect without behavioral monitoring.

---

### **Section 2: Proactive Threat Hunting in OT (1 Hour)**

#### **2.1 Mindset: Assume Breach**
Threat hunting is a proactive practice that assumes a sufficiently motivated attacker is already inside your network. The goal is to find them before they achieve their objectives.

#### **2.2 Hunting Methodologies**
*   **Hypothesis-Driven Hunting:** Start with a "what if" scenario and then search for the evidence.
    *   *Hypothesis:* "An attacker is using a dual-homed engineering workstation to bridge our IT and OT networks."
    *   *Hunt:* Search for devices with multiple network interface cards (NICs). Scrutinize all traffic from those devices. Look for connections to both corporate IP ranges and OT IP ranges.
*   **Crown Jewel Analysis:**
    *   Identify your most critical assets (e.g., the SIS, the primary DCS controllers, historian).
    *   Treat all activity related to these assets with suspicion. Manually review all logs, network connections, and configuration changes related to them. Look for anything even slightly out of the ordinary.

#### **2.3 What to Hunt For**
*   **Living off the Land Binaries (LotL):** Attackers using legitimate tools like `powershell.exe`, `psexec.exe`, or `rdpclip.exe` for malicious activity. Hunt for unusual parent-child process relationships (e.g., an HMI application spawning PowerShell).
*   **Unusual Remote Access:** Scrutinize all RDP, VNC, and SSH logs. Look for connections from unusual sources or at odd times.
*   **Unauthorized PLC Programming:** Are there any `*.ACD` (Rockwell) or `*.S7P` (Siemens) files on systems where they shouldn't be?

---

### **Section 3: OT Incident Response (1 Hour)**

#### **3.1 The Golden Rule: Safely Maintain Operations**
The goal of OT IR is **NOT** simply to "eradicate the threat." It is to work with engineering to return to a safe and normal operational state. Disconnecting a host without understanding the process impact could be more dangerous than the malware itself.

#### **3.2 The OT IR Team: A Multi-Disciplinary Effort**
*   **SOC Analyst / IR Lead:** The cybersecurity expert.
*   **Plant Operator / Engineer:** The process expert. They understand what the physical impact of any action will be.
*   **Safety Officer:** The authority on personnel and environmental safety.
*   **Legal & Communications:** To manage liability and public/regulatory communication.

#### **3.3 The OT IR Lifecycle (Adapted from NIST)**
*   **Preparation:** (You are here!) Having asset inventories, network diagrams, and response playbooks ready.
*   **Detection & Analysis:** The alert fires. The hunt begins.
*   **Containment:** *The most critical and nuanced phase in OT.*
    *   **Cannot "Pull the Plug":** Disconnecting a PLC could cause a valve to close, a motor to stop, or pressure to build.
    *   **Consult the Engineers:** The SOC analyst provides data; the engineer makes the risk decision.
    *   **Safe Containment Strategies:**
        *   Block the malicious IP at the zone firewall.
        *   Isolate the affected network segment if there is redundancy.
        *   Disable remote access to the affected segment.
        *   Place the physical process into a safe, manual state if necessary.
*   **Eradication & Recovery:**
    *   Removing the malware and restoring systems.
    *   This is often done during a planned maintenance window.
    *   Requires known-good backups of PLC logic and HMI configurations, which must be validated by the vendor and engineers.
*   **Post-Incident Activity:** The lessons-learned phase. Update playbooks, add new detection rules, and improve architecture.

---

### **Section 4: Practical Lab - Mock Incident Triage (0.5 Hour)**

#### **4.1 Lab Objective:**
To practice the initial analysis and decision-making process for a critical OT security alert, focusing on asking the right questions under pressure.

#### **4.2 Scenario:**
You are the on-duty analyst at the "HydroGen Power" SOC. It is 3:15 AM on a Tuesday. The following high-priority alert appears on your SIEM dashboard.

*   **Alert Name:** `CRITICAL: Unauthorized PLC Logic Modification`
*   **Source:** OT Security Platform - "Clarity"
*   **Timestamp:** `2026-01-18 03:15:12 AM`
*   **Asset:** `Turbine_PLC_01` (IP: `10.10.1.100`)
*   **Details:** The `RUN` mode of the PLC was switched to `PROGRAM` mode and then back to `RUN`. This action was initiated via S7 protocol from IP address `192.168.1.55`. The logic checksum on the PLC has changed.

#### **4.3 Lab Steps: Your Triage Process**
As a group or individually, answer the following questions to formulate your initial response.

1.  **Initial Assessment & Impact:**
    *   On a scale of 1-10, how critical is this alert? Why?
    *   What is the worst-case potential impact of this activity?
2.  **Immediate Context Gathering:**
    *   What two documents will you immediately open? (Asset Inventory, Network Diagram).
    *   What process does `Turbine_PLC_01` control?
    *   What do you know about the source IP `192.168.1.55`? Is it on your OT network? Where did it come from? (Hint: It's not a `10.x.x.x` address).
3.  **Formulating Investigative Questions:**
    *   What is the first question you ask the plant operator? (e.g., "Is there any scheduled maintenance on Turbine 1?").
    *   What logs will you check first? (Firewall logs, remote access logs).
    *   What query would you run in your security tools to learn more about the suspicious IP?
4.  **Developing Safe Containment Actions:**
    *   What is the *wrong* thing to do immediately?
    *   What are two *safe* initial containment steps you can propose to the engineering team while you investigate further? (Think about blocking traffic without taking the PLC offline).
5.  **Escalation & Communication:**
    *   Who is the first person you call at 3:15 AM?
    *   Draft a 2-3 sentence initial alert summary to send to the Head of Security.

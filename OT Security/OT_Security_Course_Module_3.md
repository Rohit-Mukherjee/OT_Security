# OT Security Course - Module 3/5
## Defending the OT Environment: Segmentation & Hardening

**Estimated Time: 4 Hours**

### **Module Objective:**
Upon completion of this module, students will be able to design a secure OT network architecture based on the Purdue model, write effective industrial firewall rules using deep packet inspection concepts, understand the role of data diodes, and apply system hardening principles to critical OT assets.

---

### **Section 1: Network Segmentation as a Core Defensive Strategy (1 Hour)**

#### **1.1 From Purdue Levels to Zones & Conduits**
*   **Recap:** The Purdue Model provides the high-level blueprint for segmentation.
*   **Formalizing the Architecture (ISA/IEC 62443 Standard):**
    *   **Zones:** A logical grouping of assets that share common security requirements. A zone has a clear border. For example, all devices in a single production line could form a zone. A Safety Instrumented System (SIS) would be in its own, highly restricted zone.
    *   **Conduits:** The defined communication pathways between zones. All communication between zones must travel through a conduit, which is where security controls (like firewalls) are enforced.
*   **Micro-segmentation:**
    *   The practice of creating small, granular zones, even within a single Purdue level. Instead of having one large "Level 2" network, you might have separate zones for each production line, each with its own firewall conduit.
    *   **Benefit:** This drastically limits an attacker's ability to move laterally. If one production line is compromised, micro-segmentation can prevent the attack from spreading to other lines.

#### **1.2 Case Study in Action: How Segmentation Could Have Limited NotPetya**
*   **Scenario (NotPetya, 2017):** A destructive wiper malware disguised as ransomware. It spread extremely fast via the EternalBlue/EternalRomance exploits (SMBv1).
*   **Industrial Impact:** Major global companies like Maersk and Merck were severely impacted, with production halting at factories worldwide. The malware spread indiscriminately from IT networks into OT networks.
*   **How Segmentation Helps:** In a well-segmented environment:
    1.  The initial IT infection would have been stopped at the IT/OT DMZ firewall because SMB traffic (port 445) should *never* be allowed from the enterprise network into the OT network.
    2.  Even if one OT zone was infected (e.g., via a compromised engineering workstation), micro-segmentation would have prevented the malware from spreading to other, isolated zones. The damage would have been contained to a much smaller area.

---

### **Section 2: Industrial Firewalls & Unidirectional Gateways (1.5 Hours)**

#### **2.1 Industrial Firewalls: The Gatekeepers**
*   **How they differ from IT Firewalls:**
    *   **Hardware:** Ruggedized for harsh environments (vibration, temperature extremes).
    *   **Protocol Intelligence:** They are "application-aware" for OT protocols. This is their most important feature.
*   **Deep Packet Inspection (DPI) for Firewall Rules:**
    *   Traditional firewalls only filter based on IP address and port (Layer 3/4). This is insufficient for OT. For example, allowing `TCP Port 502` for Modbus allows *all* Modbus communication, including potentially dangerous commands.
    *   Industrial firewalls use DPI to look inside the protocol (Layer 7). This allows for highly granular rules based on the specific OT commands being used.
*   **Example Rule Comparison:**

| **Rule Type** | **Firewall Rule** | **Security Level** |
| :--- | :--- | :--- |
| **Traditional (Bad)** | `ALLOW | SRC: ANY | DST: PLC_Network | PORT: 502` | **Very Poor.** Allows anyone to send any Modbus command to any PLC. |
| **Stateful (Better)** | `ALLOW | SRC: HMI_1 | DST: PLC_1 | PORT: 502` | **Good.** Limits access to a specific HMI-PLC pair. |
| **Industrial DPI (Best)** | `ALLOW | SRC: HMI_1 | DST: PLC_1 | PORT: 502 | DPI_RULE: Modbus Function Codes READ_ONLY` | **Excellent.** The HMI can only read data from the PLC, not write to it. It cannot execute a "Stop CPU" or "Write Program" command. |

#### **2.2 Unidirectional Gateways (Data Diodes): The One-Way Street**
*   **What they are:** Hardware-enforced one-way data transfer devices. They provide a physical air gap for network traffic.
*   **How they work:**
    *   A typical data diode has two parts: a "send" side and a "receive" side.
    *   They use fiber optics with the transmitter of the source network connected to the receiver of the destination network. The reverse path is physically disconnected (the other fiber strand is removed or the transmitter is disabled).
    *   Specialized proxy servers on either side handle the protocol communication and transfer the data across the one-way link.
*   **Critical Use Cases:**
    *   **Sending OT data to IT:** A plant historian (OT) can send its data to a corporate database (IT) for business analytics with a zero-risk of an attack flowing back from IT to OT.
    *   **Protecting Safety Systems:** A Safety Instrumented System (SIS) can report its status to the DCS/SCADA system, but nothing can send commands back to the SIS, ensuring its integrity.

---

### **Section 3: System & Application Hardening in OT (0.5 Hours)**

#### **3.1 The Principle of Least Functionality**
*   If a system doesn't need a service, port, or application to perform its dedicated function, it should be disabled or removed.
*   **Examples:**
    *   Disable web browsers on HMI terminals.
    *   Turn off File and Print Sharing if not absolutely required.
    *   Remove unnecessary software (games, office applications) from engineering workstations.

#### **3.2 Application Whitelisting**
*   A powerful security control for fixed-function systems like HMIs and SCADA servers.
*   Instead of a blacklist (trying to block known bad software), whitelisting defines a list of *all* approved applications. Anything not on the list is blocked by default.
*   This is highly effective at preventing unknown malware from executing.

#### **3.3 Implementing Secure Remote Access**
*   Uncontrolled remote access is a primary vector for attacks.
*   **The Wrong Way:** Allowing vendors to use tools like TeamViewer, VNC, or direct RDP into the control network.
*   **The Right Way:**
    1.  **Terminate in the DMZ:** All remote access sessions (VPNs) must terminate on a **Jump Server (or Bastion Host)** within the IT/OT DMZ.
    2.  **No Direct OT Access:** The vendor logs into the Jump Server, and from there, a second, controlled connection is made into the OT network.
    3.  **Multi-Factor Authentication (MFA):** All remote access must require MFA.
    4.  **Logging & Monitoring:** All sessions on the Jump Server should be recorded and logged for auditing.
    5.  **Time-Based Access:** Grant access only for the duration of the required maintenance window.

---

### **Section 4: Practical Lab - Designing a Secure Network Segment (1 Hour)**

#### **4.1 Lab Objective:**
To apply the principles of segmentation, zones, conduits, and industrial firewalling to a practical design scenario.

#### **4.2 Scenario:**
You are the security architect for "FizzPop Beverages." The company is installing a new, high-speed "Bottling Line 3." Your task is to design the network security for this new line to ensure it is isolated and secure.

*   **Assets for the New Zone:**
    *   `Bottling_PLC_03` (IP: 10.20.3.10) - Controls the bottling machinery.
    *   `Bottling_HMI_03` (IP: 10.20.3.11) - Operator interface for the line.
*   **Interacting Assets from Other Zones:**
    *   `MES_Server` (IP: 10.20.100.5, Level 3) - Manufacturing Execution System that sends recipe data (e.g., bottle size, syrup mix) to the PLC.
    *   `Supervisor_Workstation` (IP: 10.20.2.25, Level 2) - Used by the plant supervisor to monitor the status of all bottling lines.

#### **4.3 Lab Steps:**

1.  **Network Diagram (15 mins):**
    *   Draw a simple block diagram. Create a new "Zone" for Bottling Line 3. Show the existing "Level 3 Zone" (with `MES_Server`) and "Level 2 Zone" (with `Supervisor_Workstation`).
    *   Draw the firewalls (conduits) that connect these zones.

2.  **Firewall Rule Policy (30 mins):**
    *   Write a plain-English firewall policy for the conduits you've drawn. Be as specific as possible. Use the DPI-based rule format where applicable.
    *   Think about what communication is *absolutely necessary*. Deny everything else by default.

3.  **Justification (15 mins):**
    *   For each rule you create, write a brief justification.

#### **Example Solution:**

**Firewall Policy for "Bottling Line 3" Conduit**

| Rule | Source                | Destination        | Protocol / Service      | DPI Rule / Intent | Justification |
| :--- | :-------------------- | :----------------- | :---------------------- | :---------------- | :--- |
| **1**  | `MES_Server` (L3)     | `Bottling_PLC_03`  | EtherNet/IP (TCP/44818) | `CIP_WRITE` (Recipe Data Tags) | **ALLOW.** Necessary for MES to send production recipes to the PLC. Must be restricted to specific tags. |
| **2**  | `Supervisor_Workstation` (L2) | `Bottling_HMI_03` | VNC (TCP/5900)          | `(N/A)` | **ALLOW.** Allows the supervisor to remotely view the HMI for monitoring purposes. |
| **3**  | `Bottling_PLC_03`     | `Bottling_HMI_03`  | Siemens S7 (TCP/102)    | `ALL` | **ALLOW.** Necessary for the HMI to get status data from and send commands to its paired PLC within the zone. |
| **4**  | `ANY`                 | `ANY`              | `ANY`                   | `(N/A)` | **DENY & LOG.** The default deny-all rule. Catches and logs all other traffic, which is unauthorized. |

This exercise forces you to think like a security architect, balancing operational needs with security requirements and applying the modern defensive tools available for OT.

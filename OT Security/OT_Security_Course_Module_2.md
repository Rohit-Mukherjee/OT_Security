# OT Security Course - Module 2/5
## OT Network Visibility & Asset Management

**Estimated Time: 4 Hours**

### **Module Objective:**
Upon completion of this module, students will understand the critical importance of visibility in OT environments, be able to identify methods for passive asset discovery, comprehend the data gathered by OT visibility platforms, and learn how to approach vulnerability management in a way that respects OT constraints.

---

### **Section 1: The Challenge of OT Visibility (1 Hour)**

#### **1.1 Why Visibility is Harder in OT**
*   **Legacy Devices:** Many OT devices are decades old, pre-dating modern networking, let alone security. They often lack the capability for agents or even basic logging.
*   **Proprietary Protocols:** Thousands of unique, vendor-specific, or industry-specific protocols (beyond Modbus, DNP3, S7). Standard IT tools often can't parse or understand them.
*   **No Agents:** Installing software agents on PLCs, RTUs, or older HMIs is typically not possible due to:
    *   Real-time operating system (RTOS) requirements.
    *   Limited processing power/memory.
    *   Vendor warranties being voided.
    *   Risk of process interruption (blue screen of death in a power plant is bad).
*   **Impact of Active Scanning:** Traditional IT vulnerability scanners or network discovery tools (like Nmap) can crash or disrupt sensitive OT devices. Active scanning is often a no-go.
*   **The "Dark Side" of OT:**
    *   **Unknown Devices:** Unmanaged switches, unauthorized devices plugged in by contractors.
    *   **Unmanaged Connections:** Ad-hoc network links, unauthorized remote access.
    *   **Vendor Access:** Uncontrolled or poorly managed vendor access often introduces unknown elements.

#### **1.2 The Importance of Comprehensive Asset Inventory**
*   **Fundamental Security Principle:** You cannot protect what you cannot see or don't know exists.
*   **Compliance:** Meeting regulatory requirements (e.g., NERC CIP, ISA/IEC 62443).
*   **Risk Assessment:** Understanding which assets are critical, their vulnerabilities, and their impact.
*   **Incident Response:** Knowing what's on the network is crucial for containment and recovery.
*   **Operational Efficiency:** Understanding network dependencies and potential points of failure.

---

### **Section 2: Passive Asset Discovery & Network Monitoring (1.5 Hours)**

#### **2.1 Passive Monitoring Techniques**
*   **The Core Principle:** Listen to network traffic without actively interacting with devices. This avoids disrupting sensitive OT processes.
*   **Network TAPs (Test Access Points):** Hardware devices that create a copy of network traffic for monitoring, ensuring no impact on the live network.
*   **SPAN (Switched Port Analyzer) / Port Mirroring:** A feature on managed switches that copies traffic from one or more ports to a dedicated monitoring port.
    *   **Considerations:** Can introduce latency or drop packets under heavy load, less reliable than TAPs. Placement is key (core switches, specific industrial zones).
*   **Deep Packet Inspection (DPI) for OT Protocols:**
    *   Specialized OT security platforms use DPI engines to analyze industrial protocols (Modbus, DNP3, S7comm, EtherNet/IP, etc.).
    *   They extract metadata about devices (vendor, model, firmware, serial number), communication patterns, and commands being executed.

#### **2.2 OT Asset Discovery & Visibility Platforms**
*   **Functionality:** These platforms are purpose-built for OT environments. Examples include Claroty, Dragos, Nozomi Networks, Tenable.ot (formerly Indegy).
*   **Key Information Gathered:**
    *   **Asset Details:** Device type (PLC, HMI, RTU, Workstation), manufacturer, model, firmware version, operating system, IP/MAC addresses, serial numbers, rack/slot information.
    *   **Communication Patterns:** Who is talking to whom? What protocols are being used? How often?
    *   **Configuration Changes:** Detection of unauthorized (or undocumented) changes to PLC programs or device configurations.
    *   **Vulnerability Identification:** Cross-referencing identified assets/firmware with public vulnerability databases (CVEs).
    *   **Baseline Deviation:** Learning "normal" behavior and alerting on anomalies (e.g., a PLC communicating with an external IP, a new Modbus function code used).
*   **Deployment:** Typically deployed with sensors in each OT zone (Level 1, 2, 3) reporting to a central management console, often hosted in the DMZ or IT network.

---

### **Section 3: OT Vulnerability Management (1 Hour)**

#### **3.1 Unique Challenges of Vulnerability Management in OT**
*   **Inability to Patch:** Many OT devices cannot be patched due to:
    *   System stability requirements (cannot tolerate reboots).
    *   Lack of vendor support for newer OS/patches.
    *   Validation requirements (patches need extensive testing against the physical process).
    *   Regulatory restrictions (e.g., change management freezes).
*   **Vendor Dependency:** Reliance on equipment manufacturers for fixes, which can be slow or non-existent for older gear.
*   **Legacy Operating Systems:** Many HMIs and engineering workstations still run Windows XP or older Linux versions, which are end-of-life and highly vulnerable.
*   **Downtime is NOT an Option:** Scheduled downtime is expensive and limited, making patching windows rare.

#### **3.2 Risk-Based Approach & Compensating Controls**
*   **Prioritization:** Instead of just CVE scores, vulnerabilities must be prioritized based on:
    *   **Impact on Safety:** Could this lead to physical harm or environmental damage?
    *   **Impact on Availability:** Could this disrupt the critical process?
    *   **Exploitability:** How easy is it to exploit? Is there known malware?
    *   **Asset Criticality:** How critical is the affected device to the overall process?
*   **Compensating Controls:** When patching is not feasible, implement alternative security measures to reduce the risk:
    *   **Network Segmentation:** Isolate the vulnerable device within a smaller network segment.
    *   **Strict Access Control:** Limit who can access the device (physical and logical).
    *   **Monitoring & Alerting:** Implement enhanced monitoring for any activity involving the vulnerable device.
    *   **Application Whitelisting:** Allow only approved programs to run on vulnerable HMIs/workstations.
    *   **Unidirectional Gateways (Data Diodes):** For highly critical systems, ensure data flows only out of the segment.

#### **3.3 Secure Configuration Management**
*   Ensuring that all OT devices, where possible, are configured securely from deployment (e.g., changing default passwords, disabling unnecessary services, limiting network access).

---

### **Section 4: Practical Lab - Analyzing a Mock OT Asset Inventory & Risks (0.5 Hour)**

#### **4.1 Lab Objective:**
To interpret data from a typical OT asset inventory report, identify potential security risks, and propose practical compensating controls.

#### **4.2 Required Materials:**
*   **Mock OT Asset Inventory Report (Provided below).**
    *   *(Instructor note: This would typically be a CSV, Excel sheet, or a screenshot from an OT visibility platform. For this course, the content will be described directly for analysis).*

#### **4.3 Mock Report Scenario:**
You are a new OT security analyst for "HydroGen Power," a medium-sized hydroelectric power plant. Your first task is to review a recent passive scan report from an OT visibility platform.

**Partial Mock Asset Inventory Report - HydroGen Power Plant (Excerpt):**

| Asset Name         | IP Address  | MAC Address      | Type          | Vendor        | Model/OS           | Firmware Version | Discovered Vulnerabilities (CVEs) | Last Seen            | Connected To (Directly) |
| :----------------- | :---------- | :--------------- | :------------ | :------------ | :----------------- | :--------------- | :-------------------------------- | :------------------- | :---------------------- |
| **Turbine_PLC_01** | 10.10.1.100 | 00:1A:2B:3C:4D:5E | PLC           | Siemens       | S7-300             | V3.2             | CVE-2015-xxxx (Hardcoded Creds)   | 2026-01-15 10:30     | Turbine_HMI_01, Control_Server_01 |
| **Turbine_HMI_01** | 10.10.1.101 | 00:1A:2B:3C:4D:5F | HMI           | Siemens       | Simatic IPC        | Windows XP SP3   | CVE-2017-xxxx (SMB Vulnerability) | 2026-01-15 10:30     | Turbine_PLC_01, Engineering_WS_01 |
| **SCADA_Server_01**| 10.10.2.10  | 00:1B:2C:3D:4E:5F | Server        | Dell          | Windows Server 2008 R2 | N/A              | CVE-2019-xxxx (RDP Vulnerability) | 2026-01-15 10:35     | Historian_Server_01, Engineering_WS_01, IT_DMZ_Firewall |
| **Historian_Server_01** | 10.10.2.20  | 00:1B:2C:3D:4E:6A | Server        | HP            | CentOS 6           | N/A              | CVE-2016-xxxx (Old Apache)        | 2026-01-15 10:35     | SCADA_Server_01, IT_DMZ_Firewall |
| **Engineering_WS_01** | 10.10.1.102 | 00:1C:2D:3E:4F:5A | Workstation   | Custom Build  | Windows 7 Pro      | N/A              | CVE-2017-xxxx (SMB Vulnerability), Unpatched | 2026-01-15 10:20     | Turbine_HMI_01, SCADA_Server_01, USB_Drive_Inserted |
| **Flow_Sensor_03** | 10.10.0.50  | 00:2A:3B:4C:5D:6E | Sensor        | Endress+Hauser | Promass 83          | V1.0             | (None known)                      | 2026-01-15 10:25     | Turbine_PLC_01 |
| **Unknown_Device_01** | 10.10.1.200 | 00:00:00:00:00:00 | Unidentified  | Unknown       | Unknown            | Unknown          | Unknown                           | 2026-01-15 10:15     | Turbine_HMI_01 |
| **Remote_Access_VPN** | 10.10.3.1   | 00:1E:2F:3A:4B:5C | VPN Concentrator | Cisco         | IOS XE             | V16.x            | (None known)                      | 2026-01-15 10:30     | IT_DMZ_Firewall |
| **Turbine_PLC_02** | 10.10.1.103 | 00:1A:2B:3C:4D:6F | PLC           | Siemens       | S7-300             | V3.2             | CVE-2015-xxxx (Hardcoded Creds)   | 2026-01-15 10:30     | Turbine_HMI_02, Control_Server_01 |
| **Turbine_HMI_02** | 10.10.1.104 | 00:1A:2B:3C:4D:7A | HMI           | Siemens       | Simatic IPC        | Windows XP SP3   | CVE-2017-xxxx (SMB Vulnerability) | 2026-01-15 10:30     | Turbine_PLC_02, Engineering_WS_01 |

#### **4.4 Lab Steps:**

1.  **Review the Report:** Carefully examine each entry in the table.
2.  **Identify Critical Assets:** Which assets are most crucial for the plant's safe and continuous operation?
3.  **Identify High-Risk Vulnerabilities:** Which discovered vulnerabilities pose the most immediate threat, especially considering the asset's criticality?
4.  **Analyze Anomalies/Gaps:**
    *   What is "Unknown_Device_01"? Why is it unidentified?
    *   "Engineering_WS_01" shows "USB_Drive_Inserted" – what's the implication?
    *   Note the "Connected To (Directly)" column. Are there any unexpected connections?
5.  **Propose Mitigation & Compensating Controls:** For the top 3-5 identified risks, formulate specific, actionable recommendations, differentiating between patching (if feasible) and compensating controls.

#### **Example Analysis Point:**
*   **Risk:** `Turbine_HMI_01` and `Turbine_HMI_02` are running `Windows XP SP3` with a `CVE-2017-xxxx (SMB Vulnerability)`. This OS is end-of-life and highly vulnerable.
*   **Mitigation/Compensating Control:** Upgrading the OS may not be possible due to application compatibility. Therefore, implement:
    1.  **Network Segmentation:** Place HMIs in a dedicated VLAN/subnet with strict firewall rules, limiting connections only to necessary PLCs and SCADA servers.
    2.  **Application Whitelisting:** Implement a whitelisting solution (e.g., AppLocker) to ensure only approved applications can run on the HMI.
    3.  **Disable SMBv1:** If possible and compatible, disable SMBv1 on these systems to mitigate the specific vulnerability.
    4.  **Strict USB Control:** Implement technical and administrative controls to prevent unauthorized USB device usage on engineering workstations and HMIs.

By completing this lab, you'll practice how to turn raw visibility data into actionable security intelligence for an OT environment.

# OT Security Course - Module 1/5
## Foundations of OT Security & The Industrial Threat Landscape

**Estimated Time: 4 Hours**

### **Module Objective:**
Upon completion of this module, students will be able to articulate the fundamental differences between IT and OT environments, describe the hierarchical structure of an industrial network using the Purdue Model, identify core OT components and protocols, and analyze the attack vectors and impacts of seminal cyber-physical incidents.

---

### **Section 1: Introduction to the Industrial World (1 Hour)**

#### **1.1 What is Operational Technology (OT)?**
*   **Definition:** OT is the hardware and software dedicated to detecting or causing a change in physical processes through the direct monitoring and/or control of physical devices such as valves, pumps, etc.
*   **Key Components (The "Crown Jewels"):**
    *   **Programmable Logic Controller (PLC):** A ruggedized industrial computer that is the "hands" of the operation. It takes instructions and directly controls a machine or process (e.g., "keep temperature at 95°C," "spin turbine at 3600 RPM").
    *   **Human-Machine Interface (HMI):** A graphical dashboard that allows a human operator to observe the status of a process and issue commands (e.g., a screen in a control room showing tank levels and temperatures).
    *   **Supervisory Control and Data Acquisition (SCADA):** A system for high-level process supervision. It gathers data from and manages multiple pieces of equipment (PLCs, RTUs) over a large area, like a pipeline or power grid.
    *   **Distributed Control System (DCS):** A system that is process-oriented and controls an entire site or plant, often with thousands of I/O points. It's a self-contained system with a central supervisory control loop.
    *   **Historian:** A server with a time-series database that collects and stores vast amounts of data from the OT environment for process analysis and troubleshooting.

#### **1.2 The Critical Mindset Shift: IT vs. OT Priorities**
*   **Review IT Priorities:**
    1.  **Confidentiality:** Is the data secret?
    2.  **Integrity:** Has the data been tampered with?
    3.  **Availability:** Can I access the data?
*   **Introduce OT Priorities:**
    1.  **Safety & Availability:** Is the process running, and is it running safely for people and the environment? Any deviation or downtime can have catastrophic physical consequences. The system *must* be available.
    2.  **Integrity:** Are the commands and sensor readings correct? A false temperature reading could lead to an explosion. A malicious "open valve" command is a disaster.
    3.  **Confidentiality:** Is the process recipe a secret? This is important, but a distant third to safety and integrity.

*   **Group Discussion:** Why can't we just install antivirus and a firewall on a PLC? (Answers: Real-time OS intolerance for latency, vendor warranty voided, potential for process interruption, lack of processing power).

---

### **Section 2: The Architecture and Insecurities of Control Systems (1 Hour)**

#### **2.1 Deep Dive: The Purdue Model of Industrial Control**
*   A hierarchical model for segmenting the layers of an industrial network. The primary security goal is to create "air gaps" or tightly controlled conduits between the levels.
    *   **Level 5: Enterprise Network (IT)** - Corporate email, user PCs, ERP systems.
    *   **Level 4: Business Logistics (IT)** - Servers managing business functions that support the plant.
    *   --- **The DMZ: The Critical Boundary** --- This is where IT and OT must securely exchange data.

#### **2.1.1 Deeper Dive: The IT/OT Demilitarized Zone (DMZ)**
*   **Purpose:** The IT/OT DMZ acts as a secure buffer zone between the less secure IT enterprise network (Levels 4-5) and the highly sensitive OT control network (Levels 0-3). Its primary function is to allow necessary data exchange while preventing direct communication between IT and OT, thereby limiting the attack surface.
*   **Key Design Principles:**
    *   **No Direct Routing:** Traffic should never route directly from the IT network into the OT network, or vice versa, bypassing the DMZ.
    *   **Layered Security:** Typically involves at least two firewalls (one facing IT, one facing OT) with strict, explicit allow rules.
    *   **Controlled Data Flow:** Only necessary protocols and specific data flows are permitted through the DMZ.
    *   **Protocol Conversion/Proxies:** Often hosts servers that convert IT protocols to OT protocols (e.g., database gateways, OPC UA proxies) or act as application-layer proxies.
    *   **Intermediate Processing:** Data exchanged between IT and OT often undergoes processing or mirroring within the DMZ to prevent direct access to sensitive systems.
*   **Common Components within the IT/OT DMZ:**
    *   **Firewalls:** Typically a pair of industrial firewalls, enforcing policies at both the IT and OT interfaces.
    *   **Data Historian Mirror:** A mirror of the OT historian database, allowing IT systems to access process data without directly querying the OT historian.
    *   **Patch Management Servers:** Servers used to securely distribute patches and updates to OT assets from the IT side, after thorough testing.
    *   **Antivirus Update Servers:** For distributing antivirus signatures to OT endpoints that can run AV.
    *   **Jump Servers (Bastion Hosts):** Hardened servers used as a controlled gateway for administrators and vendors needing remote access to the OT network. All access is logged and monitored.
    *   **Application Gateways/Proxies:** For specific applications that need to communicate across the boundary (e.g., Manufacturing Execution Systems - MES).
    *   **Remote Access Solutions:** Secure VPN concentrators or equivalent for external access, often terminating on a jump server.
*   **Security Considerations:**
    *   A compromise of the DMZ should *not* lead to a direct compromise of the OT network (or IT network).
    *   Requires continuous monitoring and auditing of traffic, configurations, and logs.
    *   All devices within the DMZ must be highly hardened and follow strict security baselines.

    *   **Level 2: Area Supervisory Control** - The HMIs and SCADA servers that operators use to manage a specific process area.
    *   **Level 1: Basic Control** - The PLCs, RTUs, and intelligent controllers executing commands.
    *   **Level 0: The Process** - The physical motors, valves, sensors, and actuators.

#### **2.2 Insecure by Design: An Introduction to OT Protocols**
*   **Background:** Many OT protocols were designed decades ago for isolated, trusted networks. They were built for efficiency and reliability, not security.
*   **Example: Modbus**
    *   One of the oldest and most common protocols.
    *   **No Encryption:** All commands and data are sent in cleartext.
    *   **No Authentication:** Any device on the network can send a valid Modbus command to a PLC. The PLC has no way of verifying who sent it.
    *   **No Integrity Checks:** It's possible to intercept and modify commands in transit.

---

### **Section 3: Seminal Case Studies (1 Hour)**

#### **3.1 Case Study: Stuxnet (2010)**
*   **Target:** Iranian Nuclear Program (Natanz facility).
*   **Objective:** Physically damage uranium enrichment centrifuges.
*   **Attack Vector:**
    1.  **Infection:** Started on IT networks of third-party contractors.
    2.  **Propagation:** Used multiple Windows zero-day exploits and spread via USB drives to cross the "air gap" into the OT network.
    3.  **Discovery:** Once on the OT network, it looked for a very specific Siemens Step7 PLC configuration. If not found, it did nothing.
    4.  **Attack:** If found, it subtly modified the PLC's code to dangerously speed up and slow down the centrifuges, causing them to tear themselves apart.
    5.  **Deception:** While the attack was underway, it replayed "normal" sensor readings back to the HMI, so operators were completely blind to the destruction.
*   **Impact & Lessons:** The first publicly known malware designed to cause specific physical destruction. It proved that code could cross an air gap and destroy equipment.

#### **3.2 Case Study: BlackEnergy3 & The Ukrainian Grid Attack (2015)**
*   **Target:** Ukrainian Power Distribution Companies.
*   **Objective:** Cause a widespread power outage.
*   **Attack Vector:**
    1.  **Infection:** Spear phishing emails with malicious Microsoft Office documents sent to IT staff.
    2.  **Credential Theft:** Stole credentials to gain access to the corporate VPN.
    3.  **Pivot to OT:** Used the VPN to move from the IT network into the SCADA network.
    4.  **Attack:** From their remote position, the attackers took direct control of the HMIs and SCADA servers. They systematically opened breakers at multiple substations, cutting power to over 230,000 people.
    5.  **Denial of Service:** They also launched a DDoS attack on the call centers to prevent customers from reporting the outage and flashed the firmware on key network devices to make recovery more difficult.
*   **Impact & Lessons:** The first confirmed cyberattack to cause a blackout. It demonstrated how a breach on the IT side could be used as a direct launchpad for a devastating OT attack.

---

### **Section 4: Practical Lab - Introduction to OT Network Analysis (1 Hour)**

#### **4.1 Lab Objective**
To gain hands-on experience by identifying and analyzing a common OT protocol within a sample network packet capture (`.pcap`).

#### **4.2 Required Tools**
*   **Wireshark:** The industry-standard network protocol analyzer. (Free to download at wireshark.org).
*   **Sample PCAP file:** Search for a public "modbus_example.pcapng" or "s7_traffic.pcapng" file online. Many security researchers and universities provide these for training. *(Instructor note: You will need to provide this file to the students).*

#### **4.3 Lab Steps**
1.  **Installation:** Install Wireshark on your machine.
2.  **Open the Capture:** Launch Wireshark and open your sample `.pcapng` file (`File -> Open`).
3.  **Initial Analysis:** You will see a stream of network packets. It might look overwhelming. Let's filter it.
4.  **Filtering for Modbus:** In the "Apply a display filter" bar at the top, type `modbus` and press Enter. Wireshark will now only show packets containing the Modbus protocol.
5.  **Examine the Packets:**
    *   Look at the "Info" column. You will see human-readable descriptions of the commands, like `Read Coils`, `Read Holding Registers`, or **`Write Single Coil`**.
    *   Click on a `Read` request packet. In the packet details pane below, expand the "Modbus" section. You can see the **Function Code** (e.g., `1` for Read Coils), the starting address, and the quantity of registers to read.
    *   Now click on the corresponding response packet. In the details, you can see the data that was returned from the PLC.
6.  **Challenge:**
    *   Find a **`Write`** command in the packet capture (e.g., `Write Single Coil` or `Write Single Register`).
    *   Analyze the packet details. What is the value being written?
    *   **Think:** If you were an attacker, how could you use this knowledge? What would happen if you sent your own `Write` command to turn off a critical pump or change a temperature setpoint?

*This simple exercise demonstrates the fundamental insecurity of these protocols. An attacker on the network can see every command and every response in cleartext and can inject their own commands with no authentication required.*

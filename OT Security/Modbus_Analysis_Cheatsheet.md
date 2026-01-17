# Modbus Analysis Cheatsheet

This cheatsheet provides a quick reference for analyzing Modbus traffic in PCAP files to identify suspicious or malicious activity.

## Modbus Basics

Modbus is a serial communication protocol developed by Modicon (now Schneider Electric) in 1979. It is a de facto standard communication protocol for industrial electronic devices.

**Key Characteristics:**
*   **Client/Server (Master/Slave) Architecture:** A Modbus Master (Client) initiates requests to a Modbus Slave (Server).
*   **Function Codes:** Commands that specify the action to be performed.
*   **Data Types:** Coils (single bit, read/write), Discrete Inputs (single bit, read-only), Input Registers (16-bit, read-only), and Holding Registers (16-bit, read/write).
*   **No built-in security:** No authentication or encryption.

### Common Function Codes

| Function Code | Description                  | Type        | Malicious Potential                               |
|---------------|------------------------------|-------------|---------------------------------------------------|
| 1             | Read Coils                   | Read        | Information gathering                             |
| 2             | Read Discrete Inputs         | Read        | Information gathering                             |
| 3             | Read Holding Registers       | Read        | Information gathering                             |
| 4             | Read Input Registers         | Read        | Information gathering                             |
| 5             | Write Single Coil            | Write       | Manipulate a single binary state (e.g., On/Off)   |
| 6             | Write Single Register        | Write       | Change a single process parameter (e.g., setpoint)|
| 8             | Diagnostics                  | Diagnostic  | Can be used for reconnaissance or to cause errors |
| 15            | Write Multiple Coils         | Write       | Manipulate multiple binary states                 |
| 16            | Write Multiple Registers     | Write       | Change multiple process parameters, alter firmware|
| 22            | Mask Write Register          | Write       | Modify a register based on a mask               |
| 43            | Read Device Identification   | Read        | Reconnaissance (vendor, model, firmware version)  |
| 90            | Stop CPU / Stop PLC          | Diagnostic  | Denial of Service                                 |

## Malicious Indicators

*   **Anomalous Function Codes:** Use of dangerous or unusual function codes (e.g., Stop CPU, Write Program).
*   **Unauthorized Master:** A new or unrecognized IP address acting as a Modbus Master.
*   **Excessive Polling:** A master polling slaves at an unusually high rate.
*   **Writing to Critical Registers:** Attempts to write to registers that control critical processes or safety systems.
*   **Scanning Behavior:** A master sequentially polling for non-existent slave devices or registers.
*   **Unexpected Communication:** Communication between devices that do not normally interact.
*   **Mismatched Request/Response:** Mismatched transaction IDs or other inconsistencies.

## Wireshark Filters

| Filter                             | Description                                                               |
|------------------------------------|---------------------------------------------------------------------------|
| `modbus`                           | Show all Modbus traffic.                                                  |
| `modbus.func_code == <value>`      | Filter by a specific function code (e.g., `modbus.func_code == 16`).      |
| `modbus.func_code >= 5`            | Show all write commands.                                                  |
| `modbus.unit_id == <value>`        | Filter by a specific slave ID.                                            |
| `modbus.reference_num == <value>`  | Filter by a specific register address.                                    |
| `modbus.request_frame`             | Show only Modbus requests.                                                |
| `modbus.response_frame`            | Show only Modbus responses.                                               |
| `ip.addr == <ip_address> && modbus`| Show Modbus traffic to/from a specific IP address.                        |

## Tshark Commands

**Basic Analysis**

*   **Read a PCAP and display Modbus traffic:**
    ```bash
    tshark -r <file.pcap> -Y "modbus"
    ```

*   **Extract specific Modbus fields:**
    ```bash
    tshark -r <file.pcap> -Y "modbus" -T fields -e frame.number -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num -e modbus.reg_val_16
    ```

**Detecting Malicious Activity**

*   **Find all unique Modbus Masters (Clients):**
    ```bash
    tshark -r <file.pcap> -Y "modbus.request_frame" -T fields -e ip.src | sort -u
    ```

*   **Find all unique Modbus Slaves (Servers):**
    ```bash
    tshark -r <file.pcap> -Y "modbus.response_frame" -T fields -e ip.src | sort -u
    ```

*   **Summarize function codes used:**
    ```bash
    tshark -r <file.pcap> -Y "modbus" -T fields -e modbus.func_code | sort | uniq -c | sort -nr
    ```

*   **Identify devices using dangerous function codes (e.g., 90 - Stop CPU):**
    ```bash
    tshark -r <file.pcap> -Y "modbus.func_code == 90" -T fields -e frame.number -e ip.src -e ip.dst
    ```

*   **Identify all write commands:**
    ```bash
    tshark -r <file.pcap> -Y "modbus.func_code >= 5 && modbus.func_code != 8 && modbus.func_code != 43" -T fields -e frame.number -e ip.src -e ip.dst -e modbus.func_code
    ```

*   **Extract written values (for single and multiple register writes):**
    ```bash
    tshark -r <file.pcap> -Y "modbus.func_code == 6 || modbus.func_code == 16" -T fields -e frame.number -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num -e modbus.reg_val_16
    ```

*   **Look for scanning behavior (errors indicating non-existent slaves/registers):**
    ```bash
    tshark -r <file.pcap> -Y "modbus.exception_code" -T fields -e frame.number -e ip.src -e ip.dst -e modbus.exception_code
    ```
    *Common Exception Codes:*
        *   `1`: Illegal Function
        *   `2`: Illegal Data Address
        *   `3`: Illegal Data Value
        *   `4`: Slave Device Failure

*   **Create a conversation summary to identify unusual communication patterns:**
    ```bash
    tshark -r <file.pcap> -q -z conv,tcp
    ```

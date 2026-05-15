

This project is a high-performance, multi-threaded **Network Port Scanner** designed to provide comprehensive insights into a target's security posture. Built using Python, it goes beyond simple connectivity checks by integrating service identification, OS fingerprinting, and risk assessment into a single, streamlined tool.

The scanner leverages concurrency to handle large port ranges efficiently, while providing a professional, color-coded CLI interface for real-time monitoring and "live attack insights."

---

## 🚀 Core Features

*   **Dual-Directional Resolution:** Seamlessly converts Domain Names to IP addresses (and vice versa) using the DNS protocol.
*   **Flexible Scan Profiles:**
    *   **Quick Scan:** Targets well-known ports (0–1024) for rapid assessment.
    *   **Full Scan:** Exhaustive audit of all 65,535 available ports.
    *   **Custom Scan:** Allows users to define specific port ranges based on their needs.
*   **Deep Packet Inspection:**
    *   **Banner Grabbing:** Retrieves service banners to identify software versions.
    *   **Protocol Mapping:** Identifies common services (e.g., HTTP on 80, SSH on 22) and flags uncommon configurations.
    *   **OS Fingerprinting:** Analyzes responses to estimate the host's operating system.
*   **Intelligent Reporting:**
    *   **Risk Assessment:** Automatically categorizes the system’s vulnerability level (Low, Medium, or High) based on open ports.
    *   **Security Summary:** Generates an end-of-scan insight report regarding the system's security surface.
    *   **Export Functionality:** Results can be saved to a local file for further audit and documentation.
*   **Performance & UI:**
    *   **Live Attack Insights:** Displays real-time data during the scan process.
    *   **Execution Metrics:** Tracks and displays the total time taken to complete the scan.
    *   **Professional CLI:** Utilizes `colorama` for a clean, readable, and professional-grade terminal output.

---

## 🛠️ Technical Module Breakdown

The project is built on several key Python libraries, each serving a critical role in the scanner's architecture:

| Module | Purpose in this Project |
| :--- | :--- |
| `socket` | The backbone of the project; used to create network connections, perform DNS lookups, and grab service banners. |
| `concurrent.futures` | Implements a `ThreadPoolExecutor` to perform hundreds of port checks simultaneously, significantly reducing scan time. |
| `time` | Used to calculate the delta between the start and end of the scan for performance metrics. |
| `colorama` | Provides cross-platform support for ANSI escape character sequences, allowing for green (open), red (closed), and yellow (warning) output. |

### 🔍 Spotlight: `socket` Implementation
The `socket` module is the primary tool used for the scanning logic. In this project, it is used to attempt a "three-way handshake" via `socket.connect_ex()`. 

Unlike a standard connection attempt, `connect_ex` returns an error indicator rather than raising an exception:
*   A return value of `0` indicates the port is **open**.
*   Any other return value suggests the port is **closed or filtered**.

Additionally, `socket.gethostbyname()` and `socket.gethostbyaddr()` are utilized to handle the DNS resolution features, ensuring the user can target either a URL or a raw IP.

---

## 💻 How to Use

1.  **Input Target:** Enter the Domain or IP Address.
2.  **Select Mode:** Choose between Quick, Full, or Custom ranges.
3.  **Analyze:** Watch the live insights as the scanner identifies open ports, grabs banners, and assesses risk levels.
4.  **Export:** Save the final summary and port list to a `.txt` file for your records.

```

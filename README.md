## Team Contributions
| Member | Responsibility |
| :--- | :--- |
| **Li Xuan** | WiFi Protocol & Main Integration |
| **Adli** | BLE Protocol & Main Integration |
| **Swathi** | Gateway Development |
| **Guo Wei** | Server Management & Path Analysis |
| **Srusthi** | Dashboard Development |

> **Note:** Final system testing was conducted on-site over 3 days with all team members present.

---

## Technical Evolution & Hardware Pivot

### Initial Prototype: Arduino Maker Uno
Our original design aimed to implement a **tri-protocol mesh network** (WiFi, BLE, and LoRa). However, we encountered a hardware limitation: the **Arduino Maker Uno** does not support native Bluetooth communication, making a true mesh network infeasible on that platform.

### System Migration: Maker Pi Pico
We migrated the system to the **Maker Pi Pico** to leverage its support for **MicroPython**. To integrate LoRa, we implemented a **"LoRa-Arduino Bridge"**:
* **Mechanism:** Flashed bridge code to the LoRa board to act as a translator.
* **Interface:** Used **Serial communication** to allow the Python mesh algorithm to send/receive LoRa messages.

### Final Constraints & Resolution
Despite the successful bridge, the Maker Pi Pico lacked the **GPIO compatibility** and **power output** (voltage) required to drive the LoRa board reliably. Using external power banks posed a high risk of circuit failure.

**Final Decision:** LoRa was de-scoped. The final prototype successfully operates as a **dual-protocol mesh network (WiFi + BLE)**.

---

## Key Features & Security

### Compare & Apply Logic
Initially, the system was designed only to **view and compare** protocol modes. We improved this logic to **Compare & Apply**, allowing the system to not only analyze performance but actively switch or apply settings based on real-time data.

### Security Architecture
We explored a unified security layer for both protocols; however, during testing, we found that a "one-size-fits-all" approach was unstable.
* **Current Implementation:** Each protocol (WiFi and BLE) runs its own **optimized security configuration**, ensuring robust protection tailored to the specific requirements of each communication standard.



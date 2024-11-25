# ARP Poisoning and Man-in-the-Middle (MITM) Attack Simulation

## Project Overview

This project demonstrates ARP poisoning, a technique used to execute Man-in-the-Middle (MITM) attacks. It highlights vulnerabilities in the Address Resolution Protocol (ARP), enabling the interception, inspection, modification, or blocking of network traffic. By exploiting these vulnerabilities, the attacker manipulates the target's ARP cache, rerouting traffic through the attacker's machine.

The goal of this project is to showcase the ease with which ARP poisoning can compromise network communication and emphasize the importance of implementing detection mechanisms and network encryption to enhance data integrity and privacy.

## Features

- **ARP Poisoning Simulation**: Exploits ARP vulnerabilities to poison the target’s ARP cache.
- **Traffic Interception and Modification**: Enables inspection and manipulation of redirected traffic.
- **Detection and Prevention Insights**: Highlights methods to detect and mitigate ARP spoofing attacks.

---

## Prerequisites

Before running the program, ensure you have the following:

- A Linux-based operating system with root privileges.
- GCC (C Compiler) installed.
- Networking tools like `arp` and packet analysis tools such as Wireshark.
- Two virtual machines on a NAT-configured network for testing purposes.

---

## Setup and Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-repo-link
    cd your-repo-directory
    ```

2. Compile the program:
    ```bash
    gcc -o arp arp.c
    ```

3. Prepare the testing environment:
    - Set up two virtual machines on a NAT-configured network.
    - Ensure the host machine acts as the gateway.

---

## Running the Program

Run the ARP poisoning simulation using the following command:

```bash
sudo ./arp <network_interface> <target_mac> <target_ip>

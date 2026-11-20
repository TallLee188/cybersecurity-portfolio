# Project 1: Isolated Virtual Lab Setup & Nmap Service Scan

> **Authorization & Scope Statement:** All network configuration and scanning activities documented below were performed strictly on self-owned virtual machines inside an isolated Host-only subnet (`192.168.56.0/24`).

## 1. Objective

The objective of this project was to build a safely isolated virtual penetration testing lab and conduct a non-intrusive service and version enumeration scan (`nmap -sV`) against a deliberately vulnerable target. The goal was to verify network isolation before testing, map exposed TCP services, and evaluate the security impact of outdated software versions.

## 2. Environment and Tools Used

* **Hypervisor:** VMware Workstation (Windows 11 host)
* **Attacker VM:** Kali Linux (`192.168.56.129/24`, 2 GB RAM, Host-only adapter)
* **Target VM:** Metasploitable 2 (`192.168.56.128/24`, 512 MB RAM, Host-only adapter)
* **Tools:** `ip route`, `ping`, Nmap 7.99

## 3. Method (Step-by-Step)

1. **Configure Host-Only Networking:** Assigned both Kali Linux and Metasploitable 2 to VMware's Host-only virtual network and removed an unnecessary second network adapter from Metasploitable 2 to prevent unintended external connectivity.
2. **Verify Routing Tables:** Executed `ip route` on both virtual machines to confirm that only the local `192.168.56.0/24` subnet existed with no default gateway to the internet.
3. **Verify Connectivity & Isolation:**
   * Tested internal reachability from Kali to Metasploitable 2: `ping -c 4 192.168.56.128` (0% packet loss).
   * Tested external isolation from Kali: `ping -c 4 1.1.1.1` (returned `Network is unreachable`).
4. **Execute Service & Version Scan:** Ran `nmap -sV 192.168.56.128` from Kali Linux to identify open TCP ports, running services, and software versions without attempting active exploitation.

## 4. Results and Evidence

The Nmap scan completed in 57.00 seconds and identified **23 open TCP ports** on `192.168.56.128`. Key findings included:

| Port | Service | Detected Version | Key Security Risk |
| :--- | :--- | :--- | :--- |
| `21/tcp` | FTP | `vsftpd 2.3.4` | Contains the well-known 2011 smiley-face (`:)`) backdoor opening a root shell on port 6200. |
| `22/tcp` | SSH | `OpenSSH 4.7p1` | Severely outdated SSH daemon with known vulnerabilities. |
| `23/tcp` | Telnet | `Linux telnetd` | Transmits credentials and session traffic in cleartext. |
| `80/tcp` | HTTP | `Apache httpd 2.2.8` | End-of-life web server version exposed on the network. |
| `139, 445/tcp` | SMB | `Samba smbd 3.X - 4.X` | Legacy file-sharing service susceptible to remote exploitation. |
| `1524/tcp` | Bindshell | `Metasploitable root shell` | Direct unauthenticated root shell exposed on the network. |
| `3306, 5432/tcp` | Database | `MySQL 5.0.51a` / `PostgreSQL 8.3` | Database services directly exposed instead of bound to localhost. |

### Troubleshooting Record
* **Issue:** Running `ping -c 192.168.56.128` returned `ping: invalid argument: '192.168.56.128'`.
* **Diagnosis & Fix:** The `-c` flag requires a numeric packet count. Correcting the command to `ping -c 4 192.168.56.128` resolved the error and confirmed 4/4 replies.

### Supporting Evidence
Sanitised lab screenshots are stored in the [`evidence/`](./evidence/) directory:
* [`fig-a1-vmware-network-settings.png`](./evidence/fig-a1-vmware-network-settings.png) — VMware Host-only adapter configuration for both VMs
* [`fig-a2-vms-running.png`](./evidence/fig-a2-vms-running.png) — Kali Linux and Metasploitable 2 running side-by-side
* [`fig-a3-ping-connectivity.png`](./evidence/fig-a3-ping-connectivity.png) — Internal ping connectivity test (`0% packet loss`)
* [`fig-a4-routing-tables.png`](./evidence/fig-a4-routing-tables.png) — Routing tables (`ip route`) confirming local subnet only
* [`fig-a5-internet-isolation.png`](./evidence/fig-a5-internet-isolation.png) — External ping test (`1.1.1.1`) returning `Network is unreachable`
* [`fig-a6-nmap-sv-output.png`](./evidence/fig-a6-nmap-sv-output.png) — Full `nmap -sV 192.168.56.128` service and version scan output

## 5. What I Would Do Differently / Remediation

If this were a production server, I would immediately harden it using the following controls:
1. **Decommission insecure legacy protocols:** Disable Telnet (`23/tcp`), unencrypted FTP (`21/tcp`), and the exposed bindshell (`1524/tcp`), replacing file transfers with SFTP over an updated SSH daemon.
2. **Patch management:** Upgrade OpenSSH, Apache, Samba, and database engines to supported, patched releases.
3. **Network segmentation & firewalling:** Restrict database ports (`3306`, `5432`) to `127.0.0.1` or an internal application subnet using host-based firewall rules (`ufw`/`iptables`).
4. **Lab improvement:** In future labs, I would use an isolated VMware LAN Segment (rather than Host-only) to remove even the host-to-guest communication path, and save Nmap results using `-oA` for reproducible reporting.

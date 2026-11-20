---
layout: home
title: Cybersecurity Portfolio
---

# Li Yuanhang (Knightly Lee)
**Master of Cyber Security Candidate | Universiti Malaya**

---

## 1. About Me

Hello! I am **Li Yuanhang (Knightly Lee)**, a Master of Cyber Security candidate at Universiti Malaya with an undergraduate background in Computer Science and Technology. My transition from general software development into cybersecurity was driven by a simple realization: building functional applications is only half the challenge—protecting the infrastructure and data behind them is equally critical.

During my graduate studies, I have focused on strengthening my foundations in networking, Linux administration, packet analysis, and authorized reconnaissance. Rather than relying solely on theory, I prefer hands-on learning inside isolated virtual and containerized labs using tools such as VMware Workstation, Docker, Kali Linux, Nmap, Wireshark, and Python with Scapy. I am particularly drawn to defensive architecture and cloud security, where careful configuration, identity management, and continuous monitoring prevent small misconfigurations from turning into major breaches. This portfolio documents my practical labs, custom tooling, and ongoing growth as an aspiring security professional.

---

## 2. Technical Skills

| Category | Skills & Tools | Proficiency Level | Project Evidence |
| :--- | :--- | :--- | :--- |
| **Networking & Protocols** | TCP/IP, ARP, DNS, HTTP, Subnetting, Routing (`ip route`) | Working Knowledge | [Virtual Lab & Nmap Scan](./projects/virtual-lab-nmap-scan/) |
| **Security & Reconnaissance** | Nmap (`-sV`, `-sn`, `-PR`), Wireshark, `tcpdump`, Packet Analysis | Working Knowledge | [Scapy ARP Device Mapper](./projects/scapy-arp-device-mapper/) |
| **Programming & Scripting** | Python (Scapy, `argparse`, `unittest`), Bash | Working Knowledge | [Scapy ARP Device Mapper](./projects/scapy-arp-device-mapper/) |
| **Operating Systems & Labs** | Kali Linux, Ubuntu, VMware Workstation, Docker & Docker Compose | Working Knowledge | [Virtual Lab & Nmap Scan](./projects/virtual-lab-nmap-scan/) |
| **Cloud & Defensive Concepts** | Cloud IAM, Least Privilege, Log Monitoring (CloudTrail concepts) | Beginner | *Planned AWS Free Tier Lab* |

---

## 3. Certifications and Training

* **ISC2 Certified in Cybersecurity (CC)** — *In Progress (Target: Q1 2027)*
* **AWS Certified Cloud Practitioner** — *In Progress (Target: June 2027)*
* **AWS Skill Builder — Cloud Fundamentals** — *In Progress (Planned start: January 2027)*
* **TryHackMe — Pre Security & Hands-On Security Labs** — *Ongoing Practice* (covering networking, Linux fundamentals, log analysis, and Cyber Kill Chain mapping)
* **Cisco Networking Academy — Introduction to Cybersecurity** — *Self-Paced Study*

---

## 4. Projects

### [Project 1: Isolated Virtual Lab Setup & Nmap Service Scan](./projects/virtual-lab-nmap-scan/)
Built an isolated VMware Host-only lab (`192.168.56.0/24`) pairing Kali Linux with Metasploitable 2, verified complete internet isolation via routing tables and ICMP tests, and performed an `nmap -sV` service/version scan identifying 23 open TCP ports—including the critical `vsftpd 2.3.4` backdoor vulnerability.

### [Project 2: Python & Scapy Authorised ARP Device Mapper](./projects/scapy-arp-device-mapper/)
Developed a scope-enforced Layer 2 ARP reconnaissance tool in Python using Scapy inside an isolated Docker Compose lab (`172.28.70.0/28`). Features strict `/28` CIDR validation, rate limiting, dry-run (`--plan`) mode, automated Markdown summary generation, `unittest` coverage, and cross-validation against Nmap XML output.

---

## 5. Learning Journey

Throughout WQE7001 and my concurrent cybersecurity coursework, my understanding of security has shifted from abstract definitions to disciplined, evidence-based practice. Two hands-on labs stand out as major milestones. First, building an isolated VMware Host-only lab with Kali Linux and Metasploitable 2 taught me how to verify network isolation before running any active scan. Executing `nmap -sV` and uncovering 23 open TCP ports—particularly `vsftpd 2.3.4` with its known backdoor—demonstrated why identifying exact service versions is far more actionable than simply noting open ports. Second, developing a custom Python and Scapy ARP device mapper in a containerized environment deepened my appreciation for protocol-level mechanics and ethical guardrails, such as enforcing strict `/28` CIDR validation, rate limits, and dry-run planning modes.

Practical work also brought inevitable troubleshooting moments. During my initial virtual lab setup, I encountered two distinct issues: Metasploitable 2 initially carried an unnecessary second network adapter that risked breaking lab isolation, and my first connectivity check failed with `ping: invalid argument: '192.168.56.128'`. Rather than guessing, I diagnosed both methodically. I inspected the VMware hardware settings, removed the redundant adapter, and verified the routing tables on both machines using `ip route` alongside an external ping to `1.1.1.1` to confirm `Network is unreachable`. For the ping error, reviewing the command syntax revealed I had omitted the packet count after the `-c` flag; correcting it to `ping -c 4 192.168.56.128` immediately yielded 0% packet loss.

Despite this progress, **cloud security architecture and Identity and Access Management (IAM)** remain the areas I find most challenging. Studying real-world incidents like the 2019 Capital One breach highlighted how subtle misconfigurations—such as over-privileged IAM roles paired with SSRF—can bypass traditional perimeter defenses like WAFs. While I am comfortable configuring local Linux subnets and writing Python scripts for packet inspection, translating least-privilege principles into multi-service cloud environments like AWS and Azure requires much deeper hands-on familiarity with cloud logging, role assumption, and automated compliance monitoring.

To close this gap, I have set a concrete improvement goal: **by June 30, 2027**, I aim to build foundational proficiency in AWS cloud security and earn the **AWS Certified Cloud Practitioner** certification. I will measure my progress through three verifiable milestones: completing the free AWS Skill Builder cloud fundamentals modules, passing the official certification exam, and publishing a third portfolio project built in an AWS Free Tier lab. That lab will document how to intentionally misconfigure a test S3 bucket, detect unauthorized access patterns via Amazon CloudTrail logs, and remediate the IAM policy using least-privilege controls.

---

## 6. Career Objective

My career objective is to become a **Cloud Security Engineer**, helping organizations design resilient cloud architectures, enforce least-privilege access controls, and detect misconfigurations before they can be exploited. As businesses across Malaysia accelerate cloud adoption under initiatives like MyDIGITAL, I want to work from the inside to build secure-by-design systems rather than focusing solely on periodic audits.

To reach this role, I will take three concrete steps over the next 24 months:
1. **Strengthen cloud and security foundations (2027):** Complete AWS Skill Builder training, prepare for the ISC2 Certified in Cybersecurity (CC) and AWS Certified Cloud Practitioner exams, and deepen my Linux and networking fundamentals.
2. **Build hands-on cloud security labs (2027–2028):** Practice IAM policy hardening, S3 access auditing, and Amazon CloudTrail log monitoring in sandboxed environments, documenting each project on this portfolio.
3. **Gain industry experience (2028):** Apply for cloud support or junior cloud security internships while pursuing the AWS Certified Solutions Architect – Associate certification.

---

## 7. Contact Information

* **Email:** [talllee188@gmail.com](mailto:talllee188@gmail.com)
* **GitHub:** [https://github.com/TallLee188](https://github.com/TallLee188)
* **LinkedIn:** [https://www.linkedin.com/in/沅杭-李-4b45b1441](https://www.linkedin.com/in/沅杭-李-4b45b1441)

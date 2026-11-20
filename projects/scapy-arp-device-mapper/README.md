# Project 2: Python & Scapy Authorised ARP Device Mapper

> **Authorization & Scope Statement:** This tool was developed and tested exclusively inside an isolated Docker Compose course lab network (`172.28.70.0/28`). Strict scope enforcement is built directly into the code to prevent out-of-scope scanning.

## 1. Objective

The objective of this project was to design, implement, and validate a lightweight Layer 2 ARP network reconnaissance tool in Python using Scapy. Beyond discovering live hosts on an authorized subnet, the tool enforces ethical scanning guardrails (maximum `/28` CIDR scope, rate limiting, retry caps, and a dry-run `--plan` mode) and generates human-readable Markdown summaries alongside structured JSON output.

## 2. Environment and Tools Used

* **Language & Libraries:** Python 3, Scapy `2.7.0`, `argparse`, `ipaddress`, `unittest`
* **Containerized Lab:** Docker & Docker Compose (`workbench` container on internal bridge `eth0`, subnet `172.28.70.0/28`)
* **Validation Tool:** Nmap `7.94SVN` (`-sn -PR` ARP discovery)

## 3. Method (Step-by-Step)

1. **Scope Validation (`load_scope`):** Implemented strict JSON schema validation ensuring only IPv4 networks no broader than `/28`, unique authorized target IPs inside that subnet, a maximum rate of 20 pps, and 1–2 attempts per host are accepted.
2. **Packet Construction & Strict Reply Matching (`make_arp`, `check_reply`):** Crafted broadcast Ethernet frames (`ff:ff:ff:ff:ff:ff`) encapsulating ARP who-has requests (`op=1`). Filtered replies strictly for `op=2`, matching target source IP, matching scanner IP/MAC, and consistent Ethernet/ARP source MAC addresses.
3. **Dry-Run & Execution Modes:** Added `--plan` to print planned ARP probes without transmitting packets, and `--execute` to run rate-limited probes using `scapy.all.srp()`.
4. **Unit Testing:** Wrote 9 automated test cases in `test_device_mapper.py` covering valid/invalid ARP replies, duplicate reply aggregation, missing replies, deterministic result sorting, destination MAC checks, and invalid `/24` scope rejection.
5. **Cross-Validation with Nmap:** Executed the tool inside the isolated `workbench` container and compared the output directly against an equivalent rate-limited Nmap ARP scan (`nmap -sn -PR -n -e eth0 --max-rate 20 --max-retries 1`).

## 4. Results and Evidence

Both `device_mapper.py` and the Nmap validation scan observed the exact same two live hosts and MAC addresses on `172.28.70.0/28` during the `2026-11-03` test window:

| Target IP | Scapy Tool Status | Replies | Observed MAC Address | Nmap XML Status | Agreement |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `172.28.70.3` | `observed` | 2 | `3a:93:eb:5a:4f:db` | `up` (`arp-response`) | Exact Match |
| `172.28.70.10` | `observed` | 2 | `b6:00:f2:1c:6d:82` | `up` (`arp-response`) | Exact Match |

### Supporting Evidence
All scripts, unit tests, scope configurations, and cross-validation artifacts are stored in [`evidence/`](./evidence/):
* [`device_mapper.py`](./evidence/device_mapper.py) — Full Python/Scapy tool source code
* [`test_device_mapper.py`](./evidence/test_device_mapper.py) — Unit test suite (9 tests)
* [`scope.json`](./evidence/scope.json) — Authorised lab scope definition (`172.28.70.0/28`)
* [`result.json`](./evidence/result.json) — Structured JSON output from `--execute`
* [`result.summary.md`](./evidence/result.summary.md) — Auto-generated Markdown summary table
* [`nmap-validation.xml`](./evidence/nmap-validation.xml) — Independent Nmap ARP validation output

## 5. What I Would Do Differently / Limitations

* **Evidence Limitations:** If a host drops or ignores ARP requests, the tool marks it as `not observed`. Absence of an ARP reply does not prove an IP is unoccupied—it may simply be filtering traffic.
* **Usability Improvement:** Currently, `--execute` prints nothing until the entire scan finishes. Adding a lightweight terminal progress indicator (or verbose logging flag) would give operators clearer feedback during larger scans.
* **Automated Testing of Extensions:** While the core packet logic is covered by `unittest`, I manually verified `make_summary()`. Adding dedicated unit tests for the Markdown summary generator would protect it against future regressions.

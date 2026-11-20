from scapy.all import Ether, ARP

import argparse
import ipaddress
import json
import sys
import time
from scapy.all import srp, get_if_addr, get_if_hwaddr
from datetime import datetime, timezone
from pathlib import Path



def make_arp(ip, my_ip=None, my_mac=None):
    # broadcast mac
    eth = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(op=1, pdst=ip)

    if my_ip:
        arp.psrc = my_ip

    if my_mac:
        eth.src = my_mac
        arp.hwsrc = my_mac

    return eth / arp



def check_reply(pkt, ip, my_ip, my_mac=None):
    if not pkt.haslayer(ARP) or not pkt.haslayer(Ether):
        return None

    a = pkt[ARP]
    eth = pkt[Ether]

    if a.op != 2:
        return None

    if a.psrc != ip or a.pdst != my_ip:
        return None

    if a.hwsrc.lower() != eth.src.lower():
        return None

    if my_mac:
        if eth.dst.lower() != my_mac.lower():
            return None
        if a.hwdst.lower() != my_mac.lower():
            return None

    return a.hwsrc



def add_reply(found, pkt, ip, my_ip, t, my_mac=None):
    mac = check_reply(pkt, ip, my_ip, my_mac)

    if mac is None:
        return

    key = (ip, mac)

    if key not in found:
        found[key] = {
            "ip": ip,
            "mac": mac,
            "count": 0,
            "first_seen": t,
            "last_seen": t
        }

    found[key]["count"] += 1
    found[key]["first_seen"] = min(found[key]["first_seen"], t)
    found[key]["last_seen"] = max(found[key]["last_seen"], t)


def get_results(ips, found):
    res = []

    for ip in sorted(ips, key=ipaddress.ip_address):
        records = [
            v for k, v in found.items() if k[0] == ip
        ]
        records.sort(key=lambda x: x["mac"])

        res.append({
            "ip": ip,
            "status": "observed" if records else "not observed",
            "observations": records
        })

    return res


def scan(scope):
    iface = scope["interface"]
    my_ip = get_if_addr(iface)
    my_mac = get_if_hwaddr(iface)

    net = ipaddress.ip_network(scope["network"])

    if ipaddress.ip_address(my_ip) not in net:
        raise ValueError("Scanner is outside the lab network")

    found = {}
    gap = 1 / scope["maximum_rate_pps"]
    last = None

    for ip in scope["authorised_hosts"]:
        for i in range(scope["maximum_attempts"]):

            if last is not None:
                # rate limit
                wait = gap - (time.monotonic() - last)
                if wait > 0:
                    time.sleep(wait)

            pkt = make_arp(ip, my_ip, my_mac)
            last = time.monotonic()

            ans, _ = srp(
                pkt,
                iface=iface,
                timeout=scope["timeout_seconds"],
                retry=0,
                multi=True,
                verbose=False
            )

            for sent, reply in ans:
                if sent.haslayer(ARP) and sent[ARP].pdst == ip:
                    add_reply(found, reply, ip, my_ip, float(reply.time), my_mac)

    return get_results(scope["authorised_hosts"], found)


def load_scope(path):
    with open(path, "r", encoding="utf-8") as file:
        scope = json.load(file)

    if scope.get("schema") != "wqe7002-recon-scope-v1":
        raise ValueError("Invalid scope schema")

    if scope.get("option") != "device-map":
        raise ValueError("Only Option A is supported")

    network = ipaddress.ip_network(scope["network"], strict=True)

    # max /28 network
    if network.version != 4 or network.prefixlen < 28:
        raise ValueError("Network must be IPv4 and no broader than /28")

    hosts = scope.get("authorised_hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("Authorised host list is missing")

    parsed_hosts = [ipaddress.ip_address(host) for host in hosts]

    if any(host.version != 4 or host not in network for host in parsed_hosts):
        raise ValueError("Host outside the authorised network")

    if len(set(parsed_hosts)) != len(parsed_hosts):
        raise ValueError("Duplicate authorised hosts")

    rate = scope.get("maximum_rate_pps")
    attempts = scope.get("maximum_attempts")

    if type(rate) not in (int, float) or not 0 < rate <= 20:
        raise ValueError("Invalid probe rate")

    if type(attempts) is not int or not 1 <= attempts <= 2:
        raise ValueError("Invalid attempt limit")

    return scope


def make_summary(path):
    #extension: generate markdown report
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    hosts = data["hosts"]

    total = sum(1 for h in hosts if h["status"] == "observed")

    lines = [
        "# ARP Scan Summary",
        f"Scope: {data['scope_id']}",
        f"Observed: {total}/{len(hosts)}",
        "",
        "| IP | Status | Replies | Time gap (s) |",
        "|---|---|---|---|"
    ]

    for h in hosts:
        if not h["observations"]:
            lines.append(f"| {h['ip']} | not observed | 0 | - |")
            continue

        for obs in h["observations"]:
            gap = obs["last_seen"] - obs["first_seen"]
            lines.append(
                f"| {h['ip']} | observed | {obs['count']} | {gap:.3f} |"
            )

    output = Path(path).with_suffix(".summary.md")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output


def main():
    parser = argparse.ArgumentParser(description="Scapy Device Mapper")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--output", required=True)

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--execute", action="store_true")

    args = parser.parse_args()

    try:
        scope = load_scope(args.scope)

        if args.plan:
            print("=== Device Mapper: Dry Run ===")
            print("Scope ID:", scope["scope_id"])
            print("Network:", scope["network"])
            print("Interface:", scope["interface"])
            print("Targets:", scope["authorised_hosts"])
            print("Rate:", scope["maximum_rate_pps"])
            print("Attempts:", scope["maximum_attempts"])

            print("\nPlanned ARP Requests:")
            for ip in scope["authorised_hosts"]:
                print("ARP request to", ip, "via", scope["interface"])

            print("\nNo packets transmitted.")
            return 0

        if args.execute:
            start = datetime.now(timezone.utc)
            hosts = scan(scope)
            end = datetime.now(timezone.utc)

            result = {
                "tool": "device_mapper",
                "version": "0.1",
                "scope_id": scope["scope_id"],
                "option": scope["option"],
                "start_utc": start.isoformat(),
                "end_utc": end.isoformat(),
                "parameters": {
                    "network": scope["network"],
                    "interface": scope["interface"],
                    "targets": scope["authorised_hosts"],
                    "rate": scope["maximum_rate_pps"],
                    "attempts": scope["maximum_attempts"],
                    "timeout": scope["timeout_seconds"]
                },
                "hosts": hosts
            }

            path = Path(args.output)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=4, sort_keys=True)

            print("Scan completed.")
            print("Result saved to:", path)
            print("Summary saved to:", make_summary(path))

    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

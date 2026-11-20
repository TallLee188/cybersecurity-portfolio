from src.device_mapper import check_reply, add_reply, get_results, make_arp
import unittest
from scapy.all import Ether, ARP
from src.device_mapper import check_reply, add_reply, get_results, load_scope
import json
import tempfile
from pathlib import Path

class TestReply(unittest.TestCase):

    def test_correct_reply(self):
        pkt = Ether(src="02:00:00:00:00:03") / ARP(
            op=2,
            psrc="172.28.70.3",
            pdst="172.28.70.2",
            hwsrc="02:00:00:00:00:03"
        )

        res = check_reply(pkt, "172.28.70.3", "172.28.70.2")
        self.assertEqual(res, "02:00:00:00:00:03")

    def test_wrong_ip(self):
        pkt = Ether(src="02:00:00:00:00:04") / ARP(
            op=2,
            psrc="172.28.70.4",
            pdst="172.28.70.2",
            hwsrc="02:00:00:00:00:04"
        )

        res = check_reply(pkt, "172.28.70.3", "172.28.70.2")
        self.assertIsNone(res)

    def test_not_reply(self):
        pkt = Ether() / ARP(
            op=1,
            psrc="172.28.70.3",
            pdst="172.28.70.2"
        )

        res = check_reply(pkt, "172.28.70.3", "172.28.70.2")
        self.assertIsNone(res)

    def test_duplicate_reply(self):
        pkt = Ether(src="02:00:00:00:00:03") / ARP(
            op=2,
            psrc="172.28.70.3",
            pdst="172.28.70.2",
            hwsrc="02:00:00:00:00:03"
        )

        found = {}
        add_reply(found, pkt, "172.28.70.3", "172.28.70.2", 10)
        add_reply(found, pkt, "172.28.70.3", "172.28.70.2", 12)

        res = get_results(["172.28.70.3"], found)
        obs = res[0]["observations"][0]

        self.assertEqual(obs["count"], 2)
        self.assertEqual(obs["first_seen"], 10)
        self.assertEqual(obs["last_seen"], 12)

    def test_missing_reply(self):
        found = {}
        res = get_results(
            ["172.28.70.3", "172.28.70.10"], found
        )

        self.assertEqual(res[0]["status"], "not observed")
        self.assertEqual(res[1]["status"], "not observed")


    def test_arp_packet(self):
        pkt = make_arp("172.28.70.3")

        self.assertEqual(pkt[Ether].dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(pkt[ARP].op, 1)
        self.assertEqual(pkt[ARP].pdst, "172.28.70.3")

        
    def test_invalid_scope(self):
        data = {
            "schema": "wqe7002-recon-scope-v1",
            "option": "device-map",
            "network": "172.28.70.0/24",
            "authorised_hosts": ["172.28.70.3"],
            "maximum_rate_pps": 20,
            "maximum_attempts": 2
        }

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scope.json"
            path.write_text(json.dumps(data))

            with self.assertRaises(ValueError):
                load_scope(path)



    def test_result_order(self):
        a = {
            "ip": "172.28.70.3",
            "mac": "02:00:00:00:00:03",
            "count": 1,
            "first_seen": 10,
            "last_seen": 10
        }

        b = {
            "ip": "172.28.70.3",
            "mac": "02:00:00:00:00:04",
            "count": 1,
            "first_seen": 12,
            "last_seen": 12
        }

        found1 = {
            (a["ip"], a["mac"]): a,
            (b["ip"], b["mac"]): b
        }

        found2 = {
            (b["ip"], b["mac"]): b,
            (a["ip"], a["mac"]): a
        }

        ips1 = ["172.28.70.10", "172.28.70.3"]
        ips2 = ["172.28.70.3", "172.28.70.10"]

        res1 = get_results(ips1, found1)
        res2 = get_results(ips2, found2)

        self.assertEqual(
            json.dumps(res1, sort_keys=True),
            json.dumps(res2, sort_keys=True)
        )


    def test_reply_destination(self):
        my_mac = "02:00:00:00:00:02"
        other_mac = "02:00:00:00:00:99"

        pkt = Ether(
            src="02:00:00:00:00:03",
            dst=my_mac
        ) / ARP(
            op=2,
            psrc="172.28.70.3",
            pdst="172.28.70.2",
            hwsrc="02:00:00:00:00:03",
            hwdst=my_mac
        )

        res = check_reply(
            pkt, "172.28.70.3", "172.28.70.2", my_mac
        )
        self.assertEqual(res, "02:00:00:00:00:03")

        pkt[Ether].dst = other_mac
        res = check_reply(
            pkt, "172.28.70.3", "172.28.70.2", my_mac
        )
        self.assertIsNone(res)



if __name__ == "__main__":
    unittest.main()

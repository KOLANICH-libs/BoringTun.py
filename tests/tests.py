#!/usr/bin/env python3
import itertools
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from collections import OrderedDict

dict = OrderedDict

import BoringTUN
from BoringTUN import *
from BoringTUN.config import WGConfig, Interface, Peer

pingPacket = (
	b"\x45\x00\x00\x54\x84\xcb\x40\x00\x40\x01\xb7\xdb\x7f\x00\x00\x01\x7f\x00\x00\x01"  # IPv4 header
	+	b"\x08\x00\x19\xc2\x00\x0e\x00\x01\x41\x3d\x5d\x62\x00\x00\x00\x00\x7b\xbc\x05\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"  # ICMP packet
)


class Tests(unittest.TestCase):
	def testPublicKeyExtraction(self):
		self.assertEqual(KeyPair(sec=SecretKey.fromBase64("YJ1bbwR9OA+7AIZI0fnLA84lcltZXbsXej+rhYZvS3A="), pub=None).pub.base64(), "JHIy+6HJTke/0WzMVLDsRnV/n/YxfiCSZargR2ZmKAY=")

	def testRoundTrip(self):
		p1 = KeyPair(sec=None, pub=None)
		p2 = KeyPair(sec=None, pub=None)

		cfg1 = WGConfig(
			interface=Interface(p1.sec),
			peers=[
				Peer(
					pub=p2.pub,
					ip=None, # needed for real, non-simulated connections
					port=None,
					psk="AgGZWT8Gp2la+dkmDWPxMVTp1WJgR4gmAubGu9Z6crg=",
					keepAliveTimeout=10,
				)
			]
		)
		cfg2 = WGConfig(
			interface=Interface(p2.sec),
			peers=[
				Peer(
					pub=p1.pub,
					ip=None, # needed for real, non-simulated connections
					port=None,
					psk=cfg1.peers[0].psk,
					keepAliveTimeout=10,
				)
			]
		)

		with Tunnel.fromConfig(cfg1) as t1:
			with Tunnel.fromConfig(cfg2) as t2:
				hs = t1.force_handshake()
				self.assertEqual(hs.opcode, Opcode.WRITE_TO_NETWORK)
				hs = t2.unwrap(hs.buf)
				self.assertEqual(hs.opcode, Opcode.WRITE_TO_NETWORK)
				hs = t1.unwrap(hs.buf)
				self.assertEqual(hs.opcode, Opcode.WRITE_TO_NETWORK)
				hs = t2.unwrap(hs.buf)
				self.assertEqual(hs.opcode, Opcode.WIREGUARD_DONE)

				# actual data
				tx = t1.wrap(pingPacket)
				self.assertEqual(tx.opcode, Opcode.WRITE_TO_NETWORK)

				rx = t2.unwrap(tx.buf)
				self.assertEqual(rx.opcode, Opcode.WRITE_TO_TUNNEL_IPV4)
				self.assertEqual(rx.buf, pingPacket)

				#test ticks
				#tx = t1.tick()
				#self.assertEqual(tx.opcode, Opcode.WRITE_TO_NETWORK)
				#rx = t2.unwrap(tx.buf)
				#self.assertEqual(rx.opcode, Opcode.WIREGUARD_DONE)

				# test_stats
				s1 = t1.stats()
				self.assertEqual(s1.tx_bytes, 84)
				self.assertEqual(s1.rx_bytes, 0)
				s2 = t2.stats()
				self.assertEqual(s2.tx_bytes, 0)
				self.assertEqual(s2.rx_bytes, 84)

if __name__ == "__main__":
	unittest.main()

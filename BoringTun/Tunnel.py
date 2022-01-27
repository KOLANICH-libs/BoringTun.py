__all__ = ("Tunnel", "Opcode", "Action")

import typing

from .config import Interface, Peer, WGConfig
from .ctypes import stats
from .KeyPair import Key
from .tunnelMiddleLevel import MAX_WIREGUARD_PACKET_SIZE, Action, Opcode, TunnPtr, new_tunnel, tunnel_free, wireguard_force_handshake, wireguard_read, wireguard_stats, wireguard_tick, wireguard_write

# pylint:disable=too-many-arguments


class Base64TunnelDataCache:
	"""BoringTun interface is poorly designed, so the lib requires for some API keys in the form of base64 strings.
	See https://github.com/cloudflare/boringtun/issues/248 for more info.
	"""

	__slots__ = ("sec", "pub", "psk")

	def __init__(self, interface, peer):
		self.sec = interface.sec
		self.pub = peer.pub
		self.psk = peer.psk
		self._preprocessKeys()

	def _preprocessKeys(self):
		for k in __class__.__slots__:
			el = getattr(self, k)

			if isinstance(el, Key):
				el = el.base64()

			if isinstance(el, str):
				el = el.encode("ascii")

			setattr(self, k, el)


class Tunnel:
	__slots__ = ("idx", "interface", "peer", "b64c", "openTunnel")

	def __init__(self, interface: Interface, peer: Peer, idx: int = 0) -> None:

		if not isinstance(interface, Interface):
			interface = Interface(interface)

		self.interface = interface
		self.peer = peer

		self.b64c = Base64TunnelDataCache(interface, peer)

		self.idx = idx
		self.openTunnel = None

	@classmethod
	def fromConfig(cls, cfg: WGConfig, idx: int = 0) -> "Tunnel":
		if len(cfg.peers) > 1:
			raise ValueError("Config contains more than 1 peer. Each tunnel is exactly between an interface and one peer. If you need to connect multiple peers, you need multiple tunnels.", cfg.peers)
		return cls(cfg.interface, cfg.peers[0], idx=idx)

	def __enter__(self) -> "OpenTunnel":
		self.openTunnel = OpenTunnel(b64c=self.b64c, keepAlive=self.peer.keepAliveTimeout, idx=self.idx)
		return self.openTunnel

	def __exit__(self, exc_type: None, exc_value: None, traceback: None) -> None:
		self.openTunnel.close()
		self.openTunnel = None


class OpenTunnel:
	__slots__ = ("ptr",)

	def __init__(self, b64c: Base64TunnelDataCache, keepAlive, idx: int = 0) -> None:
		self.ptr = new_tunnel(static_private=b64c.sec, server_static_public=b64c.pub, preshared_key=b64c.psk, keep_alive=keepAlive, index=idx)  # type=TunnPtr
		if self.ptr is None:
			raise Exception("Failed to create the tunnel. Make sure that all the keys are Base64 strings and that the pre-shared key is also generated if you use it!")

	def wrap(self, src: bytes) -> Action:
		return wireguard_write(self.ptr, src, MAX_WIREGUARD_PACKET_SIZE)

	def unwrap(self, src: bytes) -> Action:
		return wireguard_read(self.ptr, src, MAX_WIREGUARD_PACKET_SIZE)

	def tick(self) -> Action:
		return wireguard_tick(self.ptr, MAX_WIREGUARD_PACKET_SIZE)

	def force_handshake(self) -> Action:
		return wireguard_force_handshake(self.ptr, MAX_WIREGUARD_PACKET_SIZE)

	def stats(self) -> stats:
		return wireguard_stats(self.ptr)

	def close(self) -> None:
		tunnel_free(self.ptr)
		self.ptr = None

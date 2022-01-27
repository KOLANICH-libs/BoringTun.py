import typing
from ipaddress import ip_address
from pathlib import Path

from .KeyPair import PublicKey, SecretKey

__all__ = ("Interface", "Peer", "WGConfig")


class Interface:
	__slots__ = ("sec",)

	def __init__(self, sec: SecretKey):
		self.sec = sec

	@classmethod
	def fromCfgEntry(cls, e) -> "Peer":
		sec = SecretKey.fromBase64(e["PrivateKey"])
		#listenPort = int(cfg.interface['ListenPort'])
		return cls(sec)


DEFAULT_KEEPALIVE_TIMEOUT = 10


class Peer:
	__slots__ = ("pub", "psk", "ip", "port", "keepAliveTimeout")

	def __init__(self, pub: PublicKey, ip: ip_address, port: int, psk: str = None, keepAliveTimeout: int = DEFAULT_KEEPALIVE_TIMEOUT):
		self.pub = pub
		self.psk = psk
		self.ip = ip
		self.port = port
		self.keepAliveTimeout = keepAliveTimeout

	@classmethod
	def fromCfgEntry(cls, e) -> "Peer":
		pub = PublicKey.fromBase64(e["PublicKey"])
		ip, port = e["Endpoint"].split(":")
		psk = e.get("PresharedKey", None)
		#e['AllowedIPs']
		port = int(port)
		ip = ip_address(ip)
		keepAliveTimeout = e.get("PersistentKeepalive", DEFAULT_KEEPALIVE_TIMEOUT)
		return cls(pub=pub, ip=ip, port=port, psk=psk, keepAliveTimeout=keepAliveTimeout)


class WGConfig:
	__slots__ = ("interface", "peers")

	def __init__(self, interface: typing.Union[Interface, SecretKey], peers: typing.Iterable[Peer]):
		if isinstance(interface, SecretKey):
			interface = Interface(interface)

		self.interface = interface
		self.peers = peers

	@classmethod
	def fromFile(cls, f: Path) -> "WGConfig":
		import wg_conf

		cfg = wg_conf.WireguardConfig(f)
		sec = Interface.fromCfgEntry(cfg.interface)
		peers = [Peer.fromCfgEntry(p) for p in cfg.peers.values()]
		return cls(sec, peers)

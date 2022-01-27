import asyncio
import typing
from enum import Enum
from threading import Thread

import asyncio_dgram
from icecream import ic

from .config import Peer
from .Tunnel import Opcode, Tunnel


class TunnelStateMachine:
	@classmethod
	def WIREGUARD_DONE(cls, sself, state):
		pass

	@classmethod
	def WRITE_TO_NETWORK(cls, sself, state):
		sself.transport.sendto(state.buf)

	# user queue

	@classmethod
	def WIREGUARD_ERROR(cls, sself, state):
		pass

	@classmethod
	def WRITE_TO_TUNNEL_IPV4(cls, sself, state):
		sself.appProtocol.datagram_received(state.buf, None)

	@classmethod
	def WRITE_TO_TUNNEL_IPV6(cls, sself, state):
		sself.appProtocol.datagram_received(state.buf, None)


class BoringTUNProtocol(asyncio.Transport, asyncio.DatagramProtocol):
	__slots__ = ("transport", "tunnel", "openTunnel", "cmdQ", "keepAliveTask", "appProtocol", "_eventProcessorTask", "handshakeCounter", "initialized")

	STATE_MACHINE_CLASS = TunnelStateMachine

	def __init__(self, tunnel: Tunnel, appProtocol: asyncio.Protocol = None):
		super().__init__()
		self.transport = None
		self.tunnel = tunnel
		self.openTunnel = None
		self.cmdQ = asyncio.Queue(maxsize=0)
		self.keepAliveTask = None
		self.appProtocol = appProtocol
		self._eventProcessorTask = None
		self.initialized = asyncio.Future()

	async def getTransport(self, wgServer: str, port: int):
		loop = asyncio.get_event_loop()
		return await loop.create_datagram_endpoint(lambda: self, remote_addr=(str(wgServer), port))  # , local_addr=('127.0.0.1', 9999)

	async def getTransportForPeer(self, peer: Peer):
		return await self.getTransport(peer.ip, peer.port)

	async def getTransportForTunnel(self, tunnel: Tunnel):
		return await self.getTransportForPeer(tunnel.peer)

	async def eventProcessor(self):
		while True:
			try:
				op = await self.cmdQ.get()
				#print("next op:", op)
				processor = getattr(self.__class__.STATE_MACHINE_CLASS, op.opcode.name)
				processor(self, op)
				self.cmdQ.task_done()
			except Exception as ex:
				import traceback

				print(traceback.format_exc())

	async def keepAliver(self):
		while True:
			self.cmdQ.put_nowait(wg.openTunnel.tick())
			await asyncio.sleep(self.tunnel.peer.keepAliveTimeout, result=None)

	def write(self, data):
		msg = self.openTunnel.wrap(data)
		self.cmdQ.put_nowait(msg)

	def is_writing(self):
		return self._eventProcessorTask is not None

	def pause_writing(self):
		if self._eventProcessorTask is not None:
			self._eventProcessorTask.cancel()
			self._eventProcessorTask = None

	def resume_writing(self):
		if not self.is_writing():
			self._eventProcessorTask = asyncio.create_task(self.eventProcessor())

	def error_received(self, exc):
		ic(exc)

	def forceHandshake(self):
		hs = self.openTunnel.force_handshake()
		if hs.opcode != Opcode.WRITE_TO_NETWORK:
			raise SystemError("First packet of the handshake is not Opcode.WRITE_TO_NETWORK")
		self.cmdQ.put_nowait(hs)

	def connection_made(self, transport):
		self.transport = transport

		if self.openTunnel is None:
			self.openTunnel = self.tunnel.__enter__()

		self.resume_writing()

		asyncio.create_task(self._waitReadyAndSendConnectionMade())

	async def waitQueueClear(self):
		self.stopKeepAlive()
		await self.cmdQ.join()

	async def _waitReadyAndSendConnectionMade(self):
		await self.waitHandshake()
		self.startTasks()
		if self.appProtocol is not None:
			self.appProtocol.connection_made(self)

	async def waitHandshake(self):
		await self.waitQueueClear()
		self.forceHandshake()
		await self.initialized

	async def processPacket(self, data, responseAddrAndPort):
		nextOp = self.openTunnel.unwrap(data)
		if nextOp.opcode != Opcode.WIREGUARD_ERROR:
			peerName = self.transport.get_extra_info("peername")
			if peerName != responseAddrAndPort:
				#await self.__class__.getTransport(*responseAddrAndPort)
				print("Mismatch", peerName, responseAddrAndPort)

		if nextOp.opcode == Opcode.WRITE_TO_NETWORK and data[0] == 2:  # handshake response
			if not self.initialized.done():
				self.initialized.set_result(True)

		await self.cmdQ.put(nextOp)

	def datagram_received(self, data, responseAddrAndPort):
		asyncio.ensure_future(self.processPacket(data, responseAddrAndPort))

	def resume_reading(self):
		pass

	def pause_reading(self):
		raise NotImplementedError

	def is_reading(self):
		True

	def startTasks(self):
		self.resume_writing()
		self.startKeepAlive()

	def stopTasks(self):
		self.pause_writing()
		self.stopKeepAlive()

	def startKeepAlive(self):
		if self.tunnel.peer.keepAliveTimeout is not None:
			if self.keepAliveTask is None:
				self.keepAliveTask = asyncio.create_task(self.keepAliver())

	def stopKeepAlive(self):
		if self.keepAliveTask is not None:
			self.keepAliveTask.stop()

	def connection_lost(self, exc):
		self.stopTasks()

		if self.openTunnel is not None:
			self.openTunnel.__exit__(type(exc), exc, None)
			self.openTunnel = None

		if self.appProtocol is not None:
			self.appProtocol.connection_lost(self)

	@classmethod
	async def createConnection(cls, protocol_factory, tunnel):
		if protocol_factory is not None:
			protocol = protocol_factory()
		else:
			protocol = None

		boringTunTransportProtocol = cls(tunnel, protocol)
		transport, boringTunTransportProtocol_1 = await boringTunTransportProtocol.getTransportForTunnel(tunnel)
		assert boringTunTransportProtocol is boringTunTransportProtocol_1
		return boringTunTransportProtocol, protocol


async def open_wireguard_connection(tunn: Tunnel, protocol_factory=None):
	reader = asyncio.streams.StreamReader()
	protocol = asyncio.streams.StreamReaderProtocol(reader)
	transport, child_protocol = await BoringTUNProtocol.createConnection(protocol_factory, tunn)
	writer = asyncio.streams.StreamWriter(transport, child_protocol, reader, asyncio.get_event_loop())
	return reader, writer

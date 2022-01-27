__all__ = ("TunnPtr", "Opcode", "Action", "wireguard_write", "wireguard_read", "wireguard_tick", "wireguard_force_handshake", "prepareOutputBuffer", "wireguard_stats")

import typing
from ctypes import c_char_p, c_ubyte, cast, pointer

from .ctypes import MAX_WIREGUARD_PACKET_SIZE, LP_c_ubyte, Opcode, TunnPtr, new_tunnel, tunnel_free, wireguard_force_handshake as ct_wireguard_force_handshake, wireguard_read as ct_wireguard_read, wireguard_result, wireguard_stats, wireguard_tick as ct_wireguard_tick, wireguard_write as ct_wireguard_write  # pylint:disable=unused-import


class Action:
	__slots__ = ("opcode", "buf")

	def __init__(self, opcode: Opcode, buf: typing.Optional[bytes] = None):
		self.opcode = opcode
		self.buf = buf

	def __repr__(self):
		return self.__class__.__name__ + "(" + repr(self.opcode) + (", " + repr(self.buf) if self.buf else "") + ")"

	def __iter__(self):
		yield self.opcode
		yield self.buf


def prepareOutputBuffer(dstSize: int) -> typing.Tuple[LP_c_ubyte, bytearray]:
	dst = bytearray(dstSize)
	dstBuff = (c_ubyte * dstSize).from_buffer(dst)
	dstPtr = cast(pointer(dstBuff), LP_c_ubyte)

	return dstPtr, dst


def postprocessOutputResult(res: wireguard_result, dst: bytearray) -> Action:
	return Action(Opcode(res.op), buf=bytes(dst[: res.size]))


def decorateReceiver(ctypesFunc: typing.Callable) -> typing.Callable:
	def receiver(tPtr: TunnPtr, dstSize: int) -> Action:
		dstPtr, dst = prepareOutputBuffer(dstSize)
		res = ctypesFunc(tPtr, dstPtr, dstSize)

		return postprocessOutputResult(res, dst)

	receiver.__name__ = ctypesFunc.__name__

	return receiver


def decorateProcessTransformer(ctypesFunc: typing.Callable) -> typing.Callable:
	def procTransformer(tPtr: TunnPtr, src: bytes, dstSize: int) -> Action:
		srcSize = len(src)

		dstPtr, dst = prepareOutputBuffer(dstSize)

		res = ctypesFunc(tPtr, cast(c_char_p(src), LP_c_ubyte), srcSize, dstPtr, dstSize)

		return postprocessOutputResult(res, dst)

	procTransformer.__name__ = ctypesFunc.__name__

	return procTransformer


wireguard_write = decorateProcessTransformer(ct_wireguard_write)
wireguard_read = decorateProcessTransformer(ct_wireguard_read)

wireguard_tick = decorateReceiver(ct_wireguard_tick)
wireguard_force_handshake = decorateReceiver(ct_wireguard_force_handshake)

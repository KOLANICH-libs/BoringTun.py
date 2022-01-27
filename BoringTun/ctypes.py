import platform
import typing
from ctypes import CDLL, POINTER, Structure, c_char, c_char_p, c_float, c_int, c_int32, c_int64, c_uint8, c_uint16, c_uint32, c_ulong, c_void_p, cast
from enum import IntEnum

# pylint:disable=too-few-public-methods

__all__ = ("x25519_secret_key", "x25519_public_key", "x25519_key_to_base64", "x25519_key_to_hex", "x25519_key_to_str_free", "check_base64_encoded_x25519_key", "new_tunnel", "tunnel_free", "wireguard_write", "wireguard_read", "wireguard_tick", "wireguard_force_handshake", "wireguard_stats", "benchmark")

uintptr_t = c_ulong
result_type = c_int
LP_c_char = POINTER(c_char)
LP_c_ubyte = POINTER(c_uint8)

MAX_WIREGUARD_PACKET_SIZE = 0x10000 + 0x40


def toPythonBytes(bytesArr: LP_c_char) -> bytes:
	return cast(bytesArr, c_char_p).value


def toPythonString(bytesArr: LP_c_char) -> str:
	return toPythonBytes(bytesArr).decode("ascii")


class Opcode(IntEnum):
	"""Indicates the operation required from the caller"""

	WIREGUARD_DONE = 0  # No operation is required.
	WRITE_TO_NETWORK = 1  # Write dst buffer to network. Size indicates the number of bytes to write.
	WIREGUARD_ERROR = 2  # Some error occurred, no operation is required. Size indicates error code.
	WRITE_TO_TUNNEL_IPV4 = 4  # Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
	WRITE_TO_TUNNEL_IPV6 = 6  # Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.


TunnPtr = c_void_p  # opaque pointer


KeyBufferT = c_uint8 * int(32)


class x25519_key(Structure):
	__slots__ = ("key",)
	_fields_ = (("key", KeyBufferT),)

	def __repr__(self):
		return self.__class__.__name__ + ".fromBytes(" + repr(bytes(self.key)) + ")"

	@classmethod
	def fromBytes(cls, data: bytes) -> "x25519_key":
		res = cls()
		res[:] = data
		return res

	def __getitem__(self, k: typing.Union[int, slice]):
		return self.key[k]

	def __setitem__(self, k: typing.Union[int, slice], v: bytes) -> None:
		self.key[k] = v


X25519SecretKey = X25519PublicKey = x25519_key


class wireguard_result(Structure):
	__slots__ = [
		"op",
		"size",
	]
	_fields_ = [
		("op", result_type),
		("size", uintptr_t),
	]


class stats(Structure):
	__slots__ = [
		"time_since_last_handshake",
		"tx_bytes",
		"rx_bytes",
		"estimated_loss",
		"estimated_rtt",
		"reserved",
	]
	_fields_ = [
		("time_since_last_handshake", c_int64),
		("tx_bytes", uintptr_t),
		("rx_bytes", uintptr_t),
		("estimated_loss", c_float),
		("estimated_rtt", c_int32),
		("reserved", c_uint8 * int(56)),
	]

	def __repr__(self):
		return self.__class__.__name__ + "<" + ", ".join("=".join((k, repr(getattr(self, k)))) for k in self.__class__.__slots__) + ">"


if platform.system() == "Windows":
	lib = CDLL("./libboringtun.dll")
else:
	lib = CDLL("./libboringtun.so")


def assignTypesFromFunctionSignature(func, lib):  # pytlint:disable=redefined-outer-name
	rawFunc = getattr(lib, func.__name__)
	rawFunc.argtypes = [func.__annotations__[argName] for argName in func.__code__.co_varnames[: func.__code__.co_argcount]]
	rawFunc.restype = func.__annotations__["return"]
	return rawFunc


atffs = assignTypesFromFunctionSignature


def x25519_secret_key() -> X25519SecretKey:
	"""Generates a new x25519 secret key."""
	return _x25519_secret_key()


_x25519_secret_key = atffs(x25519_secret_key, lib)


def x25519_public_key(private_key: X25519SecretKey) -> X25519PublicKey:
	"""Computes a public x25519 key from a secret key."""
	return _x25519_public_key(private_key)


_x25519_public_key = atffs(x25519_public_key, lib)


def x25519_key_to_base64(key: x25519_key) -> LP_c_char:
	"""
	Returns the base64 encoding of a key as a UTF8 C-string.

	The memory has to be freed by calling `x25519_key_to_str_free`"""
	return _x25519_key_to_base64(key)


_x25519_key_to_base64 = atffs(x25519_key_to_base64, lib)


def x25519_key_to_hex(key: x25519_key) -> LP_c_char:
	"""
	Returns the hex encoding of a key as a UTF8 C-string.
	The memory has to be freed by calling `x25519_key_to_str_free`"""
	return _x25519_key_to_hex(key)


_x25519_key_to_hex = atffs(x25519_key_to_hex, lib)


def x25519_key_to_str_free(stringified_key: LP_c_char) -> None:
	"""Frees memory of the string given by `x25519_key_to_hex` or `x25519_key_to_base64`"""
	return _x25519_key_to_str_free(stringified_key)


_x25519_key_to_str_free = atffs(x25519_key_to_str_free, lib)


def check_base64_encoded_x25519_key(key: c_char_p) -> c_int32:
	"""
	Check if the input C-string represents a valid base64 encoded x25519 key.
	Return 1 if valid 0 otherwise."""
	return _check_base64_encoded_x25519_key(key)


_check_base64_encoded_x25519_key = atffs(check_base64_encoded_x25519_key, lib)


def new_tunnel(static_private: c_char_p, server_static_public: c_char_p, preshared_key: c_char_p, keep_alive: c_uint16, index: c_uint32) -> TunnPtr:
	"""
	Allocate a new tunnel, return NULL on failure.
	Keys must be valid base64 encoded 32-byte keys."""
	return _new_tunnel(static_private, server_static_public, preshared_key, keep_alive, index)


_new_tunnel = atffs(new_tunnel, lib)


def tunnel_free(tunnel: TunnPtr) -> None:
	"""Drops the Tunn object"""
	return _tunnel_free(tunnel)


_tunnel_free = atffs(tunnel_free, lib)


def wireguard_write(tunnel: TunnPtr, src: LP_c_ubyte, src_size: c_uint32, dst: LP_c_ubyte, dst_size: c_uint32) -> wireguard_result:
	"""
	Write an IP packet from the tunnel interface.
	For more details check noise::tunnel_to_network functions."""
	return _wireguard_write(tunnel, src, src_size, dst, dst_size)


_wireguard_write = atffs(wireguard_write, lib)


def wireguard_read(tunnel: TunnPtr, src: LP_c_ubyte, src_size: c_uint32, dst: LP_c_ubyte, dst_size: c_uint32) -> wireguard_result:
	"""
	Read a UDP packet from the server.
	For more details check noise::network_to_tunnel functions."""
	return _wireguard_read(tunnel, src, src_size, dst, dst_size)


_wireguard_read = atffs(wireguard_read, lib)


def wireguard_tick(tunnel: TunnPtr, dst: LP_c_ubyte, dst_size: c_uint32) -> wireguard_result:
	"""
	This is a state keeping function, that need to be called periodically.
	Recommended interval: 100ms."""
	return _wireguard_tick(tunnel, dst, dst_size)


_wireguard_tick = atffs(wireguard_tick, lib)


def wireguard_force_handshake(tunnel: TunnPtr, dst: LP_c_ubyte, dst_size: c_uint32) -> wireguard_result:
	"""Force the tunnel to initiate a new handshake, dst buffer must be at least 148 byte long."""

	return _wireguard_force_handshake(tunnel, dst, dst_size)


_wireguard_force_handshake = atffs(wireguard_force_handshake, lib)


def wireguard_stats(tunnel: TunnPtr) -> stats:
	"""
	Returns stats from the tunnel:
	Time of last handshake in seconds (or -1 if no handshake occurred)
	Number of data bytes encapsulated
	Number of data bytes decapsulated"""
	return _wireguard_stats(tunnel)


_wireguard_stats = atffs(wireguard_stats, lib)


def benchmark(name: c_int32, idx: c_uint32) -> LP_c_char:
	"""Performs an internal benchmark, and returns its result as a C-string."""

	return benchmark(name, idx)


_benchmark = atffs(benchmark, lib)

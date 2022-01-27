__all__ = ("Key", "PublicKey", "SecretKey", "KeyPair", "x25519_key_to_base64", "x25519_key_to_hex", "check_base64_encoded_x25519_key")

import typing
from base64 import b64decode, b64encode
from binascii import hexlify

from .ctypes import X25519PublicKey, X25519SecretKey
from .ctypes import check_base64_encoded_x25519_key as ct_check_base64_encoded_x25519_key
from .ctypes import toPythonString, x25519_key, x25519_key_to_base64 as ct_x25519_key_to_base64, x25519_key_to_hex as ct_x25519_key_to_hex, x25519_key_to_str_free, x25519_public_key, x25519_secret_key

# pylint:disable=too-few-public-methods


def x25519_key_to_base64(key: x25519_key) -> str:
	tempRes = ct_x25519_key_to_base64(key)
	res = toPythonString(tempRes)
	x25519_key_to_str_free(tempRes)
	return res


def x25519_key_to_hex(key: x25519_key) -> str:
	tempRes = ct_x25519_key_to_hex(key)
	res = toPythonString(tempRes)
	x25519_key_to_str_free(tempRes)
	return res


def check_base64_encoded_x25519_key(key: str) -> bool:
	return bool(ct_check_base64_encoded_x25519_key(key.encode("ascii")))


class Key:
	__slots__ = ("data",)

	KEY_TYPE = x25519_key

	def __init__(self, data: typing.Optional[x25519_key] = None) -> None:
		if data is None:
			data = self.__class__.KEY_TYPE()
		else:
			if not isinstance(data, self.__class__.KEY_TYPE):
				raise ValueError("Data must be of type " + self.__class__.KEY_TYPE.__name__, data)

		self.data = data

	USE_NATIVE_IMPLS = False

	def _base64Native(self) -> str:
		return x25519_key_to_base64(self.data)

	def _hexNative(self) -> str:
		return x25519_key_to_hex(self.data)

	def _base64Python(self) -> str:
		return b64encode(bytes(self)).decode("ascii")

	def _hexPython(self) -> str:
		return hexlify(bytes(self)).decode("ascii")

	def base64(self) -> str:
		if self.__class__.USE_NATIVE_IMPLS:
			return self._base64Native()

		return self._base64Python()

	def hex(self) -> str:
		if self.__class__.USE_NATIVE_IMPLS:
			return self._hexNative()

		return self._hexPython()

	def __getitem__(self, k):
		return self.data[k]

	def __setitem__(self, k, v):
		self.data[k] = v

	@classmethod
	def fromKeyBytes(cls, key: bytes) -> x25519_key:
		return cls(cls.KEY_TYPE.fromBytes(key))

	@classmethod
	def fromBase64(cls, key: str) -> x25519_key:
		if not check_base64_encoded_x25519_key(key):
			raise ValueError("The key base64 provided is neither a valid public nor private key", key)

		return cls.fromKeyBytes(b64decode(key))

	def __bytes__(self) -> bytes:
		return bytes(self.data.key)

	def __repr__(self):
		return self.__class__.__name__ + "(" + repr(self.data) + ")"


class PublicKey(Key):
	__slots__ = ()

	KEY_TYPE = X25519PublicKey


class SecretKey(Key):
	__slots__ = ()

	KEY_TYPE = X25519SecretKey

	@classmethod
	def generate(cls) -> "SecretKey":
		return cls(x25519_secret_key())

	def getPublic(self) -> PublicKey:
		return PublicKey(x25519_public_key(self.data))

	def __repr__(self):
		return self.__class__.__name__ + "<!!!SECRET_DATA!!!>"


class KeyPair:
	__slots__ = ("sec", "pub")

	def __init__(self, *, sec: SecretKey, pub: PublicKey) -> None:

		if sec is None and pub is None:
			sec = SecretKey.generate()

		if sec is not None:
			if pub is None:
				pub = sec.getPublic()

		self.sec = sec
		self.pub = pub

	def __repr__(self):
		return self.__class__.__name__ + "(" + "sec=" + repr(self.sec) + ", pub=" + repr(self.pub) + ")"

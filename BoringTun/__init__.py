__all__ = ("KeyPair", "Key", "PublicKey", "SecretKey", "Tunnel", "Opcode", "Action")

from warnings import warn

warn("We have moved from M$ GitHub to https://codeberg.org/KOLANICH-libs/BoringTUN.py , read why on https://codeberg.org/KOLANICH/Fuck-GuanTEEnomo .")

from .KeyPair import Key, KeyPair, PublicKey, SecretKey
from .Tunnel import Action, Opcode, Tunnel

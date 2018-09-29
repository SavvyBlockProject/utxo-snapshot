import plyvel
import struct
from binascii import hexlify, unhexlify
from base58 import b58encode_chk
import json
import typing
import hashlib
import argparse

COINS = {
    "mue": {
        "base58pubkey": b"\x10",
        "base58script": b"\x4c",
    },
    "bitcoin": {
        "base58pubkey": b"\x01",
        "base58script": b"\x05",
    },
}

parser = argparse.ArgumentParser(description="parses a chainstate folder into specific balances")
parser.add_argument('chainstatefolder', type=str, help="folder to extract chainstate from")
parser.add_argument('coin', type=str, help="coin to use for address stringification")

args = parser.parse_args()
if args.coin not in COINS.keys():
    print("Unknown coin {}".format(args.coin))

sha256 = lambda x: hashlib.sha256(x).digest()
ripemd160 = lambda x: hashlib.new('ripemd160', x).digest()
hash160 = lambda x: ripemd160(sha256(x))

db = plyvel.DB(args.chainstatefolder, compression=None)

class MutableBytes:
    def __init__(self, b: bytes):
        self.b = b
    
    def read(self, n: int):
        out = self.b[:n]
        self.b = self.b[n:]
        return out

def deserialize_varint(raw: MutableBytes) -> int:
    n = 0
    while True:
        chData = ord(raw.read(1))
        n = (n << 7) | (chData & 0x7F)
        if chData & 0x80:
            n += 1
        else:
            return n

def serialize_varint(n: int) -> bytes:
    tmp = []
    len = 0
    while True:
        tmp.append((n & 0x7F) | (0x80 if len else 0x00))
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
        len += 1
    return bytes(tmp)

class Script:
    def __init__(self, b):
        self.b = b
    def __str__(self):
        return "Script({})".format(self.address())

    def serialize(self):
        return self.b

    def get_hash(self):
        return hash160(self.serialize())

    def address(self):
        return P2SH(self.get_hash()).address() # for any random script, use the P2SH format

class TxOut:
    value: int
    scriptPubKey: Script
    def __init__(self, value: int, scriptPubKey):
        self.value = value
        self.scriptPubKey = scriptPubKey
    
    def __str__(self):
        return "TxOut(value={}, scriptPubKey={})".format(self.value, str(self.scriptPubKey))

# Coins struct
class Coins:
    coinbase: bool
    vout: typing.List[TxOut]
    height: int
    version: int
    def __init__(self, coinbase, vout, height, version):
        self.coinbase = coinbase
        self.vout = vout
        self.height = height
        self.version = version
    
    def print(self):
        print("Coinbase: {}".format(self.coinbase))
        print("Version: {}".format(self.version))
        print("Height: {}".format(self.height))
        print("Outputs:")
        for i in self.vout:
            print("\t- {}".format(str(i)))

def decompress_amount(x):
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    n = 0
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x*10 + d
    else:
        n = x+1
    while e:
        n *= 10
        e -= 1
    return n

def get_spacial_size(size):
    if size == 0 or size == 1:
        return 20
    return 32

class P2PKH(Script):
    def __init__(self, pkh):
        self.pkh = pkh
    def address(self):
        return b58encode_chk(COINS[args.coin]["base58pubkey"] + self.pkh)

class P2SH(Script):
    def __init__(self, sh):
        self.sh = sh
    def address(self):
        return b58encode_chk(COINS[args.coin]["base58script"] + self.sh)

class P2PK(Script):
    def __init__(self, pk, compressed=True):
        self.pk = pk

class Unspendable(Script):
    def __init__(self):
        pass
    def address(self):
        return None

def pow_mod(x, y, z):
    "Calculate (x ** y) % z efficiently."
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number


def decompress_script(size, i) -> Script:
    if size == 0:
        return P2PKH(i[:20])
    if size == 1:
        return P2SH(i[:20])
    if size == 2 or size == 3:
        return P2SH(b"\x21" + struct.pack(b"B", size) + i[:32] + b"\xac") # P2PK encoded as a P2SH


def deserialize_compressed_script(raw: MutableBytes) -> Script:
    size = deserialize_varint(raw)
    if size < 6:
        compressed_script = raw.read(get_spacial_size(size))
        return decompress_script(size, compressed_script)
    size -= 6
    s = raw.read(size)
    if len(s) > 0 and s[0] == b"\x6a": # op_return
        return Unspendable()
    return Script(s)


def deserialize_compressed_txout(raw: MutableBytes) -> TxOut:
    val = deserialize_varint(raw)
    val = decompress_amount(val)
    script = deserialize_compressed_script(raw)
    return TxOut(val, script)


def deserialize_coins(raw: MutableBytes) -> Coins:
    version = deserialize_varint(raw) # 1
    code = deserialize_varint(raw) # 6

    coinbase = code & 1 != 0 # False
    avail = [code&2 != 0, code&4 != 0] # True, True
    maskCode = code//8 + (0 if (code & 6) != 0 else 1) # 0

    while maskCode > 0:
        chAvail = ord(raw.read(1))
        for p in range(8):
            avail.append((chAvail & (1 << p)) != 0)
        if chAvail != 0:
            maskCode -= 1
        
    vout = []
    for i in range(len(avail)):
        if avail[i]:
            vout.append(deserialize_compressed_txout(raw))
        else:
            vout.append(None)
    
    height = deserialize_varint(raw)
    return Coins(coinbase, vout, height, version)

def deobfuscate(o_key, val):
    l_val = len(value)
    l_obf = len(o_key)

    if l_obf < l_val:
        extended_key = (o_key * ((l_val // l_obf) + 1))[:l_val]
    else:
        extended_key = o_key[:l_val]
    
    r = bytes(a ^ b for a, b in zip(val, extended_key))
    
    assert len(val) == len(r)
    return r

o_key = db.get((unhexlify("0e00") + b"obfuscate_key"))[1:]

balances = {}

for key, value in db.iterator(prefix=b"c"):
    if len(key) != 33:
        continue
    if o_key is not None:
        value = deobfuscate(o_key, value)
    c = deserialize_coins(MutableBytes(value))
    for out in c.vout:
        if out is None or out.scriptPubKey is None:
            continue
        addr = out.scriptPubKey.address()
        if addr is not None:
            if addr not in balances:
                balances[addr] = out.value
            else:
                balances[addr] += out.value

with open("balances.json", "w") as f:
    out_json = []
    for k in balances.keys():
        out_json.append({"address": k, "balance": balances[k]})
    json.dump(out_json, f)
    f.close()

db.close()
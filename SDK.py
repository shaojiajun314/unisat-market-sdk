import sys
import asyncio
import embit
import bitcoin
import requests
from requests.cookies import cookiejar_from_dict
from time import sleep
from embit.psbt import PSBT

from playwright.async_api import async_playwright
from cf_clearance import async_cf_retry, async_stealth


# from binascii import unhexlify

# def hex_str_to_bytes(hex_str):
#     return unhexlify(hex_str.encode('ascii'))

# def check_key(key):
#     if (type(key) is str):
#         key = hex_str_to_bytes(key)
#     if (type(key) is bytes and (len(key) == 33 or len(key) == 65)):
#         return key
#     assert False

# import hashlib

# def hash160(s):
#     return hashlib.new('ripemd160', sha256(s)).digest()

# def key_to_p2wpkh(key, main = False):
#     key = check_key(key)
#     return program_to_witness(0, hash160(key), main)

# def program_to_witness(version, program, main=False):
#     if (type(program) is str):
#         program = hex_str_to_bytes(program)
#     assert 0 <= version <= 16
#     assert 2 <= len(program) <= 40
#     assert version > 0 or len(program) in [20, 32]
#     return encode_segwit_address("bc" if main else "bcrt", version, program)

# def bech32_polymod(values):
#     generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
#     chk = 1
#     for value in values:
#         top = chk >> 25
#         chk = (chk & 0x1ffffff) << 5 ^ value
#         for i in range(5):
#             chk ^= generator[i] if ((top >> i) & 1) else 0
#     return chk

# def bech32_hrp_expand(hrp):
#     return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

# from enum import Enum
# class Encoding(Enum):
#     BECH32 = 1
#     BECH32M = 2

# BECH32_CONST = 1
# CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# def bech32_create_checksum(encoding, hrp, data):
#     values = bech32_hrp_expand(hrp) + data
#     const = BECH32M_CONST if encoding == Encoding.BECH32M else BECH32_CONST
#     polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
#     return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

# def bech32_verify_checksum(hrp, data):
#     check = bech32_polymod(bech32_hrp_expand(hrp) + data)
#     if check == BECH32_CONST:
#         return Encoding.BECH32
#     elif check == BECH32M_CONST:
#         return Encoding.BECH32M
#     else:
#         return None

# def bech32_decode(bech):
#     if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
#             (bech.lower() != bech and bech.upper() != bech)):
#         return (None, None, None)
#     bech = bech.lower()
#     pos = bech.rfind('1')
#     if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
#         return (None, None, None)
#     if not all(x in CHARSET for x in bech[pos+1:]):
#         return (None, None, None)
#     hrp = bech[:pos]
#     data = [CHARSET.find(x) for x in bech[pos+1:]]
#     encoding = bech32_verify_checksum(hrp, data)
#     if encoding is None:
#         return (None, None, None)
#     return (encoding, hrp, data[:-6])

# def bech32_encode(encoding, hrp, data):
#     combined = data + bech32_create_checksum(encoding, hrp, data)
#     return hrp + '1' + ''.join([CHARSET[d] for d in combined])

# def convertbits(data, frombits, tobits, pad=True):
#     acc = 0
#     bits = 0
#     ret = []
#     maxv = (1 << tobits) - 1
#     max_acc = (1 << (frombits + tobits - 1)) - 1
#     for value in data:
#         if value < 0 or (value >> frombits):
#             return None
#         acc = ((acc << frombits) | value) & max_acc
#         bits += frombits
#         while bits >= tobits:
#             bits -= tobits
#             ret.append((acc >> bits) & maxv)
#     if pad:
#         if bits:
#             ret.append((acc << (tobits - bits)) & maxv)
#     elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
#         return None
#     return ret

# def decode_segwit_address(hrp, addr):
#     encoding, hrpgot, data = bech32_decode(addr)
#     if hrpgot != hrp:
#         return (None, None)
#     decoded = convertbits(data[1:], 5, 8, False)
#     if decoded is None or len(decoded) < 2 or len(decoded) > 40:
#         return (None, None)
#     if data[0] > 16:
#         return (None, None)
#     if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
#         return (None, None)
#     if (data[0] == 0 and encoding != Encoding.BECH32) or (data[0] != 0 and encoding != Encoding.BECH32M):
#         return (None, None)
#     return (data[0], decoded)

# def sha256(s):
#     return hashlib.new('sha256', s).digest()

# def encode_segwit_address(hrp, witver, witprog):
#     encoding = Encoding.BECH32 if witver == 0 else Encoding.BECH32M
#     ret = bech32_encode(encoding, hrp, [witver] + convertbits(witprog, 8, 5))
#     if decode_segwit_address(hrp, ret) == (None, None):
#         return None
#     return ret

# class ADDRESS_TYPES(Enum):
# 	# P2TR = 'P2TR'
# 	P2WPKH = 'P2WPKH'
# 	# todo


RETRY_COUNT = 10
SLEEP_SECONDS = 10


class SDK_ERROR(Exception):
	def __init__(self, msg, *args, **kw):
		self.msg = msg
		super().__init__(*args, **kw)

	def __str__(self):
		return f'{self.msg}'

class HTTP_ERROR(SDK_ERROR):
	def __init__(self, msg, status_code, *args, **kw):
		self.status_code = status_code
		super().__init__(msg, *args, **kw)

	def __str__(self):
		return f'{self.msg} - {self.status_code}'


def retry(func):
	def inner(*arg, **kw):
		for i in range(RETRY_COUNT):
			try:
				return func(*arg, **kw)
			except HTTP_ERROR as e:
				if e.status_code == 429:
					print('http 429 retry')
					sleep(SLEEP_SECONDS)
					continue
				if e.status_code == 403:
					print('challenge')
					print(arg[0].challenge_cloudflare())
					continue
				raise

		print('429 retry too many')
		sys.exit(1)
	return inner


class AuctionItem():
	def __init__(
		self,
		address,
		amount,
		auctionId,
		inscriptionId,
		inscriptionNumber,
		limit,
		marketType,
		price,
		tick,
		unitPrice,
		_id
	):
		self.address = address
		self.amount = amount
		self.auctionId = auctionId
		self.inscriptionId = inscriptionId
		self.inscriptionNumber = inscriptionNumber
		self.limit = limit
		self.marketType = marketType
		self.price = price
		self.tick = tick
		self.unitPrice = unitPrice
		self._id = _id

	def __str__(self):
		return f'{self.auctionId} - {self.tick}'


class SDK():
	base_url = 'https://market-api.unisat.io/unisat-market-v2'
	def __init__(
		self,
		private_key,
		address=None,
		cookies=None,
		chrome_path=None
		# address_type=ADDRESS_TYPES.P2WPKH,
	):
		self.private_key = private_key
		self.private_key_for_sign = embit.ec.PrivateKey.from_wif(private_key)
		self.public_key = bitcoin.privkey_to_pubkey(private_key)
		self.chrome_path = chrome_path
		self.session = requests.Session()
		self.session.cookies = cookiejar_from_dict(cookies or {})
		if address:
			self.address = address
		else:
			# todo ！！！！
			# 这个生成代码太多了，还是手动传入 地址吧，比较方便
			# 就是上面注释的代码
			raise
			# if address_type == ADDRESS_TYPES.P2WPKH:
			# 	self.address = key_to_p2wpkh(self.public_key, main=True)

	async def __challenge_cloudflare(self):
		async with async_playwright() as p:
			browser = await p.chromium.launch(
				executable_path=self.chrome_path,
				headless=False,
				chromium_sandbox=False
			)
			page = await browser.new_page()
			await async_stealth(page, pure=False)
			await page.goto('https://unisat.io')
			success = await async_cf_retry(page)
			assert success, 'todo error'
			# user_agent = await page.evaluate("() => navigator.userAgent")
			cookies = {
				cookie["name"]: cookie["value"]
				for cookie in await page.context.cookies()
			}
			print(cookies)
			self.session.cookies = cookiejar_from_dict(cookies)

	def challenge_cloudflare(self):
		asyncio.run(self.__challenge_cloudflare())
	
	@retry
	def brc20_types(self, tick=None):
		if tick:
			r = self.session.get(
				f'https://unisat.io/brc20-api-v2/brc20/status?ticker={tick}&start=0&limit=10&complete=&sort=transactions',
				headers={
					'User-Agent':
					'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'
				}
			)
			if r.status_code != 200:
				raise HTTP_ERROR(msg='brc20_types error', status_code=r.status_code)
			ret = r.json()
			if ret['code'] != 0:
				raise HTTP_ERROR(msg='brc20_types error', status_code=r.status_code)
			return [
				i['ticker']
				for i in ret['data']['detail']
			]

		r = self.session.post(
			f'{self.base_url}/auction/brc20_types',
		)
		if r.status_code != 200:
			raise HTTP_ERROR(msg='brc20_types error', status_code=r.status_code)
		ret = r.json()
		if ret['code'] != 0:
			raise HTTP_ERROR(msg='brc20_types error', status_code=r.status_code)
		return [
			i['tick']
			for i in ret['data']['list']
		]

	@retry
	def __auction_list(self, tick, s, l):
		r = self.session.post(
			f'{self.base_url}/auction/list',
			json={
				"filter":{
					"nftType":"brc20",
					"nftConfirm":True,
					"isEnd":False,
					"tick": tick
				},
				"sort":{
					"unitPrice":1
				},
				"start":0,
				"limit":l
			}
		)
		if r.status_code != 200:
			raise HTTP_ERROR(msg='auction_list error', status_code=r.status_code)
		ret = r.json()
		if ret['code'] != 0:
			raise HTTP_ERROR(msg='auction_list error', status_code=r.status_code)
		return ret
	
	def auction_list(self, tick, limit=20):
		start = 0
		# if not (tick in self.brc20_types):
		# 	raise SDK_ERROR(msg=f'error brc20_type {tick}')
		while 1:
			ret = self.__auction_list(tick, start, limit)
			for i in ret['data']['list']:
				yield AuctionItem(**i)
			start += limit
			if ret['data']['total'] <= start:
				break

	def __sign_psbt(self, psbt_bid_params):
		psbt = PSBT.from_string(psbt_bid_params)
		psbt.sign_with(self.private_key_for_sign)
		# tmp = len('1084201')
		ret = psbt.to_string(encoding='hex').replace('1084201', '113')
		return ret

	def bid(self, auction):
		created_data = self._create_bid(auction)
		bidId = created_data['bidId']
		psbtBidParams= created_data['psbtBid']
		psbtBid = self.__sign_psbt(psbtBidParams)
		self.confirm_bid(auction, bidId, psbtBid)

	@retry
	def confirm_bid(self, auction, bidId, psbtBid):
		r = self.session.post(
			f'{self.base_url}/auction/confirm_bid',
			json={
				"auctionId": i.auctionId,
				"bidId": bidId,
				"psbtBid": psbtBid,
				"psbtBid2": '',
				'psbtSettle': '',
			}
		)
		if r.status_code != 200:
			raise HTTP_ERROR(msg='confirm_bid error', status_code=r.status_code)
		ret = r.json()
		if ret['code'] != 0:
			raise HTTP_ERROR(msg=ret['msg'], status_code=r.status_code)

	@retry
	def _create_bid(self, auction):
		if not isinstance(auction, AuctionItem):
			raise SDK_ERROR('error auction type')
		r = self.session.post(
			f'{self.base_url}/auction/create_bid',
			json={
				"address": self.address,
				"auctionId": auction.auctionId,
				"bidPrice": auction.price,
				"pubkey": self.public_key,
			}
		)
		if r.status_code != 200:
				raise HTTP_ERROR(msg='create_bid error', status_code=r.status_code)
		ret = r.json()
		if ret['code'] != 0:
			raise HTTP_ERROR(msg=ret['msg'], status_code=r.status_code)
		return ret['data']


if __name__ == '__main__':
	import os
	private_key =os.getenv('private_key')
	address =os.getenv('address') or None
	print(address)

	
	sdk = SDK(
		private_key,
		address=address,
		chrome_path="C:\Program Files\Google\Chrome\Application\chrome.exe"
	)
	print(sdk.brc20_types())
	print(sdk.brc20_types('shi'))
	print('*' * 20)
	for i in sdk.auction_list(sdk.brc20_types()[0]):
		print(i)
	i = next(sdk.auction_list('0shi'))
	print('*' * 20)
	sdk.bid(i)










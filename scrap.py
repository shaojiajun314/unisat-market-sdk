import sys
import asyncio
import embit
import bitcoin
import requests
from SDK import SDK_ERROR, HTTP_ERROR
from requests.cookies import cookiejar_from_dict
from time import sleep
from json import dumps
from embit.psbt import PSBT

from playwright.async_api import async_playwright
from cf_clearance import async_cf_retry, async_stealth

RETRY_COUNT = 10
SLEEP_SECONDS = 10


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
					arg[0].challenge_cloudflare()
					continue
				raise

		print('429 retry too many')
		sys.exit(1)
	return inner


class Scrap():
	base_url = 'https://market-api.unisat.io/unisat-market-v2'
	def __init__(
		self,
		cookies=None,
		chrome_path=None
	):
		self.chrome_path = chrome_path
		self.session = requests.Session()
		self.session.cookies = cookiejar_from_dict(cookies or {})

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
	def get(self, tick, start, limit):
		r = r = self.session.get(
			f'https://unisat.io/brc20-api-v2/brc20/status?ticker={tick}&start={start}&limit={limit}&complete=&sort=transactions',
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
		return ret

	def scrap_tickers(self, tick):
		start = 0
		limit = 500
		ticks = set()
		while 1:
			ret = self.get(tick, start, limit)
			ticks = ticks.union({i['ticker']
				for i in ret['data']['detail']})
			start += limit
			if ret['data']['total'] <= start:
				break
			
		return ticks

if __name__ == '__main__':
	import os


	scrap = Scrap(
		chrome_path="C:\Program Files\Google\Chrome\Application\chrome.exe",
	)
	ticks = set()
	for i in [
		'a',
		'b',
		'c',
		'd',
		'e',
		'f',
		'g',
		'h',
		'i',
		'j',
		'k',
		'l',
		'm',
		'n',
		'o',
		'p',
		'q',
		'r',
		's',
		't',
		'u',
		'v',
		'w',
		'x',
		'y',
		'z',
		'1',
		'2',
		'3',
		'4',
		'5',
		'6',
		'7',
		'8',
		'9'
	]:
		ticks = ticks.union(scrap.scrap_tickers(i))
		print(len(ticks))
	print(ticks)
	f = open('ticks.json', 'w')
	f.write(dumps(tuple(ticks)))
	f.close()











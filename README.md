# python 版本 3.10.6

# 1 sdk 实例化
```python
sdk = SDK(
	private_key, # wif 格式的私钥
	address=address, #
	chrome_path=chrome_path #  chrome 浏览器路径 
)

```

# 2 取 推荐的 brc20 列表
```python
sdk.brc20_types()
# 返回 list[str]
# ['ordi', 'VMPX', ...]
```

# 3 搜索 brc20
```python
# 搜索词 s
sdk.brc20_types(s)
# s = 'shi'
# 返回 list[str]
# ['SHIB', 'shit', 'Oshi', '0shi', 'shis', 'SHIP', 'BSHI', 'QSHI', 'gshi', 'SHIC']
```

# 4 auction 列表
```python
# brc20 tick s, (2, 3 的返回值)
sdk.auction_list(s)
# 
# 返回 一个可迭代对象 genarator -> AuctionItem
for i in sdk.auction_list(sdk.brc20_types()[0]):
	print(i) # AuctionItem
```

# 5 购买 bid
```python
# auction (4 的迭代 item )
sdk.bid(auction)
# 
# 成功 返回 None
# 否侧 抛错
```

# 6 错误
```python
# SDK_ERROR
class SDK_ERROR(Exception):
	msg: str # 错误信息

# HTTP_ERROR
class HTTP_ERROR(Exception):
	msg: str # 错误信息
	status_code: int # http 状态码
```


# 7 完整 demo
```python
import os
private_key =os.getenv('private_key')
address =os.getenv('address') or None

print(address)

sdk = SDK(
	private_key,
	address=address
)

print(sdk.brc20_types())

print(sdk.brc20_types('shi'))

print('*' * 20)

for i in sdk.auction_list(sdk.brc20_types()[0]):
	print(i)

print('*' * 20)

i = next(sdk.auction_list('0shi'))
sdk.bid(i)
```
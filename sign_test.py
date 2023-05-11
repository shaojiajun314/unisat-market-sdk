import os
import embit
import bitcoin
from json import loads
from embit import bip32
from embit.psbt import PSBT

private_key =os.getenv('private_key')
print(private_key)
private_key = embit.ec.PrivateKey.from_wif(private_key)
test = bip32.HDKey(private_key, chain_code=private_key.secret)

def sign(raw_psbt):
	psbt = PSBT.from_string(raw_psbt)
	psbt.sign_with(private_key, None)
	return psbt.to_string(encoding='hex').replace('1084201', '113')

raw = loads(open('sign_test.json').read())
count = 0
for t, r in raw.items():
	assert sign(r) == t
	count += 1
print('done, counts:', count)
# Make sure anvil is running locally first
# run with $ anvil -p 3030
# we use the default anvil node here
import os
import json
import ezkl
sol_code_path = 'test_1.sol'

address_path = os.path.join("address.json")
proof_path = os.path.join('test.pf')

res = ezkl.deploy_evm(
    address_path,
    sol_code_path,
    'http://127.0.0.1:3030'
)

assert res == True

with open(address_path, 'r') as file:
    addr = file.read().rstrip()


res = ezkl.verify_evm(
    addr,
    proof_path,
    "http://127.0.0.1:3030"
)
assert res == True
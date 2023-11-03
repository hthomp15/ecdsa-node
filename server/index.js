const express = require("express");
const app = express();
const cors = require("cors");

const secp = require("ethereum-cryptography/secp256k1");
const { keccak256 } = require("ethereum-cryptography/keccak");
const { utf8ToBytes } = require("ethereum-cryptography/utils");


function hashMessage(message) {
  const bytes = utf8ToBytes(message);
  const hash = keccak256(bytes);
  return hash
}

async function recoverKey(message, signature, recoveryBit) {
  return secp.recoverPublicKey(hashMessage(message), signature, recoveryBit);
}

const port = 3042;

app.use(cors());
app.use(express.json());

const balances = {
  //privateKey:  5807de6fbef1d53dfe5ba7151251e5ee99249bb82cce76b9fffc2502862a72db
  "03a19a07a90bba84e67a5eae36cd035b04c1a9c3e23825abc1386ef8b3ee8efbbd": 100,

  //privateKey:  cd392fc4746a6b2b46d5c35b6232482bfdc4f464f8da4af34c5122f26b3fb301
  "0324a41a4c6951b2b40b769213d56fa47cb11afd0c486af16bbc53b3f7bd128555": 50,

  //privateKey:  1fc47fb8c5213007cb8a0c2d3a08a09e3efbac9e1309c4b9386f472f671b8feb
  "0292f5b89ba70aeaca59cc27cf7698991b6ddb4dbd73051625871e8ef59df70bfc": 75,
};

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const { sender, sig:sigStringed, msg } = req.body;
  const { recipient, amount } = msg;

  // convert stringified bigints back to bigints
  const sig = {
    ...sigStringed,
    r: BigInt(sigStringed.r),
    s: BigInt(sigStringed.s)
  }

  const hashMessage = (message) => keccak256(Uint8Array.from(message));

  const isValid = secp.secp256k1.verify(sig, hashMessage(msg), sender) === true;
  
  if(!isValid) res.status(400).send({ message: "Bad signature!"});

  setInitialBalance(sender);
  setInitialBalance(recipient);

  if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[recipient] += amount;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}

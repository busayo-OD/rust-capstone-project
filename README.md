# Btrust Builders: Rust Language Club - Capstone Project: Setting up and interacting with a Bitcoin Node

## Overview

In this capstone project week, you'll learn how to use Bitcoin Core's RPC to interact with a running Bitcoin node. The tasks involve connecting to a Bitcoin Core RPC daemon, creating wallets, generating addresses, creating transactions, and mining Bitcoin blocks. You'll need a Bitcoin node running in `regtest` mode on your local machine to test your solution.

A [docker-compose](./docker-compose.yaml) file is provided to help you launch a Bitcoin node in `regtest` mode locally.

> [!TIP]
> [OPTIONAL] You can also use the [bitcoin.conf](./bitcoin.conf) file to start a local regtest node with your locally built bitcoin binaries.
> Copy the `bitcoin.conf` file in the default bitcoin data-directory `~/.bitcoin/`. If you don't have the data-directory, just create one.


## Objective
Implement the tasks in this specific directory: [main.rs](./rust/src/main.rs)

Your program must:

- Create two wallet named `Miner` and `Trader`. The names are case-sensitive and should be exact.
- Generate one address from the `Miner` wallet with a label "Mining Reward".
- Mine new blocks to this address until you get positive wallet balance. (use `generatetoaddress`) (observe how many blocks it took to get to a positive balance)
- Write a short comment describing why wallet balance for block rewards behaves that way.
- Print the balance of the `Miner` wallet.
- Create a receiving addressed labeled "Received" from `Trader` wallet.
- Send a transaction paying 20 BTC from `Miner` wallet to `Trader`'s wallet.
- Fetch the unconfirmed transaction from the node's mempool and print the result. (hint: `bitcoin-cli help` to find list of all commands, look for `getmempoolentry`).
- Confirm the transaction by mining 1 block.


### Output
- Fetch the following details of the transaction and output them to a `out.txt` file in the following format. Each attribute should be on a new line.
  - `Transaction ID (txid)`
  - `Miner's Input Address`
  - `Miner's Input Amount (in BTC)`
  - `Trader's Output Address`
  - `Trader's Output Amount (in BTC)`
  - `Miner's Change Address`
  - `Miner's Change Amount (in BTC)`
  - `Transaction Fees (in BTC)`
  - `Block height at which the transaction is confirmed`
  - `Block hash at which the transaction is confirmed`


- Sample output file:
  ```
  57ecbb84fd3246ebcc734455fd30f5536637878b40fb2742d1a4fced3c28862c
  bcrt1qv5plgft75j0hegtvf6zs5pajh7k0gxg2dhj224
  50
  bcrt1qak6gpu2p6zjpwrhvd4dvdnp4rt3ysm9rpst3wu
  20
  bcrt1qxw3msnuqps0kgn6dprs9ldlz79yfj63swqupd0
  29.9999859
  -1.41e-05
  102
  3b821acd7c32c2b3da143e2c6b0134e5aa8206aeae0a54bfa4963e73ac2857a0
  ```

### Local Testing Steps
It's a good idea to run the whole test locally to ensure your code is working properly.
- Ensure that you have `npm` and `nvm` installed and your system. You will need `node v18` or greater to run the test script.
- Ensure that there is no `bitcoind` process running in your system.
- Give execution permission to `test.sh`, by running `chmod +x ./test.sh`.
- Execute [`./test.sh`](./test.sh).

If your code works, you will see the test completed successfully.

## Submission:
 - Create a commit with your local changes.
 - Push the commit to your forked repository (`git push origin main`).
  - The autograder will run your script against a test script to verify the functionality.
  - Check the status of the autograder on Github Actions to see if it passed successfully or failed.
  - You can submit multiple times before the deadline. The latest submission before the deadline will be considered your final submission.
  
Submit your final solution link to this form: [Google form](https://forms.gle/a3ibaSHcqpaZWsnPA).

### Common Issues
- Your submission should not stop the Bitcoin Core daemon at any point.
- Linux and MacOS are the recommended operating systems for this challenge. If you are using Windows, you may face compatibility issues.
- The autograder will run the test script on an Ubuntu 22.04 environment. Make sure your script is compatible with this environment.
- If you are unable to run the test script locally, you can submit your solution and check the results on the Github Actions tab.

## Evaluation Criteria
Your submission will be evaluated based on:
- **Autograder**: Your code must pass the autograder [test script](./test/test.spec.ts).
- **Explainer Comments**: Include comments explaining each step of your code.
- **Code Quality**: Your code should be well-organized, commented, and adhere to best practices.

### Plagiarism Policy
Our plagiarism detection checker thoroughly identifies any instances of copying or cheating. Participants are required to publish their solutions in the designated repository, which is private and accessible only to the individual and the administrator. Solutions should not be shared publicly or with peers. In case of plagiarism, both parties involved will be directly disqualified to maintain fairness and integrity.

### AI Usage Disclaimer
You may use AI tools like ChatGPT to gather information and explore alternative approaches, but avoid relying solely on AI for complete solutions. Verify and validate any insights obtained and maintain a balance between AI assistance and independent problem-solving.

## Why These Restrictions?
These rules are designed to enhance your understanding of the technical aspects of Bitcoin. By completing this assignment, you gain practical experience with the technology that secures and maintains the trustlessness of Bitcoin. This challenge not only tests your ability to develop functional Bitcoin applications but also encourages deep engagement with the core elements of Bitcoin technology.

### Additional Resources
- [Rust RPC client for Bitcoin Core JSON-RPC](https://github.com/rust-bitcoin/rust-bitcoincore-rpc)
- [Bitcoin Core Documentation](https://developer.bitcoin.org/)
- [Learning Bitcoin from the Command Line](https://github.com/BlockchainCommons/Learning-Bitcoin-from-the-Command-Line)
- [Bitcoin Core RPC Documentation](https://developer.bitcoin.org/reference/rpc/)

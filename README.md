# EIP7702 Staking Rescue Tool

A unified command-line tool to check for staked assets and execute a two-stage, automated rescue for compromised wallets. This system uses a relayer to sponsor transactions, making it ideal for wallets that have no native currency (like ETH) for gas fees.

This project was built to rescue staked **Caldera (ERA)** tokens but can be adapted for other staking contracts that follow a similar unstake -> cooldown -> withdraw pattern.

**Have questions?** Join the official [DrainerLESS Telegram](https://t.me/drainerless) for support.

***

### ⚠️ Disclaimer: Use at Your Own Risk

This tool handles raw private keys. While it sends them encrypted to a trusted relayer, there are inherent risks involved with handling private keys. Please review the code carefully. The authors are not responsible for any loss of funds. **NEVER commit your `.env` or `pk.txt` files to a public repository.**

***

This script is a specialized tool designed to rescue assets from compromised wallets by leveraging the power of [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) and a custom relayer. It is particularly focused on time-sensitive operations like withdrawing assets after a cooldown period has elapsed.

## Core Concepts: How It Works

The primary challenge in rescuing assets from a compromised wallet is that the attacker (the "sweeper bot") instantly drains any ETH sent to it to pay for gas fees. This makes it impossible to execute transactions conventionally.

This tool solves that problem by using two key mechanisms:

1.  **EIP-7702 Authorization**: This Ethereum standard allows a wallet (the compromised one) to sign a message that authorizes another wallet (the secure one) to execute transactions on its behalf. The compromised wallet essentially says, "I authorize this secure address to act as me for this specific transaction."

2.  **Relayer Service**: The signed authorization and the transaction details (the "intent") are sent to a trusted relayer. The relayer then pays the gas fees from its own funds and submits the transaction to the blockchain. The secure wallet never needs to send ETH to the compromised one.

This combination allows the secure wallet to control the compromised wallet's assets and execute rescue operations without alerting the sweeper bot.

## Key Features

-   **Automated Cooldown Detection**: The bot continuously monitors the blockchain to precisely determine when a withdrawal's cooldown period has ended.
-   **EIP-7702 Native Integration**: Uses a modern, gas-efficient authorization standard for secure, delegated transactions.
-   **Dynamic Transaction Building**: Automatically constructs the correct transaction calldata (`claimHex`) from the contract's ABI, preventing errors from manual encoding.
-   **Centralized Configuration**: A clean and simple setup using a `.env` file for secrets and a `campaign.json` for target-specific parameters.
-   **Atomic Operations**: Leverages the relayer's `revertOnError` feature to ensure that if any part of the rescue fails, the entire transaction is reverted.
-   **Detailed Logging**: Provides comprehensive logs for monitoring and debugging every step of the process.

## System Requirements

-   Node.js (v18 or higher recommended)
-   `npm` or a similar package manager
-   A `.env` file for environment variables.
-   A `campaign.json` file to define the rescue target.
-   A `pk.txt` file containing the private keys of the compromised wallets.

## Configuration

### 1. Environment Variables (`.env`)

Create a `.env` file in the root directory with the following variables:

```env
# A secure RPC URL, preferably a private one (e.g., from Tenderly, Alchemy, Infura)
RPC_URL=https://your-rpc-provider.com/your-api-key

# The private key of your secure wallet, which will control the rescue operations
SECURE_WALLET_PK=0x...
```

### 2. Campaign File (`campaign.json`)

This file defines the specifics of the rescue operation.

```json
{
  "name": "My Staking Rescue Campaign",
  "chainId": 1,
  "targetContractAddress": "0x...",
  "tokenAddress": "0x...",
  "abiFile": "staking-abi.json"
}
```

-   `name`: A descriptive name for the campaign.
-   `chainId`: The ID of the target blockchain (e.g., `1` for Ethereum Mainnet).
-   `targetContractAddress`: The address of the contract to interact with (e.g., the staking contract).
-   `tokenAddress`: The address of the token being rescued.
-   `abiFile`: The path to the JSON ABI file for the `targetContractAddress`.

### 3. Compromised Keys (`pk.txt`)

Create a `pk.txt` file and list the private keys of the compromised wallets, one per line.

```
0x...
0x...
0x...
```

## Usage

First, install the required dependencies:
```bash
npm install
```

### 1. Check Asset Status

To get a report of all wallets with pending withdrawals and their current status, run the `check` command. This is a read-only operation and will not execute any transactions.

```bash
node airdrop-rescuer.js check -c campaign.json
```

This will generate a file named `TOKEN_SYMBOL-CONTRACT_ADDRESS-withdraw-info.txt` with the results.

### 2. Start the Rescue Bot

To start the automated bot that will monitor and execute withdrawals as soon as they become available, run the `rescue` command:

```bash
node airdrop-rescuer.js rescue -c campaign.json
```

The bot will run continuously, checking for ready withdrawals and executing them via the relayer.

## Extensibility and Other Implementations

While this tool is configured for staking withdrawals, its architecture is highly flexible and can be adapted for a wide range of rescue operations. The core logic is centered around the `intent` object sent to the relayer.

By modifying the `triage` logic and how the `claimHex` is built, you can adapt this bot for other scenarios, such as:

-   **Claiming Airdrops**: The `triage` function could check a Merkle tree or a contract's state to see if a wallet is eligible. The `buildClaimHex` function would then encode the `claim()` function call.
-   **Vesting Contracts**: Monitor a vesting contract and execute `release()` or `claim()` functions as soon as tokens unlock.
-   **Emergency Contract Functions**: Trigger emergency functions like `pause()` or `withdraw()` on a smart contract owned by the compromised key.

The key components to modify are:
1.  **`triageStakingWallets`**: Change this function to implement the logic that determines *when* an action is possible for a given wallet.
2.  **`buildClaimHex`**: Modify this function to encode the correct function signature and arguments for your target contract interaction.

This modular design makes the tool a powerful foundation for nearly any time-sensitive rescue operation on the EVM.

## Troubleshooting

-   **RPC Connection Errors**: Ensure your `RPC_URL` in the `.env` file is correct and that your API key is valid.
-   **Invalid Private Keys**: Double-check that the keys in `pk.txt` are in the correct format (hex string, with or without `0x` prefix).
-   **Campaign File Not Found**: Make sure you are passing the correct path to your `campaign.json` file with the `-c` flag.
-   **Transaction Fails (REVERT)**: This usually indicates an issue with the transaction's calldata.
    -   Verify that the `abiFile` in `campaign.json` is correct for the `targetContractAddress`.
    -   Ensure the arguments being passed to `encodeFunctionData` in `buildClaimHex` are correct.
    -   Use a tool like Tenderly to simulate the transaction and get a detailed stack trace of the revert reason.

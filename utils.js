import fs from 'fs';
import { privateKeyToAccount } from 'viem/accounts';

export const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

export function bigintToDecimalString(amount, decimals = 18n) {
  if (typeof amount !== 'bigint') {
    console.error(`Error: amount must be BigInt, received: ${typeof amount}`, amount);
    throw new Error('amount must be BigInt');
  }
  const divisor = 10n ** BigInt(decimals);
  const integerPart = (amount / divisor).toString();
  let fractionalPart = (amount % divisor).toString().padStart(Number(decimals), '0').replace(/0+$/, '');
  return fractionalPart ? `${integerPart}.${fractionalPart}` : integerPart;
}

export function loadPrivateKeys(filePath) {
  const keys = {};
  if (!fs.existsSync(filePath)) {
    console.error(`\nERROR: Private keys file not found at '${filePath}'.`);
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
        console.warn(`Warning: Invalid private key on line ${index + 1} of ${filePath}: ${e.message}. Skipping.`);
        invalidKeys++;
      }
    }
  });
  if (invalidKeys > 0) {
    console.warn(`Total invalid private keys skipped: ${invalidKeys}`);
  }
  return keys;
}

export function loadSetFromFile(filePath) {
  if (!fs.existsSync(filePath)) return new Set();
  const fileContent = fs.readFileSync(filePath, 'utf-8');
  return new Set(fileContent.split('\n').map(line => line.trim().toLowerCase()).filter(Boolean));
}

export function findAndParseCandidates(privateKeysFilePath) {
  const candidates = new Set();
  const files = fs.readdirSync('.').filter(fn => fn.endsWith('-staking-info.txt'));
  if (files.length === 0) {
    console.warn(`Warning: No '*-staking-info.txt' file found. Checking all wallets in ${privateKeysFilePath}.`);
    return Object.keys(loadPrivateKeys(privateKeysFilePath));
  }
  const addressRegex = /^(0x[a-fA-F0-9]{40})/; 
  for (const file of files) {
    console.log(`Processing staking info file: ${file}`);
    const fileContent = fs.readFileSync(file, 'utf-8');
    fileContent.split('\n').forEach(line => {
      const match = line.match(addressRegex);
      if (match) candidates.add(match[1].toLowerCase());
    });
  }
  return Array.from(candidates);
}

export function loadPendingWithdrawals(pendingWithdrawalFile) {
  if (!fs.existsSync(pendingWithdrawalFile)) return {};
  try {
    const fileContent = fs.readFileSync(pendingWithdrawalFile, 'utf-8');
    return fileContent ? JSON.parse(fileContent) : {};
  } catch {
    console.warn("Warning: Could not parse the pending withdrawals file.");
    return {};
  }
}

export function savePendingWithdrawal(wallet, data, pendingWithdrawalFile) {
  const pending = loadPendingWithdrawals(pendingWithdrawalFile);
  pending[wallet.toLowerCase()] = data;
  fs.writeFileSync(pendingWithdrawalFile, JSON.stringify(pending, null, 2));
}

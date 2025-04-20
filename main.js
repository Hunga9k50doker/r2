require("dotenv").config();
const ethers = require("ethers");
const readline = require("readline");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const settings = require("./config/config");
const { showBanner } = require("./core/banner");
const fs = require("fs").promises;
const axios = require("axios");
const { sleep, loadData, getRandomNumber, saveToken, isTokenExpired, saveJson, getRandomElement } = require("./utils.js");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const { solveCaptcha } = require("./captcha.js");
const localStorage = require("./localStorage.json");
const wallets = loadData("wallets.txt");
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const network = {
  name: "Sepolia ETH",
  rpc: "https://ethereum-sepolia-rpc.publicnode.com",
  chainId: 11155111,
  symbol: "SepoliaETH",
  explorer: "https://sepolia.etherscan.io/",
  // address: "0x073DF8De752784FffcBa4D7C921F97CA34C360A5",
};

const USDC_ADDRESS = "0xef84994ef411c4981328ffce5fda41cd3803fae4";
const R2USD_ADDRESS = "0x20c54c5f742f123abb49a982bfe0af47edb38756";
const SR2USD_ADDRESS = "0xbd6b25c4132f09369c354bee0f7be777d7d434fa";
const USDC_TO_R2USD_CONTRACT = "0x20c54c5f742f123abb49a982bfe0af47edb38756";
const R2USD_TO_USDC_CONTRACT = "0x07abd582df3d3472aa687a0489729f9f0424b1e3";
const STAKE_R2USD_CONTRACT = "0xbd6b25c4132f09369c354bee0f7be777d7d434fa";

const USDC_TO_R2USD_METHOD_ID = "0x095e7a95";
const R2USD_TO_USDC_METHOD_ID = "0x3df02124";
const STAKE_R2USD_METHOD_ID = "0x1a5f0f00";

const ERC20_ABI = [
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function allowance(address owner, address spender) external view returns (uint256)",
  "function balanceOf(address account) external view returns (uint256)",
  "function decimals() external view returns (uint8)",
];

const SWAP_ABI = ["function swap(uint256,uint256,uint256) external returns (uint256)"];
function parseProxy(proxy) {
  if (!proxy) return null;
  let proxyUrl = proxy;
  if (!proxy.startsWith("http://") && !proxy.startsWith("https://")) {
    proxyUrl = `http://${proxy}`;
  }
  return proxyUrl;
}

async function connectToNetwork(proxy, privateKey) {
  let wallet = null;
  try {
    const proxyUrl = parseProxy(proxy);
    let provider;
    if (proxyUrl && settings.USE_PROXY) {
      const agent = new HttpsProxyAgent(proxyUrl);
      provider = new ethers.providers.JsonRpcProvider({
        url: network.rpc,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
        agent,
      });
    } else {
      provider = new ethers.providers.JsonRpcProvider(network.rpc);
    }
    wallet = new ethers.Wallet(privateKey, provider);
    return { provider, wallet, proxy };
  } catch (error) {
    console.log(colors.red(`[${wallet.address}] Connection error:`, error.message, "❌"));
    return { provider: null, wallet, proxy };
  }
}

async function askQuest(question) {
  return new Promise((resolve) => {
    rl.question(colors.yellow(`${question} `), (answer) => {
      resolve(answer);
    });
  });
}

class ClientAPI {
  constructor(itemData, accountIndex, proxy, baseURL, authInfos) {
    this.baseURL = settings.BASE_URL;
    this.baseURL_v2 = "";
    this.itemData = itemData;
    this.accountIndex = accountIndex;
    this.proxy = proxy;
    this.proxyIP = null;
    this.session_name = null;
    this.wallet = new ethers.Wallet(this.itemData.privateKey);
    // this.w3 = new Web3(new Web3.providers.HttpProvider(settings.RPC_URL, proxy));
  }

  async log(msg, type = "cyan") {
    const accountPrefix = `[R2][${this.accountIndex + 1}][${this.itemData.address}]`;
    let ipPrefix = "[Local IP]";
    if (settings.USE_PROXY) {
      ipPrefix = this.proxyIP ? `[${this.proxyIP}]` : "[Unknown IP]";
    }
    let logMessage = "";

    switch (type) {
      case "success":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.green;
        break;
      case "error":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.red;
        break;
      case "warning":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.yellow;
        break;
      case "custom":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.magenta;
        break;
      case "info":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.blue;
        break;
      default:
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.cyan;
    }
    console.log(logMessage);
  }

  async checkProxyIP() {
    try {
      const proxyAgent = new HttpsProxyAgent(this.proxy);
      const response = await axios.get("https://api.ipify.org?format=json", { httpsAgent: proxyAgent });
      if (response.status === 200) {
        this.proxyIP = response.data.ip;
        return response.data.ip;
      } else {
        throw new Error(`Cannot check proxy IP. Status code: ${response.status}`);
      }
    } catch (error) {
      throw new Error(`Error checking proxy IP: ${error.message}`);
    }
  }

  async makeRequest(
    url,
    method,
    data = {},
    options = {
      retries: 2,
      isAuth: false,
      extraHeaders: {},
      refreshToken: null,
    }
  ) {
    const { retries, isAuth, extraHeaders, refreshToken } = options;

    const headers = {
      ...this.headers,
      ...extraHeaders,
    };

    if (!isAuth && this.token) {
      headers["x-api-key"] = `${this.token}`;
    }

    let proxyAgent = null;
    if (settings.USE_PROXY) {
      proxyAgent = new HttpsProxyAgent(this.proxy);
    }
    let currRetries = 0,
      errorMessage = null,
      errorStatus = 0;

    do {
      try {
        const response = await axios({
          method,
          url,
          headers,
          timeout: 120000,
          ...(proxyAgent ? { httpsAgent: proxyAgent, httpAgent: proxyAgent } : {}),
          ...(method.toLowerCase() != "get" ? { data } : {}),
        });
        if ((response?.data?.data?.code && response?.data?.data?.code == 401) || (response?.data?.code && response?.data?.code == 401)) {
          this.token = await this.getValidToken(true);
          return await this.makeRequest(url, method, data, options);
        }
        if (response?.data?.data?.code >= 400 || response?.data?.code >= 400) {
          return { success: false, data: response.data, status: response?.data?.data?.code >= 400 || response?.data?.code >= 400, error: response.data?.msg || "unknow" };
        }
        if (response?.data?.data) return { status: response.status, success: true, data: response.data.data, error: null };
        return { success: true, data: response.data, status: response.status, error: null };
      } catch (error) {
        errorStatus = error.status;
        errorMessage = error?.response?.data?.message ? error?.response?.data : error.message;
        this.log(`Request failed: ${url} | Status: ${error.status} | ${JSON.stringify(errorMessage || {})}...`, "warning");

        if (error.status == 401) {
          this.log(`Unauthorized: ${url} | trying get new token...`);
          this.token = await this.getValidToken(true);
          return await this.makeRequest(url, method, data, options);
        }
        if (error.status == 400) {
          this.log(`Invalid request for ${url}, maybe have new update from server | contact: https://t.me/airdrophuntersieutoc to get new update!`, "error");
          return { success: false, status: error.status, error: errorMessage, data: null };
        }
        if (error.status == 429) {
          this.log(`Rate limit ${JSON.stringify(errorMessage)}, waiting 60s to retries`, "warning");
          await sleep(60);
        }
        if (currRetries > retries) {
          return { status: error.status, success: false, error: errorMessage, data: null };
        }
        currRetries++;
        await sleep(5);
      }
    } while (currRetries <= retries);
    return { status: errorStatus, success: false, error: errorMessage, data: null };
  }

  async getValidToken(isNew = false) {
    const existingToken = this.token;
    // const { isExpired: isExp, expirationDate } = isTokenExpired(existingToken);
    // this.log(`Access token status: ${isExp ? "Expired".yellow : "Valid".green} | Acess token exp: ${expirationDate}`);

    if (existingToken && !isNew) {
      this.log("Using valid token", "success");
      return existingToken;
    }

    this.log("No found token or experied, logining......", "warning");
    const loginRes = await this.auth();
    if (!loginRes?.success) return null;
    const newToken = loginRes.data;
    if (newToken?.token) {
      this.token = newToken.token;
      if (!newToken.isBound) {
        await this.bindCode();
      }
      await saveJson(this.session_name, JSON.stringify(newToken), "localStorage.json");
      return newToken.token;
    }
    this.log("Can't get new token...", "warning");
    return null;
  }

  async auth() {
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `Welcome! Sign this message to login to r2.money. This doesn't cost you anything and is free of any gas fees. Nonce: ${timestamp}`;
    const signedMessage = await this.wallet.signMessage(message);
    const payload = {
      user: this.itemData.address,
      timestamp,
      signature: signedMessage,
    };
    return this.makeRequest(`${this.baseURL}/v1/auth/login`, "post", payload, { isAuth: true });
  }

  async getUserData() {
    return this.makeRequest(`${this.baseURL}/v1/user/points?user=${this.itemData.address}`, "get");
  }

  async bindCode() {
    return this.makeRequest(`${this.baseURL}/v1/referral/bind`, "post", {
      bindCode: settings.REF_CODE,
      user: this.itemData.address,
    });
  }

  async getWalletInfo(wallet) {
    let points = 0;
    const newUSDCBalance = await this.checkBalance(wallet, USDC_ADDRESS);
    const newR2USDBalance = await this.checkBalance(wallet, R2USD_ADDRESS);
    const newsR2USDBalance = await this.checkBalance(wallet, SR2USD_ADDRESS);
    const sepo = await this.checkBalance(wallet);
    const result = await this.getUserData();
    if (result?.success) {
      points = result.data?.points || 0;
    }
    this.log(`New balance | SepoliaETH: ${sepo} | USDC: ${newUSDCBalance} | R2USD: ${newR2USDBalance} | sR2USD: ${newsR2USDBalance} Points: ${points}`, "custom");
  }

  async checkBalance(wallet, tokenAddress) {
    try {
      if (tokenAddress) {
        // Check balance for the specified ERC20 token
        const tokenContract = new ethers.Contract(tokenAddress, ERC20_ABI, wallet);
        const balance = await tokenContract.balanceOf(wallet.address);
        const decimals = await tokenContract.decimals();
        return parseFloat(ethers.utils.formatUnits(balance, decimals)).toFixed(4);
      } else {
        // Check balance for native Sepolia ETH
        const balance = await wallet.getBalance();
        return parseFloat(ethers.utils.formatEther(balance)).toFixed(4);
      }
    } catch (error) {
      this.log(`Failed to check balance: ${error.message}`, "error");
      return "0";
    }
  }

  async approveToken(wallet, tokenAddress, spenderAddress, amount) {
    try {
      if (!ethers.utils.isAddress(spenderAddress)) {
        throw new Error(`Invalid spender address: ${spenderAddress}`);
      }
      const tokenContract = new ethers.Contract(tokenAddress, ERC20_ABI, wallet);
      const decimals = await tokenContract.decimals();
      const currentAllowance = await tokenContract.allowance(wallet.address, spenderAddress);
      if (currentAllowance.gte(ethers.utils.parseUnits(amount.toString(), decimals))) {
        this.log(`Sufficient allowance already exists`);
        return true;
      }
      this.log(`Approving ${amount} tokens for spending...`, "info");
      const amountInWei = ethers.utils.parseUnits(amount.toString(), decimals);
      const tx = await tokenContract.approve(spenderAddress, amountInWei, { gasLimit: 100000 });
      this.log(`Approval transaction sent: ${tx.hash} | https://sepolia.etherscan.io/tx/${tx.hash}`);
      await tx.wait();
      this.log(`Approval confirmed | https://sepolia.etherscan.io/tx/${tx.hash}`, "success");
      return true;
    } catch (error) {
      this.log(`Failed to approve token: ${error.message}`, "error");
      return false;
    }
  }

  async swapR2USDtoUSDC(wallet, amount) {
    try {
      const r2usdBalance = await this.checkBalance(wallet, R2USD_ADDRESS);
      this.log(`Current R2USD balance: ${r2usdBalance}`);
      if (parseFloat(r2usdBalance) < parseFloat(amount)) {
        this.log(`Insufficient R2USD balance. You have ${r2usdBalance} R2USD but trying to swap ${amount} R2USD.`, "warning");
        return false;
      }
      const approved = await this.approveToken(wallet, R2USD_ADDRESS, R2USD_TO_USDC_CONTRACT, amount);
      if (!approved) return false;
      const r2usdContract = new ethers.Contract(R2USD_ADDRESS, ERC20_ABI, wallet);
      const decimals = await r2usdContract.decimals();
      const amountInWei = ethers.utils.parseUnits(amount.toString(), decimals);
      const minOutput = amountInWei.mul(97).div(100);
      this.log(`Swapping ${amount} R2USD, expecting at least ${ethers.utils.formatUnits(minOutput, decimals)} USDC`);
      const data =
        R2USD_TO_USDC_METHOD_ID +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000001" +
        amountInWei.toHexString().slice(2).padStart(64, "0") +
        minOutput.toHexString().slice(2).padStart(64, "0");
      this.log(`Swapping ${amount} R2USD to USDC...`, "warning");
      const gasFees = await this.estimateGasFees(wallet.provider);
      const tx = await wallet.sendTransaction({
        to: R2USD_TO_USDC_CONTRACT,
        data: data,
        gasLimit: settings.ESTIMATED_GAS || 500000,
        ...gasFees,
      });
      this.log(`Transaction sent: ${tx.hash} |  https://sepolia.etherscan.io/tx/${tx.hash}`);
      const receipt = await tx.wait();
      if (receipt.status === 0) {
        throw new Error("Transaction failed. The contract reverted the execution.");
      }
      this.log(`Swap confirmed! | https://sepolia.etherscan.io/tx/${tx.hash}`, "success");

      return true;
    } catch (error) {
      this.log(`Failed to swap R2USD to USDC: ${error.message}`, "error");
      if (error.transaction) {
        console.error("Transaction details:".red, {
          hash: error.transaction.hash,
          to: error.transaction.to,
          from: error.transaction.from,
          data: error.transaction.data,
        });
      }
      return false;
    }
  }

  async stakeR2USD(wallet, amount) {
    try {
      if (!ethers.utils.isAddress(STAKE_R2USD_CONTRACT)) {
        throw new Error(`Invalid staking contract address: ${STAKE_R2USD_CONTRACT}`);
      }

      const r2usdBalance = await this.checkBalance(wallet, R2USD_ADDRESS);
      this.log(`Current R2USD balance: ${r2usdBalance}`);

      if (parseFloat(r2usdBalance) < parseFloat(amount)) {
        this.log(`Insufficient R2USD balance. You have ${r2usdBalance} R2USD but trying to swap ${amount} R2USD.`, "warning");

        return false;
      }
      const r2usdContract = new ethers.Contract(R2USD_ADDRESS, ERC20_ABI, wallet);
      const decimals = await r2usdContract.decimals();
      const amountInWei = ethers.utils.parseUnits(amount.toString(), decimals);
      const currentAllowance = await r2usdContract.allowance(wallet.address, STAKE_R2USD_CONTRACT);
      this.log(`Current R2USD allowance for staking contract: ${ethers.utils.formatUnits(currentAllowance, decimals)}`);
      if (currentAllowance.lt(amountInWei)) {
        this.log(`Approving ${amount} R2USD for staking contract...`, "info");
        const approveTx = await r2usdContract.approve(STAKE_R2USD_CONTRACT, amountInWei, { gasLimit: 100000 });
        this.log(`Approval transaction sent: ${approveTx.hash} | https://sepolia.etherscan.io/tx/${approveTx.hash}`);
        await approveTx.wait();
        this.log(`Approval confirmed! | https://sepolia.etherscan.io/tx/${approveTx.hash}`, "success");
      } else {
        this.log("Sufficient allowance already exists", "warning");
      }
      const data = STAKE_R2USD_METHOD_ID + amountInWei.toHexString().slice(2).padStart(64, "0") + "0".repeat(576);
      this.log(`Staking ${amount} R2USD to sR2USD...`, "info");
      const gasFees = await this.estimateGasFees(wallet.provider);
      const tx = await wallet.sendTransaction({
        to: STAKE_R2USD_CONTRACT,
        data: data,
        gasLimit: settings.ESTIMATED_GAS || 500000,
        ...gasFees,
      });
      this.log(`Transaction sent: ${tx.hash} |  https://sepolia.etherscan.io/tx/${tx.hash}`);

      const receipt = await tx.wait();
      if (receipt.status === 0) {
        throw new Error("Transaction failed. The contract reverted the execution.");
      }
      this.log(`Stake confirmed! | https://sepolia.etherscan.io/tx/${tx.hash}`, "success");

      return true;
    } catch (error) {
      this.log(`Failed to stake R2USD: ${error.message}`, "error");
      if (error.transaction) {
        this.log(
          `Transaction details ${JSON.stringify({
            hash: error.transaction.hash,
            to: error.transaction.to,
            from: error.transaction.from,
            data: error.transaction.data,
          })}`,
          "error"
        );
      }
      return false;
    }
  }

  async swapUSDCtoR2USD(wallet, amount) {
    try {
      this.log(`Starting swap usdc to r2usd...`);
      const usdcBalance = await this.checkBalance(wallet, USDC_ADDRESS);
      this.log(`Current USDC balance: ${usdcBalance}`);
      if (parseFloat(usdcBalance) < parseFloat(amount)) {
        this.log(`Insufficient USDC balance. You have ${usdcBalance} USDC but trying to swap ${amount} USDC.`, "warning");
        return false;
      }
      const approved = await this.approveToken(wallet, USDC_ADDRESS, USDC_TO_R2USD_CONTRACT, amount);
      if (!approved) return false;
      const usdcContract = new ethers.Contract(USDC_ADDRESS, ERC20_ABI, wallet);
      const decimals = await usdcContract.decimals();
      const amountInWei = ethers.utils.parseUnits(amount.toString(), decimals);
      const data = ethers.utils.hexConcat([
        USDC_TO_R2USD_METHOD_ID,
        ethers.utils.defaultAbiCoder.encode(["address", "uint256", "uint256", "uint256", "uint256", "uint256", "uint256"], [wallet.address, amountInWei, 0, 0, 0, 0, 0]),
      ]);
      this.log(`Swapping ${amount} USDC to R2USD...`, "info");
      const gasFees = await this.estimateGasFees(wallet.provider);
      const tx = await wallet.sendTransaction({
        to: USDC_TO_R2USD_CONTRACT,
        data: data,
        gasLimit: settings.ESTIMATED_GAS || 500000,
        ...gasFees,
      });
      this.log(`Transaction sent: ${tx.hash} | https://sepolia.etherscan.io/tx/${tx.hash}`);
      await tx.wait();
      this.log(`Swap confirmed! | https://sepolia.etherscan.io/tx/${tx.hash}`, "success");
      return true;
    } catch (error) {
      this.log("Failed to swap USDC to R2USD:", "error");
      return false;
    }
  }

  async executeDailyTask(wallet, taskType, amount, numTxs) {
    this.log(`Executing daily ${taskType} for wallet ${wallet.address} | Number txs: ${numTxs}`);
    for (let i = 1; i <= numTxs; i++) {
      const timesleep = getRandomNumber(settings.DELAY_BETWEEN_REQUESTS[0], settings.DELAY_BETWEEN_REQUESTS[1]);
      this.log(`Transaction ${i} of ${numTxs} (Amount: ${amount}) | Delay ${timesleep}s`, "info");
      await sleep(timesleep);
      let success = false;
      if (taskType === "USDC to R2USD") {
        success = await this.swapUSDCtoR2USD(wallet, amount);
      } else if (taskType === "R2USD to USDC") {
        success = await this.swapR2USDtoUSDC(wallet, amount);
      } else if (taskType === "Stake R2USD") {
        success = await this.stakeR2USD(wallet, amount);
      }
      if (success) {
        this.log(`Transaction ${i} completed successfully!`, "success");
      } else {
        this.log(`Transaction ${i} failed.`, "warning");
      }
    }
  }

  async executeDailyTasks(wallet) {
    this.log("Starting daily tasks execution...");
    if (settings.ENABLE_DAILY_USDC_TO_R2USD) {
      const amount = getRandomNumber(settings.AMOUNT_TRANSFER[0], settings.AMOUNT_TRANSFER[1]);
      const numTxs = Math.floor(getRandomNumber(settings.NUMBER_OF_TRANSFER[0], settings.NUMBER_OF_TRANSFER[1]));
      await this.executeDailyTask(wallet, "USDC to R2USD", amount, numTxs);
    }
    if (settings.ENABLE_DAILY_R2USD_TO_USDC) {
      const amount = getRandomNumber(settings.AMOUNT_TRANSFER[0], settings.AMOUNT_TRANSFER[1]);
      const numTxs = Math.floor(getRandomNumber(settings.NUMBER_OF_TRANSFER[0], settings.NUMBER_OF_TRANSFER[1]));
      await this.executeDailyTask(wallet, "R2USD to USDC", amount, numTxs);
    }
    if (settings.ENABLE_DAILY_STAKE_R2USD) {
      const amount = getRandomNumber(settings.AMOUNT_STAKE[0], settings.AMOUNT_STAKE[1]);
      const numTxs = Math.floor(getRandomNumber(settings.NUMBER_OF_TRANSFER[0], settings.NUMBER_OF_TRANSFER[1]));
      await this.executeDailyTask(wallet, "Stake R2USD", amount, numTxs);
    }
    this.log("Daily tasks execution completed.", "success");
  }

  async estimateGasFees(provider) {
    try {
      const feeData = await provider.getFeeData();
      return {
        maxFeePerGas: feeData.maxFeePerGas || ethers.utils.parseUnits("50", "gwei"),
        maxPriorityFeePerGas: feeData.maxPriorityFeePerGas || ethers.utils.parseUnits("2", "gwei"),
      };
    } catch (error) {
      this.log(`${EMOJI.WARNING}("Failed to estimate gas fees, using defaults:", COLORS.YELLOW)}`, error);
      return {
        maxFeePerGas: ethers.utils.parseUnits("50", "gwei"),
        maxPriorityFeePerGas: ethers.utils.parseUnits("2", "gwei"),
      };
    }
  }

  async sendUSDCToAddress(wallet, amount, receipt) {
    try {
      if (wallet.address == receipt) return;
      const timesleep = getRandomNumber(settings.DELAY_BETWEEN_REQUESTS[0], settings.DELAY_BETWEEN_REQUESTS[1]);
      if (!receipt) receipt = getRandomElement(wallets);
      this.log(`Starting share usdc to ${receipt} | Delays ${timesleep}s...`);
      await sleep(timesleep);
      const usdcBalance = await this.checkBalance(wallet, USDC_ADDRESS);
      this.log(`Current USDC balance: ${usdcBalance}`);
      if (parseFloat(usdcBalance) < parseFloat(amount)) {
        this.log(`Insufficient USDC balance. You have ${usdcBalance} USDC but trying to send ${amount} USDC.`, "warning");
        return false;
      }
      this.log(colors.yellow(`Sending ${amount} USDC to random address: ${colors.cyan(receipt)} 📤`));
      const gasFees = await this.estimateGasFees(wallet.provider);
      const tx = await wallet.sendTransaction({
        to: receipt,
        gasLimit: settings.ESTIMATED_GAS || 100000,
        ...gasFees,
      });

      this.log(colors.white(`Transaction sent! Hash: ${colors.cyan(tx.hash)} 🚀`));
      this.log("Waiting for confirmation...", "info");
      await tx.wait();
      this.log(colors.green(`Transaction confirmed | View on explorer: ${network.explorer}/tx/${tx.hash} 🔗`));

      return true;
    } catch (error) {
      this.log(colors.red("Error sending USDC:", error.message, "❌"));
      return null;
    }
  }

  async handleUSDCtoR2USDSwap(wallet) {
    const amount = getRandomNumber(settings.AMOUNT_TRANSFER[0], settings.AMOUNT_TRANSFER[1]);
    await this.swapUSDCtoR2USD(wallet, amount);
  }

  async handleR2USDtoUSDCSwap(wallet) {
    const amount = getRandomNumber(settings.AMOUNT_TRANSFER[0], settings.AMOUNT_TRANSFER[1]);
    await this.swapR2USDtoUSDC(wallet, amount);
  }

  async handleStakeR2USD(wallet) {
    const amount = getRandomNumber(settings.AMOUNT_STAKE[0], settings.AMOUNT_STAKE[1]);
    await this.stakeR2USD(wallet, amount);
  }

  async handleShare(wallet) {
    for (let i = 1; i <= wallets.length; i++) {
      const amount = getRandomNumber(settings.AMOUNT_TRANSFER[0], settings.AMOUNT_TRANSFER[1]);
      await this.sendUSDCToAddress(wallet, amount, wallets[i]);
    }
  }

  async dailyTasks(wallet) {
    await this.executeDailyTasks(wallet);
  }

  async runAccount() {
    const accountIndex = this.accountIndex;
    this.session_name = this.itemData.address;
    this.token = JSON.parse(localStorage[this.session_name] || "{}")?.token;

    if (settings.USE_PROXY) {
      try {
        this.proxyIP = await this.checkProxyIP();
      } catch (error) {
        this.log(`Cannot check proxy IP: ${error.message}`, "warning");
        return;
      }
      const timesleep = getRandomNumber(settings.DELAY_START_BOT[0], settings.DELAY_START_BOT[1]);
      console.log(`=========Tài khoản ${accountIndex + 1} | ${this.proxyIP} | Bắt đầu sau ${timesleep} giây...`.green);
      await sleep(timesleep);
    }

    const { provider, wallet, proxy } = await connectToNetwork(this.proxy, this.itemData.privateKey);

    if (!provider) {
      this.log("Failed to connect to network. Exiting...", "error");
      return;
    }
    this.wallet = wallet;
    this.token = await this.getValidToken();
    await this.getWalletInfo(wallet);

    switch (this.itemData.acction) {
      case "1":
        await this.handleUSDCtoR2USDSwap(wallet);
        break;
      case "2":
        await this.handleR2USDtoUSDCSwap(wallet);
        break;
      case "3":
        await this.handleStakeR2USD(wallet);
        break;
      case "4":
        await this.dailyTasks(wallet);
        break;
      case "5":
        await this.getWalletInfo(wallet);
        break;
      case "6":
        await this.handleShare(wallet);
        break;
      default:
        process.exit(0);
    }
  }
}

async function runWorker(workerData) {
  const { itemData, accountIndex, proxy, hasIDAPI = null, authInfos } = workerData;
  const to = new ClientAPI(itemData, accountIndex, proxy, hasIDAPI, authInfos);
  try {
    await Promise.race([to.runAccount(), new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 24 * 60 * 60 * 1000))]);
    parentPort.postMessage({
      accountIndex,
    });
  } catch (error) {
    parentPort.postMessage({ accountIndex, error: error.message });
  } finally {
    if (!isMainThread) {
      parentPort.postMessage("taskComplete");
    }
  }
}

async function main() {
  showBanner();
  const privateKeys = loadData("privateKeys.txt");
  const proxies = loadData("proxies.txt");
  let acction = 0;
  if (privateKeys.length == 0 || (privateKeys.length > proxies.length && settings.USE_PROXY)) {
    console.log("Số lượng proxy và data phải bằng nhau.".red);
    console.log(`Data: ${privateKeys.length}`);
    console.log(`Proxy: ${proxies.length}`);
    process.exit(1);
  }
  if (!settings.USE_PROXY) {
    console.log(`You are running bot without proxies!!!`.yellow);
  }
  let maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;

  const features = [
    "Swap USDC to R2USD",
    "Swap R2USD to USDC",
    "Stake R2USD to sR2USD",
    "Setup Daily Swap and Stake",
    "Check balances & points",
    // "Transfer USDC to others wallets (share into address in wallets.txt)",
  ];

  console.log(colors.white("\n===== MAIN MENU ====="));
  features.map((value, index) => console.log(colors.white(`${index + 1}. ${value}`)));
  console.log(colors.white("===================="));

  acction = await askQuest(`Choose an option (1-${features.length}): `);
  if (acction < 1 || acction > features.length) {
    console.log(colors.red("Invalid option. Please try again. ⚠️"));
    process.exit(0);
  }

  const data = privateKeys.map((val, index) => {
    const prvk = val.startsWith("0x") ? val : `0x${val}`;
    const wallet = new ethers.Wallet(prvk);
    const item = {
      address: wallet.address,
      privateKey: prvk,
      index,
      acction,
    };
    return item;
  });

  await sleep(1);
  while (true) {
    let currentIndex = 0;
    const errors = [];
    while (currentIndex < data.length) {
      const workerPromises = [];
      const batchSize = Math.min(maxThreads, data.length - currentIndex);
      for (let i = 0; i < batchSize; i++) {
        const worker = new Worker(__filename, {
          workerData: {
            hasIDAPI: null,
            itemData: data[currentIndex],
            accountIndex: currentIndex,
            proxy: proxies[currentIndex % proxies.length],
            authInfos: {},
          },
        });

        workerPromises.push(
          new Promise((resolve) => {
            worker.on("message", (message) => {
              if (message === "taskComplete") {
                worker.terminate();
              }
              if (settings.ENABLE_DEBUG) {
                console.log(message);
              }
              resolve();
            });
            worker.on("error", (error) => {
              console.log(`Lỗi worker cho tài khoản ${currentIndex}: ${error?.message}`);
              worker.terminate();
              resolve();
            });
            worker.on("exit", (code) => {
              worker.terminate();
              if (code !== 0) {
                errors.push(`Worker cho tài khoản ${currentIndex} thoát với mã: ${code}`);
              }
              resolve();
            });
          })
        );

        currentIndex++;
      }

      await Promise.all(workerPromises);

      if (errors.length > 0) {
        errors.length = 0;
      }

      if (currentIndex < data.length) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
    }

    await sleep(3);
    console.log(`=============${new Date().toLocaleString()} | Hoàn thành tất cả tài khoản`.magenta);
    showBanner();
    await sleep(1);
    process.exit(0);
  }
}

if (isMainThread) {
  main().catch((error) => {
    console.log("Lỗi rồi:", error);
    process.exit(1);
  });
} else {
  runWorker(workerData);
}

"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ethereumjs_wallet_1 = require("ethereumjs-wallet");
const eth_simple_keyring_1 = __importDefault(require("@rabby-wallet/eth-simple-keyring"));
const bip39 = __importStar(require("bip39"));
const sigUtil = __importStar(require("eth-sig-util"));
// Options:
const hdPathString = "m/44'/60'/0'/0";
const type = 'HD Key Tree';
class HdKeyring extends eth_simple_keyring_1.default {
    /* PUBLIC METHODS */
    constructor(opts = {}) {
        super();
        this.type = type;
        this.mnemonic = null;
        this.hdPath = hdPathString;
        this.root = null;
        this.wallets = [];
        this._index2wallet = {};
        this.activeIndexes = [];
        this.page = 0;
        this.perPage = 10;
        this.deserialize(opts);
    }
    serialize() {
        return Promise.resolve({
            mnemonic: this.mnemonic,
            activeIndexes: this.activeIndexes,
            hdPath: this.hdPath,
        });
    }
    deserialize(opts = {}) {
        this.wallets = [];
        this.mnemonic = null;
        this.root = null;
        this.hdPath = opts.hdPath || hdPathString;
        if (opts.mnemonic) {
            this.initFromMnemonic(opts.mnemonic);
        }
        if (opts.activeIndexes) {
            return this.activeAccounts(opts.activeIndexes);
        }
        return Promise.resolve([]);
    }
    initFromMnemonic(mnemonic) {
        this.mnemonic = mnemonic;
        this._index2wallet = {};
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        this.hdWallet = ethereumjs_wallet_1.hdkey.fromMasterSeed(seed);
        this.root = this.hdWallet.derivePath(this.hdPath);
    }
    addAccounts(numberOfAccounts = 1) {
        if (!this.root) {
            this.initFromMnemonic(bip39.generateMnemonic());
        }
        let count = numberOfAccounts;
        let currentIdx = 0;
        const newWallets = [];
        while (count) {
            const [, wallet] = this._addressFromIndex(currentIdx);
            if (this.wallets.includes(wallet)) {
                currentIdx++;
            }
            else {
                this.wallets.push(wallet);
                newWallets.push(wallet);
                this.activeIndexes.push(currentIdx);
                count--;
            }
        }
        const hexWallets = newWallets.map((w) => {
            return sigUtil.normalize(w.getAddress().toString('hex'));
        });
        return Promise.resolve(hexWallets);
    }
    activeAccounts(indexes) {
        const accounts = [];
        for (const index of indexes) {
            const [address, wallet] = this._addressFromIndex(index);
            this.wallets.push(wallet);
            this.activeIndexes.push(index);
            accounts.push(address);
        }
        return accounts;
    }
    getFirstPage() {
        this.page = 0;
        return this.__getPage(1);
    }
    getNextPage() {
        return this.__getPage(1);
    }
    getPreviousPage() {
        return this.__getPage(-1);
    }
    getAddresses(start, end) {
        const from = start;
        const to = end;
        const accounts = [];
        for (let i = from; i < to; i++) {
            const [address] = this._addressFromIndex(i);
            accounts.push({
                address,
                index: i + 1,
            });
        }
        return accounts;
    }
    __getPage(increment) {
        return __awaiter(this, void 0, void 0, function* () {
            this.page += increment;
            if (!this.page || this.page <= 0) {
                this.page = 1;
            }
            const from = (this.page - 1) * this.perPage;
            const to = from + this.perPage;
            const accounts = [];
            for (let i = from; i < to; i++) {
                const [address] = this._addressFromIndex(i);
                accounts.push({
                    address,
                    index: i + 1,
                });
            }
            return accounts;
        });
    }
    getAccounts() {
        return Promise.resolve(this.wallets.map((w) => {
            return sigUtil.normalize(w.getAddress().toString('hex'));
        }));
    }
    /* PRIVATE METHODS */
    _addressFromIndex(i) {
        if (!this._index2wallet[i]) {
            const child = this.root.deriveChild(i);
            const wallet = child.getWallet();
            const address = sigUtil.normalize(wallet.getAddress().toString('hex'));
            this._index2wallet[i] = [address, wallet];
        }
        return this._index2wallet[i];
    }
}
HdKeyring.type = type;
exports.default = HdKeyring;

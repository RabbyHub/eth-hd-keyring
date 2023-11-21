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
// import Wallet, { hdkey } from 'ethereumjs-wallet';
const hdkey_1 = require("ethereum-cryptography/hdkey");
const eth_simple_keyring_1 = __importDefault(require("@rabby-wallet/eth-simple-keyring"));
const bip39 = __importStar(require("@scure/bip39"));
const english_1 = require("@scure/bip39/wordlists/english");
const sigUtil = __importStar(require("eth-sig-util"));
const util_1 = require("@ethereumjs/util");
// Options:
const type = 'HD Key Tree';
var HDPathType;
(function (HDPathType) {
    HDPathType["LedgerLive"] = "LedgerLive";
    HDPathType["Legacy"] = "Legacy";
    HDPathType["BIP44"] = "BIP44";
})(HDPathType || (HDPathType = {}));
const HD_PATH_BASE = {
    [HDPathType.BIP44]: "m/44'/60'/0'/0",
    [HDPathType.Legacy]: "m/44'/60'/0'",
    [HDPathType.LedgerLive]: "m/44'/60'/0'/0/0",
};
const HD_PATH_TYPE = {
    [HD_PATH_BASE[HDPathType.BIP44]]: HDPathType.BIP44,
    [HD_PATH_BASE[HDPathType.Legacy]]: HDPathType.Legacy,
    [HD_PATH_BASE[HDPathType.LedgerLive]]: HDPathType.LedgerLive,
};
class HdKeyring extends eth_simple_keyring_1.default {
    /* PUBLIC METHODS */
    constructor(opts = {}) {
        super();
        this.type = type;
        this.mnemonic = null;
        this.hdPath = HD_PATH_BASE[HDPathType.BIP44];
        this.wallets = [];
        this.activeIndexes = [];
        this.index = 0;
        this.page = 0;
        this.perPage = 5;
        this.byImport = false;
        this.publicKey = '';
        this.needPassphrase = false;
        this.accounts = [];
        this.accountDetails = {};
        this.passphrase = '';
        this.setAccountDetail = (address, accountDetail) => {
            this.accountDetails = Object.assign(Object.assign({}, this.accountDetails), { [address.toLowerCase()]: accountDetail });
        };
        this.getAccountDetail = (address) => {
            return this.accountDetails[address.toLowerCase()];
        };
        this.deserialize(opts);
    }
    serialize() {
        return Promise.resolve({
            mnemonic: this.mnemonic,
            /**
             * @deprecated
             */
            activeIndexes: this.activeIndexes,
            hdPath: this.hdPath,
            byImport: this.byImport,
            index: this.index,
            needPassphrase: this.needPassphrase,
            accounts: this.accounts,
            accountDetails: this.accountDetails,
            publicKey: this.publicKey,
        });
    }
    deserialize(opts = {}) {
        this.wallets = [];
        this.mnemonic = null;
        this.hdPath = opts.hdPath || HD_PATH_BASE[HDPathType.BIP44];
        this.byImport = !!opts.byImport;
        this.index = opts.index || 0;
        this.needPassphrase = opts.needPassphrase || !!opts.passphrase;
        this.passphrase = opts.passphrase;
        this.accounts = opts.accounts || [];
        this.accountDetails = opts.accountDetails || {};
        this.publicKey = opts.publicKey || '';
        if (opts.mnemonic) {
            this.mnemonic = opts.mnemonic;
            this.setPassphrase(opts.passphrase || '');
        }
        // activeIndexes is deprecated, if accounts is not empty, use accounts
        if (!this.accounts.length && opts.activeIndexes) {
            return this.activeAccounts(opts.activeIndexes);
        }
        return Promise.resolve([]);
    }
    initFromMnemonic(mnemonic, passphrase) {
        this.mnemonic = mnemonic;
        const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
        this.hdWallet = hdkey_1.HDKey.fromMasterSeed(seed);
        if (!this.publicKey) {
            this.publicKey = this.calcBasePublicKey(this.hdWallet);
        }
    }
    calcBasePublicKey(hdKey) {
        return (0, util_1.bytesToHex)(hdKey.derive(this.getHDPathBase(HDPathType.BIP44)).publicKey);
    }
    addAccounts(numberOfAccounts = 1) {
        if (!this.hdWallet) {
            this.initFromMnemonic(bip39.generateMnemonic(english_1.wordlist));
        }
        let count = numberOfAccounts;
        let currentIdx = 0;
        const addresses = [];
        while (count) {
            const [address, wallet] = this._addressFromIndex(currentIdx);
            if (this.wallets.find((w) => (0, util_1.bytesToHex)(w.publicKey) === (0, util_1.bytesToHex)(wallet.publicKey))) {
                currentIdx++;
            }
            else {
                this.wallets.push(wallet);
                addresses.push(address);
                // this.activeIndexes.push(currentIdx);
                this.setAccountDetail(address, {
                    hdPath: this.hdPath,
                    hdPathType: HD_PATH_TYPE[this.hdPath],
                    index: currentIdx,
                });
                count--;
            }
            if (!this.accounts.includes(address)) {
                this.accounts.push(address);
            }
        }
        return Promise.resolve(addresses);
    }
    activeAccounts(indexes) {
        const accounts = [];
        for (const index of indexes) {
            const [address, wallet] = this._addressFromIndex(index);
            this.wallets.push(wallet);
            this.activeIndexes.push(index);
            accounts.push(address);
            // hdPath is BIP44
            this.setAccountDetail(address, {
                hdPath: this.hdPath,
                hdPathType: HD_PATH_TYPE[this.hdPath],
                index: index,
            });
            if (!this.accounts.includes(address)) {
                this.accounts.push(address);
            }
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
    removeAccount(address) {
        var _a;
        const index = (_a = this.getInfoByAddress(address)) === null || _a === void 0 ? void 0 : _a.index;
        this.activeIndexes = this.activeIndexes.filter((i) => i !== index);
        delete this.accountDetails[address];
        this.accounts = this.accounts.filter((acc) => acc !== address);
        this.wallets = this.wallets.filter(({ publicKey }) => sigUtil
            .normalize(this._addressFromPublicKey(publicKey))
            .toLowerCase() !== address.toLowerCase());
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
        var _a;
        if ((_a = this.accounts) === null || _a === void 0 ? void 0 : _a.length) {
            return Promise.resolve(this.accounts);
        }
        return Promise.resolve(this.wallets.map((w) => {
            return sigUtil.normalize(this._addressFromPublicKey(w.publicKey));
        }));
    }
    getInfoByAddress(address) {
        const detail = this.accountDetails[address];
        if (detail) {
            return detail;
        }
        for (const key in this.wallets) {
            const wallet = this.wallets[key];
            if (sigUtil.normalize(this._addressFromPublicKey(wallet.publicKey)) ===
                address.toLowerCase()) {
                return {
                    index: Number(key),
                    hdPathType: HD_PATH_TYPE[this.hdPath],
                    hdPath: this.hdPath,
                };
            }
        }
        return null;
    }
    _addressFromIndex(i) {
        const child = this.getChildForIndex(i);
        const wallet = {
            publicKey: (0, util_1.privateToPublic)(child.privateKey),
            privateKey: child.privateKey,
        };
        const address = sigUtil.normalize(this._addressFromPublicKey(wallet.publicKey));
        return [address, wallet];
    }
    _addressFromPublicKey(publicKey) {
        return (0, util_1.bytesToHex)((0, util_1.publicToAddress)(publicKey, true)).toLowerCase();
    }
    generateMnemonic() {
        return bip39.generateMnemonic(english_1.wordlist);
    }
    setHdPath(hdPath = HD_PATH_BASE[HDPathType.BIP44]) {
        this.hdPath = hdPath;
    }
    getChildForIndex(index) {
        return this.hdWallet.derive(this.getPathForIndex(index));
    }
    isLedgerLiveHdPath() {
        return this.hdPath === HD_PATH_BASE[HDPathType.LedgerLive];
    }
    getPathForIndex(index) {
        return this.isLedgerLiveHdPath()
            ? `m/44'/60'/${index}'/0/0`
            : `${this.hdPath}/${index}`;
    }
    setPassphrase(passphrase) {
        this.passphrase = passphrase;
        this.initFromMnemonic(this.mnemonic, passphrase);
        for (const acc of this.accounts) {
            const detail = this.getAccountDetail(acc);
            if (detail) {
                this.setHdPath(detail.hdPath);
                const [address, wallet] = this._addressFromIndex(detail.index);
                if (address.toLowerCase() === acc.toLowerCase()) {
                    this.wallets.push(wallet);
                }
            }
        }
    }
    /**
     * if passphrase is correct, the publicKey will be the same as the stored one
     */
    checkPassphrase(passphrase) {
        const seed = bip39.mnemonicToSeedSync(this.mnemonic, passphrase);
        const hdWallet = hdkey_1.HDKey.fromMasterSeed(seed);
        const publicKey = this.calcBasePublicKey(hdWallet);
        return this.publicKey === publicKey;
    }
    getHDPathBase(hdPathType) {
        return HD_PATH_BASE[hdPathType];
    }
    setHDPathType(hdPathType) {
        return __awaiter(this, void 0, void 0, function* () {
            const hdPath = this.getHDPathBase(hdPathType);
            this.setHdPath(hdPath);
        });
    }
}
HdKeyring.type = type;
exports.default = HdKeyring;

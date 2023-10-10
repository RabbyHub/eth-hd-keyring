// import Wallet, { hdkey } from 'ethereumjs-wallet';
import { HDKey } from 'ethereum-cryptography/hdkey';
import SimpleKeyring from '@rabby-wallet/eth-simple-keyring';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import * as sigUtil from 'eth-sig-util';
import {
  bytesToHex,
  publicToAddress,
  hexToBytes,
  privateToPublic,
} from '@ethereumjs/util';

// Options:
const hdPathString = "m/44'/60'/0'/0";
const type = 'HD Key Tree';

interface Wallet {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

interface DeserializeOption {
  hdPath?: string;
  mnemonic?: string;
  activeIndexes?: number[];
  byImport?: boolean;
  index?: number;
  publicKey?: string;
}

class HdKeyring extends SimpleKeyring {
  static type = type;

  type = type;
  mnemonic: string | null = null;
  hdPath = hdPathString;
  hdWallet?: HDKey;
  root: HDKey | null = null;
  wallets: Wallet[] = [];
  _index2wallet: Record<number, [string, Wallet]> = {};
  activeIndexes: number[] = [];
  index = 0;
  page = 0;
  perPage = 5;
  byImport = false;
  publicKey: string = '';

  /* PUBLIC METHODS */
  constructor(opts = {}) {
    super();
    this.deserialize(opts);
  }

  serialize() {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      activeIndexes: this.activeIndexes,
      hdPath: this.hdPath,
      byImport: this.byImport,
      index: this.index,
      publicKey: this.publicKey,
    });
  }

  deserialize(opts: DeserializeOption = {}) {
    this.wallets = [];
    this.mnemonic = null;
    this.root = null;
    this.hdPath = opts.hdPath || hdPathString;
    this.byImport = !!opts.byImport;
    this.index = opts.index || 0;
    this.publicKey = opts.publicKey || '';

    if (opts.mnemonic) {
      this.initFromMnemonic(opts.mnemonic);
    }

    if (opts.activeIndexes) {
      return this.activeAccounts(opts.activeIndexes);
    }

    return Promise.resolve([]);
  }

  private initPublicKey() {
    this.root = this.hdWallet!.derive(this.hdPath);
    this.publicKey = bytesToHex(this.root.publicKey);
  }

  getPublicKey() {
    return this.publicKey;
  }

  initFromMnemonic(mnemonic) {
    this.mnemonic = mnemonic;
    this._index2wallet = {};
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    this.hdWallet = HDKey.fromMasterSeed(seed);
    this.root = this.hdWallet!.derive(this.hdPath);

    if (!this.publicKey) {
      this.initPublicKey();
    }
  }

  addAccounts(numberOfAccounts = 1) {
    if (!this.root) {
      this.initFromMnemonic(bip39.generateMnemonic(wordlist));
    }

    let count = numberOfAccounts;
    let currentIdx = 0;
    const newWallets: Wallet[] = [];
    
    while (count) {
      const [, wallet] = this._addressFromIndex(currentIdx);
      if (this.wallets.includes(wallet)) {
        currentIdx++;
      } else {
        this.wallets.push(wallet);
        newWallets.push(wallet);
        this.activeIndexes.push(currentIdx);
        count--;
      }
    }

    const hexWallets = newWallets.map((w) => {
      return sigUtil.normalize(this._addressfromPublicKey(w.publicKey));
    });

    return Promise.resolve(hexWallets);
  }

  activeAccounts(indexes: number[]) {
    const accounts: string[] = [];
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
  getAddresses(start: number, end: number) {
    const from = start;
    const to = end;
    const accounts: any[] = [];
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
    super.removeAccount(address);
    const index = this.getIndexByAddress(address);
    this.activeIndexes = this.activeIndexes.filter((i) => i !== index);
  }

  async __getPage(increment: number): Promise<
    Array<{
      address: string;
      index: string;
    }>
  > {
    this.page += increment;

    if (!this.page || this.page <= 0) {
      this.page = 1;
    }

    const from = (this.page - 1) * this.perPage;
    const to = from + this.perPage;

    const accounts: any[] = [];

    for (let i = from; i < to; i++) {
      const [address] = this._addressFromIndex(i);
      accounts.push({
        address,
        index: i + 1,
      });
    }

    return accounts;
  }

  getAccounts() {
    return Promise.resolve(
      this.wallets.map((w) => {
        return sigUtil.normalize(this._addressfromPublicKey(w.publicKey));
      }),
    );
  }

  getIndexByAddress(address: string): number | null {
    for (const key in this._index2wallet) {
      if (this._index2wallet[key][0].toLowerCase() === address.toLowerCase()) {
        return Number(key);
      }
    }
    return null;
  }

  /* PRIVATE METHODS */

  _addressFromIndex(i: number): [string, Wallet] {
    if (!this._index2wallet[i]) {
      const child = this.root!.deriveChild(i);
      const wallet = {
        publicKey: privateToPublic(child.privateKey),
        privateKey: child.privateKey,
      };
      const address = sigUtil.normalize(
        this._addressfromPublicKey(wallet.publicKey),
      );
      this._index2wallet[i] = [address, wallet];
    }

    return this._index2wallet[i];
  }

  _addressfromPublicKey(publicKey: Uint8Array) {
    return bytesToHex(publicToAddress(publicKey, true)).toLowerCase();
  }
}

export default HdKeyring;
